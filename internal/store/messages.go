package store

import (
	"database/sql"
	"encoding/json"
	"strings"
)

// StoredMessage represents a message as stored on disk.
type StoredMessage struct {
	ID          string
	ServerOrder int64 // server's authoritative per-conversation commit order (== rowid)
	Sender      string
	TS          int64
	Epoch       int64  // rooms only
	Payload     string // base64 encrypted blob
	FileIDs     []string
	Signature   string
	WrappedKeys map[string]string // DMs only: userID -> base64 wrapped key
	Deleted     bool
	DeletedBy   string
	EditedAt    int64 // Phase 15: 0 if never edited, else server's edit wall clock
}

// DeleteMessageResult contains the metadata needed after a message is
// tombstoned. FileIDs drive attachment cleanup; ServerOrder lets live
// deleted broadcasts preserve the row's original position.
type DeleteMessageResult struct {
	FileIDs     []string
	ServerOrder int64
}

// InsertRoomMessage stores a room message.
func (s *Store) InsertRoomMessage(room string, msg StoredMessage) (int64, error) {
	db, err := s.RoomDB(room)
	if err != nil {
		return 0, err
	}
	return insertMessage(db, msg)
}

// InsertGroupMessage stores a group DM message.
func (s *Store) InsertGroupMessage(groupID string, msg StoredMessage) (int64, error) {
	db, err := s.GroupDB(groupID)
	if err != nil {
		return 0, err
	}
	return insertMessage(db, msg)
}

// insertMessage inserts a message and returns the assigned server_order (the
// AUTOINCREMENT rowid). LastInsertId on the same Exec result is bound to this
// insert — not a loose later lookup — so it is the committed commit order.
func insertMessage(db *sql.DB, msg StoredMessage) (int64, error) {
	fileIDs := encodeStringSlice(msg.FileIDs)
	wrappedKeys := encodeMap(msg.WrappedKeys)

	result, err := db.Exec(`
		INSERT INTO messages (id, sender, ts, epoch, payload, file_ids, signature, wrapped_keys)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		msg.ID, msg.Sender, msg.TS, msg.Epoch, msg.Payload,
		fileIDs, msg.Signature, wrappedKeys,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// GetRoomMessages retrieves messages from a room, ordered by timestamp descending.
// Returns up to `limit` messages with ts < beforeTS. Pass 0 for beforeTS to get latest.
func (s *Store) GetRoomMessages(room string, beforeTS int64, limit int) ([]StoredMessage, error) {
	db, err := s.RoomDB(room)
	if err != nil {
		return nil, err
	}
	return getMessages(db, beforeTS, limit)
}

// GetGroupMessages retrieves messages from a group DM.
func (s *Store) GetGroupMessages(groupID string, beforeTS int64, limit int) ([]StoredMessage, error) {
	db, err := s.GroupDB(groupID)
	if err != nil {
		return nil, err
	}
	return getMessages(db, beforeTS, limit)
}

// GetRoomMessagesSince retrieves messages from a room with ts >= sinceTS, ordered ascending.
func (s *Store) GetRoomMessagesSince(room string, sinceTS int64, limit int) ([]StoredMessage, error) {
	db, err := s.RoomDB(room)
	if err != nil {
		return nil, err
	}
	return getMessagesSince(db, sinceTS, limit)
}

// GetGroupMessagesSince retrieves messages from a group DM with ts >= sinceTS.
func (s *Store) GetGroupMessagesSince(groupID string, sinceTS int64, limit int) ([]StoredMessage, error) {
	db, err := s.GroupDB(groupID)
	if err != nil {
		return nil, err
	}
	return getMessagesSince(db, sinceTS, limit)
}

func getMessages(db *sql.DB, beforeTS int64, limit int) ([]StoredMessage, error) {
	var rows *sql.Rows
	var err error

	// Order by server_order (the authoritative commit order) rather than rowid.
	// On the server they coincide (server_order is the INTEGER PRIMARY KEY), so
	// this is behavior-identical, but it states the chronological intent and
	// stays correct if the schema ever stops aliasing them (S5).
	if beforeTS > 0 {
		rows, err = db.Query(`
			SELECT id, sender, ts, epoch, payload, file_ids, signature, wrapped_keys, deleted, edited_at, server_order
			FROM messages WHERE ts < ? ORDER BY server_order DESC LIMIT ?`,
			beforeTS, limit,
		)
	} else {
		rows, err = db.Query(`
			SELECT id, sender, ts, epoch, payload, file_ids, signature, wrapped_keys, deleted, edited_at, server_order
			FROM messages ORDER BY server_order DESC LIMIT ?`,
			limit,
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanMessages(rows)
}

func getMessagesSince(db *sql.DB, sinceTS int64, limit int) ([]StoredMessage, error) {
	// server_order ASC == commit order (oldest-first), so sync_batch rows are
	// emitted in chronological commit order. server_order == rowid here (S5).
	rows, err := db.Query(`
		SELECT id, sender, ts, epoch, payload, file_ids, signature, wrapped_keys, deleted, edited_at, server_order
		FROM messages WHERE ts >= ? ORDER BY server_order ASC LIMIT ?`,
		sinceTS, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return scanMessages(rows)
}

func scanMessages(rows *sql.Rows) ([]StoredMessage, error) {
	var msgs []StoredMessage
	for rows.Next() {
		var msg StoredMessage
		var fileIDs, wrappedKeys sql.NullString
		var epoch sql.NullInt64

		err := rows.Scan(&msg.ID, &msg.Sender, &msg.TS, &epoch,
			&msg.Payload, &fileIDs, &msg.Signature, &wrappedKeys, &msg.Deleted, &msg.EditedAt, &msg.ServerOrder)
		if err != nil {
			return nil, err
		}

		if epoch.Valid {
			msg.Epoch = epoch.Int64
		}
		msg.FileIDs = decodeStringSlice(fileIDs.String)
		msg.WrappedKeys = decodeMap(wrappedKeys.String)
		msgs = append(msgs, msg)
	}
	return msgs, rows.Err()
}

// DeleteMessage marks a message as deleted (tombstone).
func (s *Store) DeleteRoomMessage(room, msgID, deletedBy string) ([]string, error) {
	result, err := s.DeleteRoomMessageWithResult(room, msgID, deletedBy)
	if err != nil {
		return nil, err
	}
	return result.FileIDs, nil
}

// DeleteRoomMessageWithResult marks a room message as deleted and returns
// cleanup metadata plus the original server_order for live tombstone broadcasts.
func (s *Store) DeleteRoomMessageWithResult(room, msgID, deletedBy string) (DeleteMessageResult, error) {
	db, err := s.RoomDB(room)
	if err != nil {
		return DeleteMessageResult{}, err
	}
	return deleteMessage(db, msgID, deletedBy)
}

// DeleteGroupMessage marks a group DM message as deleted. Returns file IDs for cleanup.
func (s *Store) DeleteGroupMessage(groupID, msgID, deletedBy string) ([]string, error) {
	result, err := s.DeleteGroupMessageWithResult(groupID, msgID, deletedBy)
	if err != nil {
		return nil, err
	}
	return result.FileIDs, nil
}

// DeleteGroupMessageWithResult marks a group DM message as deleted and returns
// cleanup metadata plus the original server_order for live tombstone broadcasts.
func (s *Store) DeleteGroupMessageWithResult(groupID, msgID, deletedBy string) (DeleteMessageResult, error) {
	db, err := s.GroupDB(groupID)
	if err != nil {
		return DeleteMessageResult{}, err
	}
	return deleteMessage(db, msgID, deletedBy)
}

// UpdateRoomMessageEdited replaces a room message's encrypted payload and
// signature and sets edited_at (Phase 15). Preserves id, sender, ts, epoch,
// file_ids, wrapped_keys, and the deleted flag — those are all immutable
// under the edit model. Also clears reactions on the edited row (inline
// SQL matching deleteMessage's pattern) so clients see a clean reaction
// slate when they process the edited broadcast. Returns sql.ErrNoRows if
// the row is missing OR already tombstoned (deleted = 1) — the edit
// handler treats both as "not found" for the byte-identical privacy
// invariant. No returned file_ids — edit never touches the attachment set.
func (s *Store) UpdateRoomMessageEdited(roomID, msgID, newPayload, newSignature string, editedAt int64) error {
	db, err := s.RoomDB(roomID)
	if err != nil {
		return err
	}
	return updatePerContextMessageEdited(db, msgID, newPayload, newSignature, editedAt)
}

// UpdateGroupMessageEdited — group DM variant. Same semantics as room.
func (s *Store) UpdateGroupMessageEdited(groupID, msgID, newPayload, newSignature string, editedAt int64) error {
	db, err := s.GroupDB(groupID)
	if err != nil {
		return err
	}
	return updatePerContextMessageEdited(db, msgID, newPayload, newSignature, editedAt)
}

// UpdateDMMessageEdited — 1:1 DM variant. Same semantics as room.
func (s *Store) UpdateDMMessageEdited(dmID, msgID, newPayload, newSignature string, editedAt int64) error {
	db, err := s.DMDB(dmID)
	if err != nil {
		return err
	}
	return updatePerContextMessageEdited(db, msgID, newPayload, newSignature, editedAt)
}

// updatePerContextMessageEdited is the inner helper shared by the three
// public wrappers. Runs a single UPDATE that sets payload, signature,
// edited_at, and wrapped_keys (wrapped_keys is unchanged for rooms and
// rewrapped for a fresh K_msg in groups/DMs — see the per-verb handlers
// for the rewrap logic). Also clears reactions on the edited row in the
// same transaction, because edits invalidate the original message's
// reaction context per Decision log Q12 in message_editing.md. The
// reaction clear matches deleteMessage's inline DELETE pattern at line
// 188 above.
//
// Returns sql.ErrNoRows when the row is missing or already deleted.
// The `deleted = 0` guard in the WHERE clause is important: an edit on
// a tombstoned row must return the same error as an edit on a truly
// missing row, so the handler can collapse both into the byte-identical
// "unknown" wire response for the privacy invariant.
func updatePerContextMessageEdited(db *sql.DB, msgID, newPayload, newSignature string, editedAt int64) error {
	result, err := db.Exec(
		`UPDATE messages SET payload = ?, signature = ?, edited_at = ? WHERE id = ? AND deleted = 0`,
		newPayload, newSignature, editedAt, msgID,
	)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	// Clear reactions on the edited message. Matches the pattern used
	// in deleteMessage at line 188 above. No pins clear — pins are
	// rooms-only and rooms don't prohibit pinning edited messages.
	return DeleteReactionsForMessage(db, msgID)
}

// UpdateGroupMessageEditedWithKeys replaces a group DM message's
// payload + signature + edited_at AND the wrapped_keys JSON blob.
// Groups and 1:1 DMs encrypt each message with a fresh K_msg, so an
// edit produces a new K_msg wrapped for the current member set —
// which means wrapped_keys changes and must be persisted alongside
// the payload replacement. Rooms don't take this path because they
// share an epoch key across all messages in the same epoch; a room
// edit reuses the same epoch key and doesn't touch wrapped_keys
// (the column is unused for rooms anyway).
func (s *Store) UpdateGroupMessageEditedWithKeys(groupID, msgID, newPayload, newSignature, newWrappedKeysJSON string, editedAt int64) error {
	db, err := s.GroupDB(groupID)
	if err != nil {
		return err
	}
	return updatePerContextMessageEditedWithKeys(db, msgID, newPayload, newSignature, newWrappedKeysJSON, editedAt)
}

// UpdateDMMessageEditedWithKeys — 1:1 DM variant. Same semantics.
func (s *Store) UpdateDMMessageEditedWithKeys(dmID, msgID, newPayload, newSignature, newWrappedKeysJSON string, editedAt int64) error {
	db, err := s.DMDB(dmID)
	if err != nil {
		return err
	}
	return updatePerContextMessageEditedWithKeys(db, msgID, newPayload, newSignature, newWrappedKeysJSON, editedAt)
}

func updatePerContextMessageEditedWithKeys(db *sql.DB, msgID, newPayload, newSignature, newWrappedKeysJSON string, editedAt int64) error {
	result, err := db.Exec(
		`UPDATE messages SET payload = ?, signature = ?, wrapped_keys = ?, edited_at = ? WHERE id = ? AND deleted = 0`,
		newPayload, newSignature, newWrappedKeysJSON, editedAt, msgID,
	)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return sql.ErrNoRows
	}
	return DeleteReactionsForMessage(db, msgID)
}

// GetUserMostRecentMessageIDRoom returns the id and ts of the user's
// most recent non-deleted message in a room, or "" and 0 if the user
// has never sent in that room. Used by handleEdit to enforce the
// most-recent rule. Returns empty (not sql.ErrNoRows) when the user
// has no messages — the handler treats empty as "no message to edit"
// which collapses into the byte-identical "not found" response.
func (s *Store) GetUserMostRecentMessageIDRoom(roomID, userID string) (msgID string, ts int64, err error) {
	db, err := s.RoomDB(roomID)
	if err != nil {
		return "", 0, err
	}
	return getUserMostRecentMessageID(db, userID)
}

// GetUserMostRecentMessageIDGroup — group DM variant.
func (s *Store) GetUserMostRecentMessageIDGroup(groupID, userID string) (msgID string, ts int64, err error) {
	db, err := s.GroupDB(groupID)
	if err != nil {
		return "", 0, err
	}
	return getUserMostRecentMessageID(db, userID)
}

// GetUserMostRecentMessageIDDM — 1:1 DM variant.
func (s *Store) GetUserMostRecentMessageIDDM(dmID, userID string) (msgID string, ts int64, err error) {
	db, err := s.DMDB(dmID)
	if err != nil {
		return "", 0, err
	}
	return getUserMostRecentMessageID(db, userID)
}

// getUserMostRecentMessageID is the inner helper. Returns empty + 0 on
// empty result sets (no error). Queries by server_order DESC instead of ts
// DESC because server_order is the authoritative commit order and a clean
// tiebreaker when two messages land at the same unix-second timestamp. On the
// server server_order == rowid (INTEGER PRIMARY KEY), so this is the same
// commit-order query the comment always intended, stated explicitly (S5).
func getUserMostRecentMessageID(db *sql.DB, userID string) (string, int64, error) {
	var id string
	var ts int64
	err := db.QueryRow(
		`SELECT id, ts FROM messages WHERE sender = ? AND deleted = 0 ORDER BY server_order DESC LIMIT 1`,
		userID,
	).Scan(&id, &ts)
	if err == sql.ErrNoRows {
		return "", 0, nil
	}
	if err != nil {
		return "", 0, err
	}
	return id, ts, nil
}

// GetRoomMessageByID fetches a single room message row by id. Used by
// the edit handler for the authorship, deletion, and epoch checks
// before attempting the UPDATE. Returns sql.ErrNoRows if the row is
// missing; callers collapse ErrNoRows into the byte-identical "unknown"
// response per the privacy invariant.
func (s *Store) GetRoomMessageByID(roomID, msgID string) (*StoredMessage, error) {
	db, err := s.RoomDB(roomID)
	if err != nil {
		return nil, err
	}
	return getMessageByID(db, msgID)
}

// GetGroupMessageByID — group DM variant.
func (s *Store) GetGroupMessageByID(groupID, msgID string) (*StoredMessage, error) {
	db, err := s.GroupDB(groupID)
	if err != nil {
		return nil, err
	}
	return getMessageByID(db, msgID)
}

// GetDMMessageByID — 1:1 DM variant.
func (s *Store) GetDMMessageByID(dmID, msgID string) (*StoredMessage, error) {
	db, err := s.DMDB(dmID)
	if err != nil {
		return nil, err
	}
	return getMessageByID(db, msgID)
}

func getMessageByID(db *sql.DB, msgID string) (*StoredMessage, error) {
	rows, err := db.Query(
		`SELECT id, sender, ts, epoch, payload, file_ids, signature, wrapped_keys, deleted, edited_at, server_order
		 FROM messages WHERE id = ? LIMIT 1`,
		msgID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	msgs, err := scanMessages(rows)
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 {
		return nil, sql.ErrNoRows
	}
	return &msgs[0], nil
}

// deleteMessage soft-deletes a message and returns cleanup/broadcast metadata.
func deleteMessage(db *sql.DB, msgID, deletedBy string) (DeleteMessageResult, error) {
	// Get metadata before clearing payload.
	var fileIDsStr sql.NullString
	var serverOrder int64
	if err := db.QueryRow(`SELECT file_ids, server_order FROM messages WHERE id = ?`, msgID).Scan(&fileIDsStr, &serverOrder); err != nil {
		return DeleteMessageResult{}, err
	}

	result, err := db.Exec(`UPDATE messages SET deleted = 1, payload = '', sender = ? WHERE id = ?`,
		deletedBy, msgID)
	if err != nil {
		return DeleteMessageResult{}, err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return DeleteMessageResult{}, sql.ErrNoRows
	}
	// Clean up reactions and pins on the deleted message
	if err := DeleteReactionsForMessage(db, msgID); err != nil {
		return DeleteMessageResult{}, err
	}
	db.Exec(`DELETE FROM pins WHERE message_id = ?`, msgID)

	var fileIDs []string
	if fileIDsStr.Valid && fileIDsStr.String != "" {
		if err := json.Unmarshal([]byte(fileIDsStr.String), &fileIDs); err != nil {
			// Try comma-separated fallback
			fileIDs = strings.Split(fileIDsStr.String, ",")
		}
	}
	return DeleteMessageResult{FileIDs: fileIDs, ServerOrder: serverOrder}, nil
}

// DeleteReactionsForMessage removes all reactions for a single message id.
func DeleteReactionsForMessage(db *sql.DB, msgID string) error {
	_, err := db.Exec(`DELETE FROM reactions WHERE message_id = ?`, msgID)
	return err
}

// GetRoomHistoryBefore pages room scroll-back before beforeID, applying the
// caller's room visibility window (first_seen / first_epoch) IN SQL. Returns the
// page oldest-first. cursorOK is false (with no error, no rows) when beforeID is
// empty or does not resolve to a row the caller may see — the handler turns that
// into a correlated invalid_cursor. hasMore reflects visible rows only.
//
// Tombstones obey the same gates: a deleted row's *existence* is itself
// information, so a pre-join/pre-epoch tombstone must not bypass visibility
// (S4) — unlike the prior in-memory filter, which exempted deleted rows from the
// epoch gate.
func (s *Store) GetRoomHistoryBefore(room, beforeID string, firstSeen, firstEpoch int64, limit int) (msgs []StoredMessage, hasMore, cursorOK bool, err error) {
	db, err := s.RoomDB(room)
	if err != nil {
		return nil, false, false, err
	}
	// firstSeen/firstEpoch == 0 means "no restriction": both clauses are then
	// trivially true, so the gate is a no-op. COALESCE guards NULL epoch rows.
	return getHistoryBefore(db, beforeID, "ts >= ? AND COALESCE(epoch, 0) >= ?", []any{firstSeen, firstEpoch}, limit)
}

// GetGroupHistoryBefore pages group-DM scroll-back before beforeID, applying the
// caller's joined_at visibility window IN SQL. See GetRoomHistoryBefore for the
// (msgs, hasMore, cursorOK, err) contract.
func (s *Store) GetGroupHistoryBefore(groupID, beforeID string, joinedAt int64, limit int) (msgs []StoredMessage, hasMore, cursorOK bool, err error) {
	db, err := s.GroupDB(groupID)
	if err != nil {
		return nil, false, false, err
	}
	return getHistoryBefore(db, beforeID, "ts >= ?", []any{joinedAt}, limit)
}

// getHistoryBefore is the shared visibility-aware scroll-back pager (S4). It
// resolves the beforeID cursor WITHIN the visible window (visGate), pages older
// visible rows by server_order, applies the visibility gate BEFORE LIMIT+1 (so
// invisible rows cannot consume the lookahead and make has_more falsely false),
// and returns the page oldest-first.
//
// Returns (msgs, hasMore, cursorOK, err). cursorOK is false — with no error and
// no rows — when beforeID is empty or does not resolve to a visible row in this
// context; the caller turns that into a correlated invalid_cursor. visGate may be
// empty (no visibility restriction); visArgs are its bound parameters.
func getHistoryBefore(db *sql.DB, beforeID, visGate string, visArgs []any, limit int) (msgs []StoredMessage, hasMore, cursorOK bool, err error) {
	if beforeID == "" {
		return nil, false, false, nil // empty cursor -> invalid_cursor
	}
	// Resolve the cursor's server_order, but only if beforeID is itself a visible
	// row — a cross-context, forged, or pre-visibility cursor must not anchor a
	// page.
	cursorWhere := "id = ?"
	cursorArgs := []any{beforeID}
	if visGate != "" {
		cursorWhere += " AND " + visGate
		cursorArgs = append(cursorArgs, visArgs...)
	}
	var cursorOrder int64
	err = db.QueryRow("SELECT server_order FROM messages WHERE "+cursorWhere, cursorArgs...).Scan(&cursorOrder)
	if err == sql.ErrNoRows {
		return nil, false, false, nil // not-found / not-visible cursor -> invalid_cursor
	}
	if err != nil {
		return nil, false, false, err
	}
	// Page the visible rows immediately below the cursor. The visibility gate is
	// applied here too (before LIMIT) so has_more counts only visible rows.
	pageWhere := "server_order < ?"
	pageArgs := []any{}
	if visGate != "" {
		pageWhere = visGate + " AND " + pageWhere
		pageArgs = append(pageArgs, visArgs...)
	}
	pageArgs = append(pageArgs, cursorOrder, limit+1)
	rows, err := db.Query(`
		SELECT id, sender, ts, epoch, payload, file_ids, signature, wrapped_keys, deleted, edited_at, server_order
		FROM messages
		WHERE `+pageWhere+`
		ORDER BY server_order DESC
		LIMIT ?`, pageArgs...)
	if err != nil {
		return nil, false, false, err
	}
	defer rows.Close()
	msgs, err = scanMessages(rows)
	if err != nil {
		return nil, false, false, err
	}
	// has_more from the +1 lookahead (visible rows only); drop the extra (oldest,
	// last in this newest-first slice), then reverse to oldest-first for the wire.
	hasMore = len(msgs) > limit
	if hasMore {
		msgs = msgs[:limit]
	}
	reverseStoredMessages(msgs)
	return msgs, hasMore, true, nil
}

// reverseStoredMessages flips a slice in place (newest-first -> oldest-first).
func reverseStoredMessages(msgs []StoredMessage) {
	for i, j := 0, len(msgs)-1; i < j; i, j = i+1, j-1 {
		msgs[i], msgs[j] = msgs[j], msgs[i]
	}
}

// StoredReaction represents a reaction as stored on disk.
type StoredReaction struct {
	ReactionID  string
	MessageID   string
	User        string
	TS          int64
	Epoch       int64
	Payload     string
	Signature   string
	WrappedKeys map[string]string // DMs only
}

// GetRoomReactionsForMessages returns all reactions on the given message IDs from a room DB.
func (s *Store) GetRoomReactionsForMessages(room string, messageIDs []string) ([]StoredReaction, error) {
	db, err := s.RoomDB(room)
	if err != nil {
		return nil, err
	}
	return getReactionsForMessages(db, messageIDs)
}

// GetGroupReactionsForMessages returns all reactions on the given message IDs from a group DM DB.
func (s *Store) GetGroupReactionsForMessages(groupID string, messageIDs []string) ([]StoredReaction, error) {
	db, err := s.GroupDB(groupID)
	if err != nil {
		return nil, err
	}
	return getReactionsForMessages(db, messageIDs)
}

func getReactionsForMessages(db *sql.DB, messageIDs []string) ([]StoredReaction, error) {
	if len(messageIDs) == 0 {
		return nil, nil
	}
	// Build placeholders: ?, ?, ?
	placeholders := strings.Repeat("?,", len(messageIDs))
	placeholders = placeholders[:len(placeholders)-1] // trim trailing comma

	args := make([]any, len(messageIDs))
	for i, id := range messageIDs {
		args[i] = id
	}

	rows, err := db.Query(`
		SELECT reaction_id, message_id, user, ts, COALESCE(epoch, 0), payload, COALESCE(signature, ''), COALESCE(wrapped_keys, '')
		FROM reactions
		WHERE message_id IN (`+placeholders+`)
		ORDER BY ts ASC`,
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reactions []StoredReaction
	for rows.Next() {
		var r StoredReaction
		var wrappedKeys string
		if err := rows.Scan(&r.ReactionID, &r.MessageID, &r.User, &r.TS, &r.Epoch, &r.Payload, &r.Signature, &wrappedKeys); err != nil {
			return nil, err
		}
		r.WrappedKeys = decodeMap(wrappedKeys)
		reactions = append(reactions, r)
	}
	return reactions, rows.Err()
}

// GetEpochRange returns the min and max epoch numbers for messages in a result set.
func GetEpochRange(msgs []StoredMessage) (int64, int64) {
	if len(msgs) == 0 {
		return 0, 0
	}
	min, max := msgs[0].Epoch, msgs[0].Epoch
	for _, m := range msgs[1:] {
		if m.Epoch < min {
			min = m.Epoch
		}
		if m.Epoch > max {
			max = m.Epoch
		}
	}
	return min, max
}

// JSON helpers for storing slices and maps in SQLite TEXT columns.

func encodeStringSlice(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return strings.Join(s, ",")
}

func decodeStringSlice(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func encodeMap(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	data, _ := json.Marshal(m)
	return string(data)
}

// EncodeWrappedKeys is an exported wrapper around encodeMap for callers
// outside the store package (specifically the Phase 15 edit handlers in
// the server package) that need to serialize a wrapped_keys map the
// same way InsertGroupMessage/InsertDMMessage do.
func EncodeWrappedKeys(m map[string]string) string {
	return encodeMap(m)
}

func decodeMap(s string) map[string]string {
	if s == "" {
		return nil
	}
	var m map[string]string
	json.Unmarshal([]byte(s), &m)
	return m
}
