package store

import (
	"database/sql"
	"encoding/json"
	"strings"
)

// StoredMessage represents a message as stored on disk.
type StoredMessage struct {
	ID          string
	Sender      string
	TS          int64
	Epoch       int64              // rooms only
	Payload     string             // base64 encrypted blob
	FileIDs     []string
	Signature   string
	WrappedKeys map[string]string  // DMs only: userID -> base64 wrapped key
	Deleted     bool
	DeletedBy   string
	EditedAt    int64              // Phase 15: 0 if never edited, else server's edit wall clock
}

// InsertRoomMessage stores a room message.
func (s *Store) InsertRoomMessage(room string, msg StoredMessage) error {
	db, err := s.RoomDB(room)
	if err != nil {
		return err
	}
	return insertMessage(db, msg)
}

// InsertGroupMessage stores a group DM message.
func (s *Store) InsertGroupMessage(groupID string, msg StoredMessage) error {
	db, err := s.GroupDB(groupID)
	if err != nil {
		return err
	}
	return insertMessage(db, msg)
}

func insertMessage(db *sql.DB, msg StoredMessage) error {
	fileIDs := encodeStringSlice(msg.FileIDs)
	wrappedKeys := encodeMap(msg.WrappedKeys)

	_, err := db.Exec(`
		INSERT INTO messages (id, sender, ts, epoch, payload, file_ids, signature, wrapped_keys)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		msg.ID, msg.Sender, msg.TS, msg.Epoch, msg.Payload,
		fileIDs, msg.Signature, wrappedKeys,
	)
	return err
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

	if beforeTS > 0 {
		rows, err = db.Query(`
			SELECT id, sender, ts, epoch, payload, file_ids, signature, wrapped_keys, deleted, edited_at
			FROM messages WHERE ts < ? ORDER BY rowid DESC LIMIT ?`,
			beforeTS, limit,
		)
	} else {
		rows, err = db.Query(`
			SELECT id, sender, ts, epoch, payload, file_ids, signature, wrapped_keys, deleted, edited_at
			FROM messages ORDER BY rowid DESC LIMIT ?`,
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
	rows, err := db.Query(`
		SELECT id, sender, ts, epoch, payload, file_ids, signature, wrapped_keys, deleted, edited_at
		FROM messages WHERE ts >= ? ORDER BY rowid ASC LIMIT ?`,
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
			&msg.Payload, &fileIDs, &msg.Signature, &wrappedKeys, &msg.Deleted, &msg.EditedAt)
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
	db, err := s.RoomDB(room)
	if err != nil {
		return nil, err
	}
	return deleteMessage(db, msgID, deletedBy)
}

// DeleteGroupMessage marks a group DM message as deleted. Returns file IDs for cleanup.
func (s *Store) DeleteGroupMessage(groupID, msgID, deletedBy string) ([]string, error) {
	db, err := s.GroupDB(groupID)
	if err != nil {
		return nil, err
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
// empty result sets (no error). Queries by rowid DESC instead of ts
// DESC because rowid reflects insert order and is a cleaner tiebreaker
// when two messages happen to land at the same unix-second timestamp.
func getUserMostRecentMessageID(db *sql.DB, userID string) (string, int64, error) {
	var id string
	var ts int64
	err := db.QueryRow(
		`SELECT id, ts FROM messages WHERE sender = ? AND deleted = 0 ORDER BY rowid DESC LIMIT 1`,
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
		`SELECT id, sender, ts, epoch, payload, file_ids, signature, wrapped_keys, deleted, edited_at
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

// deleteMessage soft-deletes a message and returns its file IDs for cleanup.
func deleteMessage(db *sql.DB, msgID, deletedBy string) ([]string, error) {
	// Get file IDs before clearing payload
	var fileIDsStr string
	db.QueryRow(`SELECT file_ids FROM messages WHERE id = ?`, msgID).Scan(&fileIDsStr)

	result, err := db.Exec(`UPDATE messages SET deleted = 1, payload = '', sender = ? WHERE id = ?`,
		deletedBy, msgID)
	if err != nil {
		return nil, err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return nil, sql.ErrNoRows
	}
	// Clean up reactions and pins on the deleted message
	if err := DeleteReactionsForMessage(db, msgID); err != nil {
		return nil, err
	}
	db.Exec(`DELETE FROM pins WHERE message_id = ?`, msgID)

	var fileIDs []string
	if fileIDsStr != "" {
		if err := json.Unmarshal([]byte(fileIDsStr), &fileIDs); err != nil {
			// Try comma-separated fallback
			fileIDs = strings.Split(fileIDsStr, ",")
		}
	}
	return fileIDs, nil
}

// DeleteReactionsForMessage removes all reactions for a single message id.
func DeleteReactionsForMessage(db *sql.DB, msgID string) error {
	_, err := db.Exec(`DELETE FROM reactions WHERE message_id = ?`, msgID)
	return err
}

// GetRoomMessagesBefore retrieves messages from a room before a specific message ID.
func (s *Store) GetRoomMessagesBefore(room, beforeID string, limit int) ([]StoredMessage, error) {
	db, err := s.RoomDB(room)
	if err != nil {
		return nil, err
	}
	return getMessagesBefore(db, beforeID, limit)
}

// GetGroupMessagesBefore retrieves messages from a group DM before a specific message ID.
func (s *Store) GetGroupMessagesBefore(groupID, beforeID string, limit int) ([]StoredMessage, error) {
	db, err := s.GroupDB(groupID)
	if err != nil {
		return nil, err
	}
	return getMessagesBefore(db, beforeID, limit)
}

func getMessagesBefore(db *sql.DB, beforeID string, limit int) ([]StoredMessage, error) {
	rows, err := db.Query(`
		SELECT id, sender, ts, epoch, payload, file_ids, signature, wrapped_keys, deleted, edited_at
		FROM messages
		WHERE rowid < (SELECT rowid FROM messages WHERE id = ?)
		ORDER BY rowid DESC
		LIMIT ?`,
		beforeID, limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanMessages(rows)
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
