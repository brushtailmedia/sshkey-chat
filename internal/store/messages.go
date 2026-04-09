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
			SELECT id, sender, ts, epoch, payload, file_ids, signature, wrapped_keys, deleted
			FROM messages WHERE ts < ? ORDER BY rowid DESC LIMIT ?`,
			beforeTS, limit,
		)
	} else {
		rows, err = db.Query(`
			SELECT id, sender, ts, epoch, payload, file_ids, signature, wrapped_keys, deleted
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
		SELECT id, sender, ts, epoch, payload, file_ids, signature, wrapped_keys, deleted
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
			&msg.Payload, &fileIDs, &msg.Signature, &wrappedKeys, &msg.Deleted)
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
	db.Exec(`DELETE FROM reactions WHERE message_id = ?`, msgID)
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
		SELECT id, sender, ts, epoch, payload, file_ids, signature, wrapped_keys, deleted
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

func decodeMap(s string) map[string]string {
	if s == "" {
		return nil
	}
	var m map[string]string
	json.Unmarshal([]byte(s), &m)
	return m
}
