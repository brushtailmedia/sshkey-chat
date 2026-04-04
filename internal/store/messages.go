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
	WrappedKeys map[string]string  // DMs only: username -> base64 wrapped key
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

// InsertConvMessage stores a DM/group DM message.
func (s *Store) InsertConvMessage(convID string, msg StoredMessage) error {
	db, err := s.ConvDB(convID)
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

// GetConvMessages retrieves messages from a conversation.
func (s *Store) GetConvMessages(convID string, beforeTS int64, limit int) ([]StoredMessage, error) {
	db, err := s.ConvDB(convID)
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

// GetConvMessagesSince retrieves messages from a conversation with ts >= sinceTS.
func (s *Store) GetConvMessagesSince(convID string, sinceTS int64, limit int) ([]StoredMessage, error) {
	db, err := s.ConvDB(convID)
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
func (s *Store) DeleteRoomMessage(room, msgID, deletedBy string) error {
	db, err := s.RoomDB(room)
	if err != nil {
		return err
	}
	return deleteMessage(db, msgID, deletedBy)
}

// DeleteConvMessage marks a DM message as deleted.
func (s *Store) DeleteConvMessage(convID, msgID, deletedBy string) error {
	db, err := s.ConvDB(convID)
	if err != nil {
		return err
	}
	return deleteMessage(db, msgID, deletedBy)
}

func deleteMessage(db *sql.DB, msgID, deletedBy string) error {
	result, err := db.Exec(`UPDATE messages SET deleted = 1, payload = '', sender = ? WHERE id = ?`,
		deletedBy, msgID)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

// GetRoomMessagesBefore retrieves messages from a room before a specific message ID.
func (s *Store) GetRoomMessagesBefore(room, beforeID string, limit int) ([]StoredMessage, error) {
	db, err := s.RoomDB(room)
	if err != nil {
		return nil, err
	}
	return getMessagesBefore(db, beforeID, limit)
}

// GetConvMessagesBefore retrieves messages from a conversation before a specific message ID.
func (s *Store) GetConvMessagesBefore(convID, beforeID string, limit int) ([]StoredMessage, error) {
	db, err := s.ConvDB(convID)
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
