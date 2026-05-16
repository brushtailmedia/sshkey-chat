package store

import (
	"database/sql"
	"errors"
	"time"
)

// SetReadPosition updates the read position for a user/device in a room,
// group DM, or 1:1 DM. Exactly one of room/groupID/dmID should be non-empty.
func (s *Store) SetReadPosition(user, deviceID, room, groupID, dmID, lastRead string) error {
	now := time.Now().Unix()
	_, err := s.dataDB.Exec(`
		INSERT INTO read_positions (user, device_id, room, group_id, dm_id, last_read, ts)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (user, device_id, room, group_id, dm_id)
		DO UPDATE SET last_read = excluded.last_read, ts = excluded.ts`,
		user, deviceID, room, groupID, dmID, lastRead, now,
	)
	return err
}

// GetReadPosition returns the last_read message ID for a user/device in a
// room, group DM, or 1:1 DM. Exactly one of room/groupID/dmID should be
// non-empty.
func (s *Store) GetReadPosition(user, deviceID, room, groupID, dmID string) (string, error) {
	var lastRead string
	var err error
	if room != "" {
		err = s.dataDB.QueryRow(`
			SELECT last_read FROM read_positions
			WHERE user = ? AND device_id = ? AND room = ?`,
			user, deviceID, room,
		).Scan(&lastRead)
	} else if groupID != "" {
		err = s.dataDB.QueryRow(`
			SELECT last_read FROM read_positions
			WHERE user = ? AND device_id = ? AND group_id = ?`,
			user, deviceID, groupID,
		).Scan(&lastRead)
	} else if dmID != "" {
		err = s.dataDB.QueryRow(`
			SELECT last_read FROM read_positions
			WHERE user = ? AND device_id = ? AND dm_id = ?`,
			user, deviceID, dmID,
		).Scan(&lastRead)
	}
	if err == sql.ErrNoRows {
		return "", nil
	}
	return lastRead, err
}

// UnreadCount is the scoped unread result emitted as
// protocol.Unread. Count is the canonical unread cardinality.
// LastRead keeps its persisted read-marker semantics. FirstUnreadID
// is the explicit unread-divider boundary — the earliest in-scope
// unread message id, ordered by rowid — empty when Count == 0.
type UnreadCount struct {
	Count         int
	LastRead      string
	FirstUnreadID string
}

// GetRoomUnreadCount returns the unread count + persisted read
// marker + explicit unread boundary for a room, scoped to epochs
// the user has membership for.
//
// Epoch scoping closes an information leak: a new room member has
// no decryption access to pre-join-epoch messages, so the count
// must not include them — otherwise the client unread badge
// reveals "N things happened here you can't read", violating the
// room's E2E contract. See unread-epoch-leak-fix.md.
//
// Two-stage query because rooms.db (room_members) and <roomID>.db
// (messages) are separate SQLite files (cross-DB JOIN needs ATTACH;
// the two-query shape matches existing store patterns).
// first_unread_id is ordered by rowid (SQLite insertion order =
// the codebase's chronological order) — NOT MIN(id): message ids
// are random nanoids, so MIN(id) would be an arbitrary row.
func (s *Store) GetRoomUnreadCount(room, user, deviceID string) (UnreadCount, error) {
	lastRead, err := s.GetReadPosition(user, deviceID, room, "", "")
	if err != nil {
		return UnreadCount{}, err
	}

	// Scope to the user's first_epoch. Non-member → unread 0 by
	// definition (they can see no messages). A real query error
	// must propagate, never silently become an unscoped count.
	firstEpoch, err := s.GetRoomMemberFirstEpoch(room, user)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return UnreadCount{LastRead: lastRead}, nil
		}
		return UnreadCount{LastRead: lastRead}, err
	}

	db, err := s.RoomDB(room)
	if err != nil {
		return UnreadCount{LastRead: lastRead}, err
	}

	out := UnreadCount{LastRead: lastRead}
	if lastRead == "" {
		err = db.QueryRow(`
			SELECT
			  (SELECT COUNT(*) FROM messages
			     WHERE deleted = 0 AND epoch >= ?),
			  COALESCE((SELECT id FROM messages
			     WHERE deleted = 0 AND epoch >= ?
			     ORDER BY rowid ASC LIMIT 1), '')`,
			firstEpoch, firstEpoch,
		).Scan(&out.Count, &out.FirstUnreadID)
	} else {
		err = db.QueryRow(`
			SELECT
			  (SELECT COUNT(*) FROM messages
			     WHERE deleted = 0 AND epoch >= ?
			       AND rowid > (SELECT rowid FROM messages WHERE id = ?)),
			  COALESCE((SELECT id FROM messages
			     WHERE deleted = 0 AND epoch >= ?
			       AND rowid > (SELECT rowid FROM messages WHERE id = ?)
			     ORDER BY rowid ASC LIMIT 1), '')`,
			firstEpoch, lastRead, firstEpoch, lastRead,
		).Scan(&out.Count, &out.FirstUnreadID)
	}
	return out, err
}

// GetGroupUnreadCount returns the unread count + read marker +
// explicit unread boundary for a group DM, scoped to the user's
// membership window.
//
// Groups have NO epoch model (per-message wrapped-key); scoping is
// by joined_at, which IS the wrapped-key recipiency boundary — the
// server wraps a message's key for the members at send time, so a
// user joined at T holds keys for exactly the messages with
// ts >= T. Same gate the group sync path already uses; ts and
// joined_at are both unix seconds. See unread-epoch-leak-fix.md
// (Phase 2).
//
// Error-aware: GetUserGroupJoinedAt maps a non-member to (0, nil)
// and propagates real query errors. A real error must propagate
// (never become an unscoped count); a non-member / zero joinedAt
// yields unread 0 (never `ts >= 0` = count every message = the
// leak re-introduced).
func (s *Store) GetGroupUnreadCount(groupID, user, deviceID string) (UnreadCount, error) {
	lastRead, err := s.GetReadPosition(user, deviceID, "", groupID, "")
	if err != nil {
		return UnreadCount{}, err
	}

	joinedAt, err := s.GetUserGroupJoinedAt(user, groupID)
	if err != nil {
		return UnreadCount{LastRead: lastRead}, err
	}
	if joinedAt == 0 {
		// Non-member (GetUserGroupJoinedAt maps sql.ErrNoRows →
		// 0,nil). Unread 0 by definition; do NOT fall through to
		// `ts >= 0`, which would count every message = the leak.
		return UnreadCount{LastRead: lastRead}, nil
	}

	db, err := s.GroupDB(groupID)
	if err != nil {
		return UnreadCount{LastRead: lastRead}, err
	}

	out := UnreadCount{LastRead: lastRead}
	if lastRead == "" {
		err = db.QueryRow(`
			SELECT
			  (SELECT COUNT(*) FROM messages
			     WHERE deleted = 0 AND ts >= ?),
			  COALESCE((SELECT id FROM messages
			     WHERE deleted = 0 AND ts >= ?
			     ORDER BY rowid ASC LIMIT 1), '')`,
			joinedAt, joinedAt,
		).Scan(&out.Count, &out.FirstUnreadID)
	} else {
		err = db.QueryRow(`
			SELECT
			  (SELECT COUNT(*) FROM messages
			     WHERE deleted = 0 AND ts >= ?
			       AND rowid > (SELECT rowid FROM messages WHERE id = ?)),
			  COALESCE((SELECT id FROM messages
			     WHERE deleted = 0 AND ts >= ?
			       AND rowid > (SELECT rowid FROM messages WHERE id = ?)
			     ORDER BY rowid ASC LIMIT 1), '')`,
			joinedAt, lastRead, joinedAt, lastRead,
		).Scan(&out.Count, &out.FirstUnreadID)
	}
	return out, err
}
