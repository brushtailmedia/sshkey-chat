package store

// Phase 20 — user_left_groups pure-history helpers.
//
// Parallel to user_left_rooms.go. Groups have no queue counterpart
// because all group leaves run inline (no CLI async path since
// Phase 14 deleted the admin-kick escape hatch). Rows are written
// exclusively from performGroupLeave and read via
// GetUserLeftGroupsCatchup on the connect handshake.
//
// Re-join cleanup (DeleteUserLeftGroupRows) wires into
// handleAddToGroup so stale leave history is cleared on re-add.
// Retention (PruneOldUserLeftGroups, 1 year) piggybacks on the
// retirement handler's opportunistic prune pattern.

import (
	"time"
)

// UserLeftGroup is one history row from user_left_groups.
type UserLeftGroup struct {
	ID          int64
	UserID      string
	GroupID     string
	Reason      string // '' | 'removed' | 'retirement'
	InitiatedBy string // user_id for self-leave, admin_id for admin remove, 'system' for retirement
	LeftAt      int64
}

// RecordUserLeftGroup inserts a history row. Called exclusively from
// performGroupLeave, never from callers directly.
func (s *Store) RecordUserLeftGroup(userID, groupID, reason, initiatedBy string) (int64, error) {
	res, err := s.dataDB.Exec(
		`INSERT INTO user_left_groups (user_id, group_id, reason, initiated_by, left_at) VALUES (?, ?, ?, ?, ?)`,
		userID, groupID, reason, initiatedBy, time.Now().Unix(),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// GetUserLeftGroupsCatchup returns the most recent leave per group
// for the user, excluding groups where the user has since been
// re-added (defensive LEFT JOIN against group_members so stale rows
// that slipped past DeleteUserLeftGroupRows don't surface in the
// catchup). Ordered by left_at descending.
func (s *Store) GetUserLeftGroupsCatchup(userID string) ([]UserLeftGroup, error) {
	rows, err := s.dataDB.Query(`
		SELECT ulg.id, ulg.user_id, ulg.group_id, ulg.reason, ulg.initiated_by, ulg.left_at
		FROM user_left_groups ulg
		LEFT JOIN group_members gm
		  ON gm.group_id = ulg.group_id AND gm.user_id = ulg.user_id
		WHERE ulg.user_id = ?
		  AND gm.user_id IS NULL
		GROUP BY ulg.group_id
		HAVING ulg.left_at = MAX(ulg.left_at)
		ORDER BY ulg.left_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []UserLeftGroup
	for rows.Next() {
		var u UserLeftGroup
		if err := rows.Scan(&u.ID, &u.UserID, &u.GroupID, &u.Reason, &u.InitiatedBy, &u.LeftAt); err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// DeleteUserLeftGroupRows removes all user_left_groups rows for the
// given (user, group). Called from handleAddToGroup after a successful
// AddGroupMember so re-joining the group clears the prior leave
// history — stale rows would otherwise re-surface on next catchup.
func (s *Store) DeleteUserLeftGroupRows(userID, groupID string) error {
	_, err := s.dataDB.Exec(
		`DELETE FROM user_left_groups WHERE user_id = ? AND group_id = ?`,
		userID, groupID,
	)
	return err
}

// PruneOldUserLeftGroups deletes rows older than maxAgeSec seconds.
// Returns the number of rows deleted. Called opportunistically from
// the retirement handler (see retirement.go) with maxAgeSec set to
// 1 year, matching the retention convention for deleted_groups /
// deleted_rooms.
func (s *Store) PruneOldUserLeftGroups(maxAgeSec int64) (int64, error) {
	cutoff := time.Now().Unix() - maxAgeSec
	res, err := s.dataDB.Exec(
		`DELETE FROM user_left_groups WHERE left_at < ?`,
		cutoff,
	)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
