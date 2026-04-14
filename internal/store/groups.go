package store

import (
	"database/sql"
	"fmt"
	"sort"
	"strings"
)

// CreateGroup creates a new group DM with the given members and optional name.
// adminID must appear in members and receives is_admin=1 during the batch
// insert; all other initial members get is_admin=0. There is no "first-admin"
// role after creation — the initial admin is indistinguishable from any admin
// promoted later and enjoys no extra protections (Phase 14 flat peer model).
func (s *Store) CreateGroup(id, adminID string, members []string, name ...string) error {
	found := false
	for _, m := range members {
		if m == adminID {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("CreateGroup: adminID %q must appear in members", adminID)
	}

	tx, err := s.dataDB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	groupName := ""
	if len(name) > 0 {
		groupName = name[0]
	}

	_, err = tx.Exec(`INSERT INTO group_conversations (id, name) VALUES (?, ?)`, id, groupName)
	if err != nil {
		return err
	}

	for _, member := range members {
		isAdmin := 0
		if member == adminID {
			isAdmin = 1
		}
		_, err = tx.Exec(
			`INSERT INTO group_members (group_id, user, is_admin) VALUES (?, ?, ?)`,
			id, member, isAdmin,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// AddGroupMember inserts a single new member into an existing group DM. Used
// by handleAddToGroup post-creation (groups were immutable pre-Phase-14, so
// the only pre-existing insertion path was CreateGroup's batch insert). The
// isAdmin parameter is always false from the handler path — new members are
// never admins at add time; promote afterwards via SetGroupMemberAdmin.
func (s *Store) AddGroupMember(groupID, userID string, isAdmin bool) error {
	flag := 0
	if isAdmin {
		flag = 1
	}
	_, err := s.dataDB.Exec(
		`INSERT INTO group_members (group_id, user, is_admin) VALUES (?, ?, ?)`,
		groupID, userID, flag,
	)
	return err
}

// GetGroupAdminIDs returns the user IDs of every admin in a group DM,
// sorted for deterministic ordering.
func (s *Store) GetGroupAdminIDs(groupID string) ([]string, error) {
	rows, err := s.dataDB.Query(`
		SELECT user FROM group_members WHERE group_id = ? AND is_admin = 1 ORDER BY user`,
		groupID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var admins []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err != nil {
			return nil, err
		}
		admins = append(admins, u)
	}
	return admins, rows.Err()
}

// IsGroupAdmin returns true if the user is a member of the group and their
// is_admin flag is set. A non-member returns (false, nil).
func (s *Store) IsGroupAdmin(groupID, userID string) (bool, error) {
	var flag int
	err := s.dataDB.QueryRow(
		`SELECT is_admin FROM group_members WHERE group_id = ? AND user = ?`,
		groupID, userID,
	).Scan(&flag)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return flag == 1, nil
}

// CountGroupAdmins returns the number of admins currently in a group. Used
// by the "at least one admin" invariant check in handleLeaveGroup,
// handleDeleteGroup, handleDemoteGroupAdmin, handleRemoveFromGroup, and the
// retirement-succession path in handleRetirement.
func (s *Store) CountGroupAdmins(groupID string) (int, error) {
	var count int
	err := s.dataDB.QueryRow(
		`SELECT COUNT(*) FROM group_members WHERE group_id = ? AND is_admin = 1`,
		groupID,
	).Scan(&count)
	return count, err
}

// SetGroupMemberAdmin sets is_admin for a specific member row. Pure mutation —
// invariant checks ("at least one admin") are the handler's responsibility,
// not the store's. Returns an error if the row does not exist.
func (s *Store) SetGroupMemberAdmin(groupID, userID string, isAdmin bool) error {
	flag := 0
	if isAdmin {
		flag = 1
	}
	res, err := s.dataDB.Exec(
		`UPDATE group_members SET is_admin = ? WHERE group_id = ? AND user = ?`,
		flag, groupID, userID,
	)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("SetGroupMemberAdmin: no such member %q in group %q", userID, groupID)
	}
	return nil
}

// GetOldestGroupMember returns the user ID of the earliest-joined member of
// a group, excluding the given userID. Used by handleRetirement's last-admin
// succession path to pick an auto-promote target when the retiring user is
// the sole admin. Ordering is by joined_at ASC (TEXT ISO-ish format orders
// correctly without conversion). Returns "" if no other members exist.
func (s *Store) GetOldestGroupMember(groupID, excludeUserID string) (string, error) {
	var user string
	err := s.dataDB.QueryRow(`
		SELECT user FROM group_members
		WHERE group_id = ? AND user != ?
		ORDER BY joined_at ASC, user ASC
		LIMIT 1`,
		groupID, excludeUserID,
	).Scan(&user)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return user, err
}

// GetGroupMembers returns the members of a group DM.
func (s *Store) GetGroupMembers(groupID string) ([]string, error) {
	rows, err := s.dataDB.Query(`
		SELECT user FROM group_members WHERE group_id = ? ORDER BY user`,
		groupID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var members []string
	for rows.Next() {
		var user string
		if err := rows.Scan(&user); err != nil {
			return nil, err
		}
		members = append(members, user)
	}
	return members, rows.Err()
}

// GetUserGroups returns all group DM records (ID, members, name) for a user.
func (s *Store) GetUserGroups(user string) ([]GroupRecord, error) {
	rows, err := s.dataDB.Query(`
		SELECT gm.group_id, GROUP_CONCAT(gm2.user, ','), COALESCE(g.name, '')
		FROM group_members gm
		JOIN group_members gm2 ON gm.group_id = gm2.group_id
		JOIN group_conversations g ON g.id = gm.group_id
		WHERE gm.user = ?
		GROUP BY gm.group_id
		ORDER BY gm.group_id`,
		user,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []GroupRecord
	for rows.Next() {
		var g GroupRecord
		var membersStr string
		if err := rows.Scan(&g.ID, &membersStr, &g.Name); err != nil {
			return nil, err
		}
		g.Members = strings.Split(membersStr, ",")
		sort.Strings(g.Members)
		groups = append(groups, g)
	}
	return groups, rows.Err()
}

// GroupRecord holds a group DM ID, its members, and optional name.
type GroupRecord struct {
	ID      string
	Members []string
	Name    string
}

// RenameGroup updates the name of a group DM.
func (s *Store) RenameGroup(groupID, name string) error {
	_, err := s.dataDB.Exec(`UPDATE group_conversations SET name = ? WHERE id = ?`, name, groupID)
	return err
}

// RemoveGroupMember removes a member from a group DM.
func (s *Store) RemoveGroupMember(groupID, user string) error {
	_, err := s.dataDB.Exec(`
		DELETE FROM group_members WHERE group_id = ? AND user = ?`,
		groupID, user,
	)
	return err
}

// IsGroupMember checks if a user is a member of a group DM.
func (s *Store) IsGroupMember(groupID, user string) (bool, error) {
	var count int
	err := s.dataDB.QueryRow(`
		SELECT COUNT(*) FROM group_members WHERE group_id = ? AND user = ?`,
		groupID, user,
	).Scan(&count)
	return count > 0, err
}

// Phase 14 removed RetireUserFromGroups — the bulk-delete helper was
// replaced by per-group iteration through performGroupLeave in
// handleRetirement, which correctly triggers last-admin succession,
// audit recording via RecordGroupEvent, and last-member cleanup (fixing
// the pre-Phase-14 orphan-on-solo bug where solo-member retirement left
// group_conversations rows and per-group DB files orbiting forever).
