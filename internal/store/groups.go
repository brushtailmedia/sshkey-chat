package store

import (
	"sort"
	"strings"
)

// CreateGroup creates a new group DM with the given members and optional name.
func (s *Store) CreateGroup(id string, members []string, name ...string) error {
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
		_, err = tx.Exec(`INSERT INTO group_members (group_id, user) VALUES (?, ?)`, id, member)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
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

// RetireUserFromGroups removes a retired user from every group DM they were
// in. Returns the list of affected group IDs so the caller can broadcast
// group_event leaves to remaining members.
//
// Unlike the previous unified RetireUserFromConversations, this function
// always removes — there is no 1:1 carve-out, because 1:1 DMs live in a
// separate table (chunk C of Phase 11) and are handled by their own
// retirement path.
func (s *Store) RetireUserFromGroups(user string) ([]string, error) {
	rows, err := s.dataDB.Query(`
		SELECT group_id FROM group_members WHERE user = ?`,
		user,
	)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if len(ids) == 0 {
		return nil, nil
	}

	for _, id := range ids {
		if _, err := s.dataDB.Exec(`
			DELETE FROM group_members WHERE group_id = ? AND user = ?`,
			id, user,
		); err != nil {
			return nil, err
		}
	}

	return ids, nil
}
