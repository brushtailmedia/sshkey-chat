package store

import (
	"database/sql"
	"sort"
	"strings"
)

// CreateConversation creates a new DM conversation with the given members and optional name.
func (s *Store) CreateConversation(id string, members []string, name ...string) error {
	tx, err := s.usersDB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	convName := ""
	if len(name) > 0 {
		convName = name[0]
	}

	_, err = tx.Exec(`INSERT INTO conversations (id, name) VALUES (?, ?)`, id, convName)
	if err != nil {
		return err
	}

	for _, member := range members {
		_, err = tx.Exec(`INSERT INTO conversation_members (conversation_id, user) VALUES (?, ?)`, id, member)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// GetConversationMembers returns the members of a conversation.
func (s *Store) GetConversationMembers(convID string) ([]string, error) {
	rows, err := s.usersDB.Query(`
		SELECT user FROM conversation_members WHERE conversation_id = ? ORDER BY user`,
		convID,
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

// GetUserConversations returns all conversation IDs, members, and names for a user.
func (s *Store) GetUserConversations(user string) ([]ConversationRecord, error) {
	rows, err := s.usersDB.Query(`
		SELECT cm.conversation_id, GROUP_CONCAT(cm2.user, ','), COALESCE(c.name, '')
		FROM conversation_members cm
		JOIN conversation_members cm2 ON cm.conversation_id = cm2.conversation_id
		JOIN conversations c ON c.id = cm.conversation_id
		WHERE cm.user = ?
		GROUP BY cm.conversation_id
		ORDER BY cm.conversation_id`,
		user,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var convs []ConversationRecord
	for rows.Next() {
		var c ConversationRecord
		var membersStr string
		if err := rows.Scan(&c.ID, &membersStr, &c.Name); err != nil {
			return nil, err
		}
		c.Members = strings.Split(membersStr, ",")
		sort.Strings(c.Members)
		convs = append(convs, c)
	}
	return convs, rows.Err()
}

// ConversationRecord holds a conversation ID, its members, and optional name.
type ConversationRecord struct {
	ID      string
	Members []string
	Name    string
}

// RenameConversation updates the name of a conversation.
func (s *Store) RenameConversation(convID, name string) error {
	_, err := s.usersDB.Exec(`UPDATE conversations SET name = ? WHERE id = ?`, name, convID)
	return err
}

// FindOneOnOneConversation finds an existing 1:1 conversation between two users.
// Returns the conversation ID or empty string if none exists.
func (s *Store) FindOneOnOneConversation(user1, user2 string) (string, error) {
	// Find conversations where both users are members and the conversation has exactly 2 members
	var convID sql.NullString
	err := s.usersDB.QueryRow(`
		SELECT cm1.conversation_id
		FROM conversation_members cm1
		JOIN conversation_members cm2 ON cm1.conversation_id = cm2.conversation_id
		WHERE cm1.user = ? AND cm2.user = ?
		AND (SELECT COUNT(*) FROM conversation_members WHERE conversation_id = cm1.conversation_id) = 2
		LIMIT 1`,
		user1, user2,
	).Scan(&convID)

	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return convID.String, nil
}

// RemoveConversationMember removes a member from a conversation.
func (s *Store) RemoveConversationMember(convID, user string) error {
	_, err := s.usersDB.Exec(`
		DELETE FROM conversation_members WHERE conversation_id = ? AND user = ?`,
		convID, user,
	)
	return err
}

// IsConversationMember checks if a user is a member of a conversation.
func (s *Store) IsConversationMember(convID, user string) (bool, error) {
	var count int
	err := s.usersDB.QueryRow(`
		SELECT COUNT(*) FROM conversation_members WHERE conversation_id = ? AND user = ?`,
		convID, user,
	).Scan(&count)
	return count > 0, err
}
