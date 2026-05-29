package store

import "testing"

// Layer 1 (server canonical) regression tests for the unread
// pre-join leak fix. See unread-epoch-leak-fix.md.
//
// Both GetRoomUnreadCount and GetGroupUnreadCount are membership-
// scoped by ts >= joined_at. Rooms previously scoped by a never-
// written first_epoch column (always 0 → counted all pre-join
// history); the joined_at parity fix closes that. Room and group
// tests are deliberately symmetric; TestUnreadCount_RoomsEqualsGroups
// Parity locks the symmetry.
//
// seedTestRoom is defined in room_retirement_test.go (same package).
// Room/group IDs must be real nanoids (RoomDB/GroupDB validate via
// ValidateNanoID); message ids are NOT validated, so they stay
// human-readable for assertions.

func openStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func roomMsg(t *testing.T, s *Store, room, id string, epoch, ts int64) {
	t.Helper()
	if _, err := s.InsertRoomMessage(room, StoredMessage{
		ID: id, Sender: "alice", TS: ts, Epoch: epoch, Payload: "x",
	}); err != nil {
		t.Fatalf("insert room msg %q: %v", id, err)
	}
}

func groupMsg(t *testing.T, s *Store, gid, id string, ts int64) {
	t.Helper()
	if _, err := s.InsertGroupMessage(gid, StoredMessage{
		ID: id, Sender: "alice", TS: ts, Payload: "x",
	}); err != nil {
		t.Fatalf("insert group msg %q: %v", id, err)
	}
}

// pinGroupJoinedAt sets a deterministic joined_at on a group_members
// row so ts boundaries are testable (CreateGroup uses datetime('now')).
func pinGroupJoinedAt(t *testing.T, s *Store, gid, user, joinedAt string) {
	t.Helper()
	if _, err := s.dataDB.Exec(
		`UPDATE group_members SET joined_at = ? WHERE group_id = ? AND user = ?`,
		joinedAt, gid, user,
	); err != nil {
		t.Fatalf("pin joined_at: %v", err)
	}
}

// pinRoomJoinedAt sets a deterministic joined_at on a room_members
// row so ts boundaries are testable (AddRoomMember uses datetime('now')).
func pinRoomJoinedAt(t *testing.T, s *Store, roomID, userID, joinedAt string) {
	t.Helper()
	if _, err := s.roomsDB.Exec(
		`UPDATE room_members SET joined_at = ? WHERE room_id = ? AND user_id = ?`,
		joinedAt, roomID, userID,
	); err != nil {
		t.Fatalf("pin room joined_at: %v", err)
	}
}

// --- Room (joined_at-scoped — parity with groups) ---

// New room member must NOT see messages sent before joined_at — the
// pre-join leak this fix closes (was: first_epoch always 0).
func TestGetRoomUnreadCount_NewMemberSkipsPreJoinMessages(t *testing.T) {
	s := openStore(t)
	roomID := GenerateID("room_")
	seedTestRoom(t, s, roomID, "general", "")
	if err := s.AddRoomMember(roomID, "me", 0); err != nil {
		t.Fatalf("add member: %v", err)
	}
	// joined_at pinned to 2022-01-01 00:00:00 UTC = unix 1640995200.
	pinRoomJoinedAt(t, s, roomID, "me", "2022-01-01 00:00:00")
	roomMsg(t, s, roomID, "pre_1", 1, 1640995100)  // before join
	roomMsg(t, s, roomID, "pre_2", 1, 1640995199)  // before join
	roomMsg(t, s, roomID, "post_1", 1, 1640995200) // == join (inclusive)
	roomMsg(t, s, roomID, "post_2", 1, 1640995300) // after join

	u, err := s.GetRoomUnreadCount(roomID, "me", "dev1")
	if err != nil {
		t.Fatalf("unread: %v", err)
	}
	if u.Count != 2 {
		t.Errorf("Count = %d, want 2 (ts >= joined_at only, NOT 4)", u.Count)
	}
	if u.FirstUnreadID != "post_1" {
		t.Errorf("FirstUnreadID = %q, want %q", u.FirstUnreadID, "post_1")
	}
}

// Long-standing / genesis member (joined far in the past) sees all —
// no regression, no genesis special-case (identical to groups).
func TestGetRoomUnreadCount_LongStandingMemberNoRegression(t *testing.T) {
	s := openStore(t)
	roomID := GenerateID("room_")
	seedTestRoom(t, s, roomID, "general", "")
	if err := s.AddRoomMember(roomID, "me", 0); err != nil {
		t.Fatalf("add member: %v", err)
	}
	pinRoomJoinedAt(t, s, roomID, "me", "2000-01-01 00:00:00")
	roomMsg(t, s, roomID, "m1", 1, 1640995200)
	roomMsg(t, s, roomID, "m2", 1, 1640995300)
	roomMsg(t, s, roomID, "m3", 1, 1640995400)

	u, err := s.GetRoomUnreadCount(roomID, "me", "dev1")
	if err != nil {
		t.Fatalf("unread: %v", err)
	}
	if u.Count != 3 {
		t.Errorf("Count = %d, want 3 (long-standing member sees all)", u.Count)
	}
}

// Non-member → unread 0, no error. Locks the GetUserRoom-footgun
// guard: GetRoomMemberJoinedAt returns raw sql.ErrNoRows, the caller
// maps it via errors.Is → 0; it must NOT degrade to `ts >= 0`
// count-all (NOT GetUserGroupJoinedAt's (0,nil), NOT GetUserRoom's
// (0,0,nil)).
func TestGetRoomUnreadCount_NonMemberReturnsZero(t *testing.T) {
	s := openStore(t)
	roomID := GenerateID("room_")
	seedTestRoom(t, s, roomID, "general", "")
	roomMsg(t, s, roomID, "m1", 1, 1640995200)
	roomMsg(t, s, roomID, "m2", 1, 1640995300)

	u, err := s.GetRoomUnreadCount(roomID, "stranger", "dev1")
	if err != nil {
		t.Fatalf("non-member must not error: %v", err)
	}
	if u.Count != 0 {
		t.Errorf("Count = %d, want 0 (non-member sees nothing)", u.Count)
	}
}

// Rejoin: stale lastRead from a prior membership must be clamped by
// the fresh joined_at so while-absent messages are not counted
// (sync leave → RemoveRoomMember; re-add → fresh joined_at default).
func TestGetRoomUnreadCount_LeftRejoinedOnlyPostRejoin(t *testing.T) {
	s := openStore(t)
	roomID := GenerateID("room_")
	seedTestRoom(t, s, roomID, "general", "")
	if err := s.AddRoomMember(roomID, "me", 0); err != nil {
		t.Fatalf("add member: %v", err)
	}
	pinRoomJoinedAt(t, s, roomID, "me", "2022-01-01 00:00:00")
	roomMsg(t, s, roomID, "old_read", 1, 1640995300) // read before leaving
	if err := s.SetReadPosition("me", "dev1", roomID, "", "", "old_read"); err != nil {
		t.Fatalf("set read pos: %v", err)
	}

	// Leave; while-absent messages must stay out of unread.
	if err := s.RemoveRoomMember(roomID, "me"); err != nil {
		t.Fatalf("remove member: %v", err)
	}
	roomMsg(t, s, roomID, "away_1", 1, 1643673600)
	roomMsg(t, s, roomID, "away_2", 1, 1643673700)

	// Re-add with a fresh joined_at, then new messages.
	if err := s.AddRoomMember(roomID, "me", 0); err != nil {
		t.Fatalf("re-add member: %v", err)
	}
	pinRoomJoinedAt(t, s, roomID, "me", "2022-03-01 00:00:00") // unix 1646092800
	roomMsg(t, s, roomID, "post_1", 1, 1646092800)             // == rejoin (inclusive)
	roomMsg(t, s, roomID, "post_2", 1, 1646092900)

	u, err := s.GetRoomUnreadCount(roomID, "me", "dev1")
	if err != nil {
		t.Fatalf("unread: %v", err)
	}
	if u.LastRead != "old_read" {
		t.Errorf("LastRead = %q, want %q", u.LastRead, "old_read")
	}
	if u.Count != 2 {
		t.Errorf("Count = %d, want 2 (post-rejoin only; while-absent must not count)", u.Count)
	}
	if u.FirstUnreadID != "post_1" {
		t.Errorf("FirstUnreadID = %q, want %q", u.FirstUnreadID, "post_1")
	}
}

// first_unread_id is ordered by rowid (chronological), NOT MIN(id):
// message ids are random nanoids. Invariant preserved under joined_at
// scoping (the rowid / FirstUnreadID logic is unchanged by the fix).
func TestGetRoomUnreadCount_FirstUnreadIDIsRowidOrderedNotMinID(t *testing.T) {
	s := openStore(t)
	roomID := GenerateID("room_")
	seedTestRoom(t, s, roomID, "general", "")
	if err := s.AddRoomMember(roomID, "u", 0); err != nil {
		t.Fatalf("add member: %v", err)
	}
	pinRoomJoinedAt(t, s, roomID, "u", "2000-01-01 00:00:00") // all in-scope
	// Lexical MIN(id) would be "m_1"; rowid-first is "m_9".
	roomMsg(t, s, roomID, "m_9", 1, 1640995200) // rowid 1 — chronologically first
	roomMsg(t, s, roomID, "m_1", 1, 1640995201) // rowid 2 — lexically smallest
	roomMsg(t, s, roomID, "m_5", 1, 1640995202) // rowid 3

	u, err := s.GetRoomUnreadCount(roomID, "u", "dev1")
	if err != nil {
		t.Fatalf("unread: %v", err)
	}
	if u.Count != 3 {
		t.Fatalf("Count = %d, want 3", u.Count)
	}
	if u.FirstUnreadID != "m_9" {
		t.Errorf("FirstUnreadID = %q, want %q (rowid-first); MIN(id) would wrongly be %q", u.FirstUnreadID, "m_9", "m_1")
	}
}

// Rooms ≡ groups parity (§5): identical joined_at + identical ts
// sequence must yield identical UnreadCount from GetRoomUnreadCount
// and GetGroupUnreadCount. Locks the symmetry the whole fix rests on.
func TestUnreadCount_RoomsEqualsGroupsParity(t *testing.T) {
	s := openStore(t)
	roomID := GenerateID("room_")
	groupID := GenerateID("group_")
	seedTestRoom(t, s, roomID, "general", "")
	if err := s.AddRoomMember(roomID, "me", 0); err != nil {
		t.Fatalf("add room member: %v", err)
	}
	if err := s.CreateGroup(groupID, "me", []string{"me"}, "G"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	pinRoomJoinedAt(t, s, roomID, "me", "2022-01-01 00:00:00")
	pinGroupJoinedAt(t, s, groupID, "me", "2022-01-01 00:00:00")

	seq := []struct {
		id string
		ts int64
	}{
		{"pre_1", 1640995100},
		{"pre_2", 1640995199},
		{"post_1", 1640995200}, // == join (inclusive)
		{"post_2", 1640995300},
		{"post_3", 1640995400},
	}
	for _, m := range seq {
		roomMsg(t, s, roomID, m.id, 1, m.ts)
		groupMsg(t, s, groupID, m.id, m.ts)
	}

	ru, err := s.GetRoomUnreadCount(roomID, "me", "dev1")
	if err != nil {
		t.Fatalf("room unread: %v", err)
	}
	gu, err := s.GetGroupUnreadCount(groupID, "me", "dev1")
	if err != nil {
		t.Fatalf("group unread: %v", err)
	}
	if ru.Count != gu.Count || ru.FirstUnreadID != gu.FirstUnreadID || ru.LastRead != gu.LastRead {
		t.Errorf("room/group parity broken:\n  room  = {Count:%d FirstUnreadID:%q LastRead:%q}\n  group = {Count:%d FirstUnreadID:%q LastRead:%q}",
			ru.Count, ru.FirstUnreadID, ru.LastRead, gu.Count, gu.FirstUnreadID, gu.LastRead)
	}
	if ru.Count != 3 || ru.FirstUnreadID != "post_1" {
		t.Errorf("Count/FirstUnreadID = %d/%q, want 3/\"post_1\"", ru.Count, ru.FirstUnreadID)
	}
}

// --- Phase 2: group (joined_at-scoped; no epoch model) ---

// New group member must NOT see messages sent before joined_at.
func TestGetGroupUnreadCount_NewMemberSkipsPreJoinMessages(t *testing.T) {
	s := openStore(t)
	groupID := GenerateID("group_")
	if err := s.CreateGroup(groupID, "me", []string{"me"}, "G"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	// joined_at pinned to 2022-01-01 00:00:00 UTC = unix 1640995200.
	pinGroupJoinedAt(t, s, groupID, "me", "2022-01-01 00:00:00")
	groupMsg(t, s, groupID, "pre_1", 1640995100)  // before join
	groupMsg(t, s, groupID, "pre_2", 1640995199)  // before join
	groupMsg(t, s, groupID, "post_1", 1640995200) // == join (inclusive)
	groupMsg(t, s, groupID, "post_2", 1640995300) // after join

	u, err := s.GetGroupUnreadCount(groupID, "me", "dev1")
	if err != nil {
		t.Fatalf("unread: %v", err)
	}
	if u.Count != 2 {
		t.Errorf("Count = %d, want 2 (ts >= joined_at only, NOT 4)", u.Count)
	}
	if u.FirstUnreadID != "post_1" {
		t.Errorf("FirstUnreadID = %q, want %q", u.FirstUnreadID, "post_1")
	}
}

// Long-standing member (joined far in the past) sees all — no regression.
func TestGetGroupUnreadCount_LongStandingMemberNoRegression(t *testing.T) {
	s := openStore(t)
	groupID := GenerateID("group_")
	if err := s.CreateGroup(groupID, "me", []string{"me"}, "G"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	pinGroupJoinedAt(t, s, groupID, "me", "2000-01-01 00:00:00")
	groupMsg(t, s, groupID, "m1", 1640995200)
	groupMsg(t, s, groupID, "m2", 1640995300)
	groupMsg(t, s, groupID, "m3", 1640995400)

	u, err := s.GetGroupUnreadCount(groupID, "me", "dev1")
	if err != nil {
		t.Fatalf("unread: %v", err)
	}
	if u.Count != 3 {
		t.Errorf("Count = %d, want 3 (long-standing member sees all)", u.Count)
	}
}

// Rejoin case: stale lastRead from a prior membership must be clamped
// by the joined_at filter so messages sent while the user was absent
// are not counted.
func TestGetGroupUnreadCount_LeftRejoinedOnlyPostRejoin(t *testing.T) {
	s := openStore(t)
	groupID := GenerateID("group_")
	if err := s.CreateGroup(groupID, "me", []string{"me"}, "G"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	// First membership window.
	pinGroupJoinedAt(t, s, groupID, "me", "2022-01-01 00:00:00")
	groupMsg(t, s, groupID, "old_read", 1640995300) // read before leaving
	if err := s.SetReadPosition("me", "dev1", "", groupID, "", "old_read"); err != nil {
		t.Fatalf("set read pos: %v", err)
	}

	// User leaves; messages while absent must stay out of unread.
	if err := s.RemoveGroupMember(groupID, "me"); err != nil {
		t.Fatalf("remove member: %v", err)
	}
	groupMsg(t, s, groupID, "away_1", 1643673600)
	groupMsg(t, s, groupID, "away_2", 1643673700)

	// Re-add user with a fresh joined_at, then send new messages.
	if err := s.AddGroupMember(groupID, "me", false); err != nil {
		t.Fatalf("re-add member: %v", err)
	}
	pinGroupJoinedAt(t, s, groupID, "me", "2022-03-01 00:00:00")
	groupMsg(t, s, groupID, "post_1", 1646092800) // == rejoin (inclusive)
	groupMsg(t, s, groupID, "post_2", 1646092900)

	u, err := s.GetGroupUnreadCount(groupID, "me", "dev1")
	if err != nil {
		t.Fatalf("unread: %v", err)
	}
	if u.LastRead != "old_read" {
		t.Errorf("LastRead = %q, want %q", u.LastRead, "old_read")
	}
	if u.Count != 2 {
		t.Errorf("Count = %d, want 2 (post-rejoin only; while-absent messages must not count)", u.Count)
	}
	if u.FirstUnreadID != "post_1" {
		t.Errorf("FirstUnreadID = %q, want %q", u.FirstUnreadID, "post_1")
	}
}

// Non-member → unread 0, no error (GetUserGroupJoinedAt maps
// ErrNoRows→0,nil; must NOT become `ts >= 0` count-all).
func TestGetGroupUnreadCount_NonMemberReturnsZero(t *testing.T) {
	s := openStore(t)
	groupID := GenerateID("group_")
	if err := s.CreateGroup(groupID, "owner", []string{"owner"}, "G"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	groupMsg(t, s, groupID, "m1", 1640995200)
	groupMsg(t, s, groupID, "m2", 1640995300)

	u, err := s.GetGroupUnreadCount(groupID, "stranger", "dev1")
	if err != nil {
		t.Fatalf("non-member must not error: %v", err)
	}
	if u.Count != 0 {
		t.Errorf("Count = %d, want 0 (non-member sees nothing)", u.Count)
	}
}
