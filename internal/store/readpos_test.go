package store

import "testing"

// Layer 1 (server canonical) regression tests for the unread
// pre-join leak fix. See unread-epoch-leak-fix.md.
//
// Phase 1: GetRoomUnreadCount is epoch-scoped (epoch >= first_epoch).
// Phase 2: GetGroupUnreadCount is membership-scoped (ts >= joined_at)
// since groups have no epoch model.
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
	if err := s.InsertRoomMessage(room, StoredMessage{
		ID: id, Sender: "alice", TS: ts, Epoch: epoch, Payload: "x",
	}); err != nil {
		t.Fatalf("insert room msg %q: %v", id, err)
	}
}

func groupMsg(t *testing.T, s *Store, gid, id string, ts int64) {
	t.Helper()
	if err := s.InsertGroupMessage(gid, StoredMessage{
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

// --- Phase 1: room ---

// New member joined at epoch 3 must NOT see the 20 pre-join
// (epoch 1+2) messages — count is the 10 epoch-3 messages only.
func TestGetRoomUnreadCount_NewMemberSkipsPreJoinEpochs(t *testing.T) {
	s := openStore(t)
	roomID := GenerateID("room_")
	seedTestRoom(t, s, roomID, "general", "")
	for i := 0; i < 10; i++ {
		roomMsg(t, s, roomID, "e1_"+string(rune('a'+i)), 1, int64(100+i))
	}
	for i := 0; i < 10; i++ {
		roomMsg(t, s, roomID, "e2_"+string(rune('a'+i)), 2, int64(200+i))
	}
	for i := 0; i < 10; i++ {
		roomMsg(t, s, roomID, "e3_"+string(rune('a'+i)), 3, int64(300+i))
	}
	if err := s.AddRoomMember(roomID, "newbie", 3); err != nil {
		t.Fatalf("add member: %v", err)
	}

	u, err := s.GetRoomUnreadCount(roomID, "newbie", "dev1")
	if err != nil {
		t.Fatalf("unread: %v", err)
	}
	if u.Count != 10 {
		t.Errorf("Count = %d, want 10 (epoch-3 only, NOT 30)", u.Count)
	}
	if u.FirstUnreadID != "e3_a" {
		t.Errorf("FirstUnreadID = %q, want %q (first epoch-3 by rowid)", u.FirstUnreadID, "e3_a")
	}
}

// Original member (first_epoch 0) sees everything — no regression.
func TestGetRoomUnreadCount_OriginalMemberCountsAll(t *testing.T) {
	s := openStore(t)
	roomID := GenerateID("room_")
	seedTestRoom(t, s, roomID, "general", "")
	for i := 0; i < 10; i++ {
		roomMsg(t, s, roomID, "e0_"+string(rune('a'+i)), 0, int64(i))
	}
	for i := 0; i < 10; i++ {
		roomMsg(t, s, roomID, "e1_"+string(rune('a'+i)), 1, int64(100+i))
	}
	if err := s.AddRoomMember(roomID, "founder", 0); err != nil {
		t.Fatalf("add member: %v", err)
	}

	u, err := s.GetRoomUnreadCount(roomID, "founder", "dev1")
	if err != nil {
		t.Fatalf("unread: %v", err)
	}
	if u.Count != 20 {
		t.Errorf("Count = %d, want 20 (original member sees all)", u.Count)
	}
}

// Non-member → unread 0, no error (must NOT degrade to count-all).
func TestGetRoomUnreadCount_NonMemberReturnsZero(t *testing.T) {
	s := openStore(t)
	roomID := GenerateID("room_")
	seedTestRoom(t, s, roomID, "general", "")
	for i := 0; i < 5; i++ {
		roomMsg(t, s, roomID, "m_"+string(rune('a'+i)), 1, int64(i))
	}

	u, err := s.GetRoomUnreadCount(roomID, "stranger", "dev1")
	if err != nil {
		t.Fatalf("non-member must not error: %v", err)
	}
	if u.Count != 0 {
		t.Errorf("Count = %d, want 0 (non-member sees nothing)", u.Count)
	}
}

// Returning member: stale lastRead from a prior (epoch-1) membership
// must be clamped by the epoch filter to the new first_epoch (4),
// not reach into the intermediate epochs 2-3.
func TestGetRoomUnreadCount_ReturningMemberStaleLastReadClamped(t *testing.T) {
	s := openStore(t)
	roomID := GenerateID("room_")
	seedTestRoom(t, s, roomID, "general", "")
	roomMsg(t, s, roomID, "old_read", 1, 100) // read during first stint
	for i := 0; i < 10; i++ {
		roomMsg(t, s, roomID, "e2_"+string(rune('a'+i)), 2, int64(200+i))
	}
	for i := 0; i < 10; i++ {
		roomMsg(t, s, roomID, "e3_"+string(rune('a'+i)), 3, int64(300+i))
	}
	for i := 0; i < 10; i++ {
		roomMsg(t, s, roomID, "e4_"+string(rune('a'+i)), 4, int64(400+i))
	}
	if err := s.AddRoomMember(roomID, "rejoiner", 4); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if err := s.SetReadPosition("rejoiner", "dev1", roomID, "", "", "old_read"); err != nil {
		t.Fatalf("set read pos: %v", err)
	}

	u, err := s.GetRoomUnreadCount(roomID, "rejoiner", "dev1")
	if err != nil {
		t.Fatalf("unread: %v", err)
	}
	if u.Count != 10 {
		t.Errorf("Count = %d, want 10 (epoch>=4 only; stale lastRead must NOT reach epochs 2-3)", u.Count)
	}
}

// Locks the audit's key invariant: first_unread_id is ordered by
// rowid (insertion/chronological order), NOT MIN(id) — message ids
// are random nanoids, so MIN(id) would return an arbitrary row.
func TestGetRoomUnreadCount_FirstUnreadIDIsRowidOrderedNotMinID(t *testing.T) {
	s := openStore(t)
	roomID := GenerateID("room_")
	seedTestRoom(t, s, roomID, "general", "")
	// All epoch 5 (all in-scope), inserted in this rowid order.
	// Lexical MIN(id) would be "m_1"; rowid-first is "m_9".
	roomMsg(t, s, roomID, "m_9", 5, 500) // rowid 1 — chronologically first
	roomMsg(t, s, roomID, "m_1", 5, 501) // rowid 2 — lexically smallest
	roomMsg(t, s, roomID, "m_5", 5, 502) // rowid 3
	if err := s.AddRoomMember(roomID, "u", 5); err != nil {
		t.Fatalf("add member: %v", err)
	}

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
