package store

import (
	"strings"
	"testing"
)

// seedTestRoom inserts a room directly into rooms.db with a given ID
// and display name. Used by Phase 12 retirement tests to set up
// specific room state without going through SeedRooms (which generates
// random nanoids we can't reference by name).
func seedTestRoom(t *testing.T, s *Store, id, displayName, topic string) {
	t.Helper()
	_, err := s.roomsDB.Exec(
		`INSERT INTO rooms (id, display_name, topic) VALUES (?, ?, ?)`,
		id, displayName, topic,
	)
	if err != nil {
		t.Fatalf("seed room %q: %v", id, err)
	}
}

// seedRoomMember inserts a room_members row for the given (room, user)
// pair. Helper for tests that need specific membership state.
func seedRoomMember(t *testing.T, s *Store, roomID, userID string) {
	t.Helper()
	_, err := s.roomsDB.Exec(
		`INSERT INTO room_members (room_id, user_id, first_epoch) VALUES (?, ?, 0)`,
		roomID, userID,
	)
	if err != nil {
		t.Fatalf("seed room_member (%s, %s): %v", roomID, userID, err)
	}
}

// TestIsRoomRetired_FalseForActive verifies that a freshly seeded room
// (retired = 0 by default) reports not-retired.
func TestIsRoomRetired_FalseForActive(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	seedTestRoom(t, s, "room_active", "general", "General chat")

	if s.IsRoomRetired("room_active") {
		t.Error("active room should not be reported as retired")
	}
}

// TestIsRoomRetired_TrueAfterSetRoomRetired verifies that calling
// SetRoomRetired flips the IsRoomRetired result to true.
func TestIsRoomRetired_TrueAfterSetRoomRetired(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	seedTestRoom(t, s, "room_toretire", "engineering", "Eng chat")

	if err := s.SetRoomRetired("room_toretire", "usr_admin", "team disbanded"); err != nil {
		t.Fatalf("SetRoomRetired: %v", err)
	}

	if !s.IsRoomRetired("room_toretire") {
		t.Error("room should be reported as retired after SetRoomRetired")
	}
}

// TestIsRoomRetired_FalseForMissing verifies that querying a non-existent
// room returns false rather than panicking or erroring.
func TestIsRoomRetired_FalseForMissing(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	if s.IsRoomRetired("room_nonexistent") {
		t.Error("missing room should not be reported as retired")
	}
}

// TestSetRoomRetired_SuffixesDisplayName verifies that a successful
// retirement appends an underscore + 4-char suffix to the display name,
// freeing the original name for reuse by a new room.
func TestSetRoomRetired_SuffixesDisplayName(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	seedTestRoom(t, s, "room_suffix", "engineering", "Eng chat")

	if err := s.SetRoomRetired("room_suffix", "usr_admin", ""); err != nil {
		t.Fatalf("SetRoomRetired: %v", err)
	}

	room, err := s.GetRoomByID("room_suffix")
	if err != nil {
		t.Fatalf("GetRoomByID: %v", err)
	}
	if room == nil {
		t.Fatal("room should exist after retirement")
	}

	// Expect "engineering_XXXX" — underscore + 4 random base62 chars
	if !strings.HasPrefix(room.DisplayName, "engineering_") {
		t.Errorf("display name should start with engineering_, got %q", room.DisplayName)
	}
	wantLen := len("engineering") + 1 + retiredRoomSuffixLen
	if len(room.DisplayName) != wantLen {
		t.Errorf("display name length = %d, want %d (engineering + _ + 4), got %q",
			len(room.DisplayName), wantLen, room.DisplayName)
	}
}

// TestSetRoomRetired_FreesOriginalName verifies that after retirement,
// a new room can be created with the original display name.
func TestSetRoomRetired_FreesOriginalName(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	seedTestRoom(t, s, "room_old", "engineering", "Eng chat")

	if err := s.SetRoomRetired("room_old", "usr_admin", ""); err != nil {
		t.Fatalf("SetRoomRetired: %v", err)
	}

	// Now insert a new room with the SAME original display name.
	// Should succeed because the retired room's display name has
	// been suffixed.
	seedTestRoom(t, s, "room_new", "engineering", "Eng chat v2")

	// Both rooms should coexist; lookup by display name should hit
	// the new one (active) not the suffixed retired one.
	r, err := s.GetRoomByDisplayName("engineering")
	if err != nil {
		t.Fatalf("GetRoomByDisplayName: %v", err)
	}
	if r == nil {
		t.Fatal("new room should be findable by display name")
	}
	if r.ID != "room_new" {
		t.Errorf("display name lookup should return new room, got %q", r.ID)
	}
}

// TestSetRoomRetired_SetsRetiredAtAndBy verifies that the retired_at
// timestamp and retired_by user ID are populated correctly.
func TestSetRoomRetired_SetsRetiredAtAndBy(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	seedTestRoom(t, s, "room_meta", "metaroom", "")

	if err := s.SetRoomRetired("room_meta", "usr_alice", "cleanup"); err != nil {
		t.Fatalf("SetRoomRetired: %v", err)
	}

	room, _ := s.GetRoomByID("room_meta")
	if room == nil {
		t.Fatal("room should exist")
	}
	if !room.Retired {
		t.Error("room.Retired should be true")
	}
	if room.RetiredBy != "usr_alice" {
		t.Errorf("RetiredBy = %q, want usr_alice", room.RetiredBy)
	}
	if room.RetiredAt == "" {
		t.Error("RetiredAt should be set")
	}
}

// TestSetRoomRetired_RejectsAlreadyRetired verifies that calling
// SetRoomRetired on an already-retired room returns an error (Q2
// decision: mirror SetUserRetired's reject-already-retired behavior).
func TestSetRoomRetired_RejectsAlreadyRetired(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	seedTestRoom(t, s, "room_twice", "twice", "")

	if err := s.SetRoomRetired("room_twice", "usr_admin", ""); err != nil {
		t.Fatalf("first SetRoomRetired: %v", err)
	}

	err = s.SetRoomRetired("room_twice", "usr_admin", "")
	if err == nil {
		t.Fatal("second SetRoomRetired should return an error")
	}
	if !strings.Contains(err.Error(), "already retired") {
		t.Errorf("error should mention already retired, got: %v", err)
	}
}

// TestSetRoomRetired_RejectsMissingRoom verifies that calling
// SetRoomRetired on a non-existent room returns an error.
func TestSetRoomRetired_RejectsMissingRoom(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	err = s.SetRoomRetired("room_nonexistent", "usr_admin", "")
	if err == nil {
		t.Fatal("SetRoomRetired on missing room should return an error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error should mention not found, got: %v", err)
	}
}

// TestGetRetiredRoomsForUser_ReturnsOnlyRetired verifies that only
// retired rooms (where the user is still a member) appear in the list.
func TestGetRetiredRoomsForUser_ReturnsOnlyRetired(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	seedTestRoom(t, s, "room_active", "active", "")
	seedTestRoom(t, s, "room_retired", "retired", "")
	seedRoomMember(t, s, "room_active", "usr_alice")
	seedRoomMember(t, s, "room_retired", "usr_alice")

	if err := s.SetRoomRetired("room_retired", "usr_admin", ""); err != nil {
		t.Fatalf("SetRoomRetired: %v", err)
	}

	rooms, err := s.GetRetiredRoomsForUser("usr_alice")
	if err != nil {
		t.Fatalf("GetRetiredRoomsForUser: %v", err)
	}
	if len(rooms) != 1 {
		t.Fatalf("expected 1 retired room, got %d", len(rooms))
	}
	if rooms[0].ID != "room_retired" {
		t.Errorf("expected room_retired, got %q", rooms[0].ID)
	}
}

// TestGetRetiredRoomsForUser_FiltersByMembership verifies Q8: a user
// who voluntarily left a room BEFORE it was retired does NOT see the
// retirement in the catchup list.
func TestGetRetiredRoomsForUser_FiltersByMembership(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	seedTestRoom(t, s, "room_left_then_retired", "leftthenretired", "")
	seedRoomMember(t, s, "room_left_then_retired", "usr_alice")

	// Alice leaves the room (removes her membership row)
	if err := s.RemoveRoomMember("room_left_then_retired", "usr_alice"); err != nil {
		t.Fatalf("RemoveRoomMember: %v", err)
	}

	// Admin later retires the room
	if err := s.SetRoomRetired("room_left_then_retired", "usr_admin", ""); err != nil {
		t.Fatalf("SetRoomRetired: %v", err)
	}

	// Alice should NOT see this retired room in her catchup list
	// because she left before retirement
	rooms, err := s.GetRetiredRoomsForUser("usr_alice")
	if err != nil {
		t.Fatalf("GetRetiredRoomsForUser: %v", err)
	}
	if len(rooms) != 0 {
		t.Errorf("alice left before retirement; should see 0 retired rooms, got %d", len(rooms))
	}
}

// TestGetRetiredRoomsForUser_EmptyForNoRetirements verifies the happy
// path where no rooms are retired returns an empty slice without
// error.
func TestGetRetiredRoomsForUser_EmptyForNoRetirements(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	seedTestRoom(t, s, "room_active", "active", "")
	seedRoomMember(t, s, "room_active", "usr_alice")

	rooms, err := s.GetRetiredRoomsForUser("usr_alice")
	if err != nil {
		t.Fatalf("GetRetiredRoomsForUser: %v", err)
	}
	if len(rooms) != 0 {
		t.Errorf("expected 0 retired rooms, got %d", len(rooms))
	}
}

// TestGetRetiredRoomsForUser_ReturnsSuffixedName verifies that the
// catchup list carries the post-retirement (suffixed) display name,
// not the original name.
func TestGetRetiredRoomsForUser_ReturnsSuffixedName(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	seedTestRoom(t, s, "room_x", "originalname", "")
	seedRoomMember(t, s, "room_x", "usr_alice")

	if err := s.SetRoomRetired("room_x", "usr_admin", ""); err != nil {
		t.Fatalf("SetRoomRetired: %v", err)
	}

	rooms, err := s.GetRetiredRoomsForUser("usr_alice")
	if err != nil {
		t.Fatalf("GetRetiredRoomsForUser: %v", err)
	}
	if len(rooms) != 1 {
		t.Fatalf("expected 1 room, got %d", len(rooms))
	}
	if !strings.HasPrefix(rooms[0].DisplayName, "originalname_") {
		t.Errorf("display name should be suffixed, got %q", rooms[0].DisplayName)
	}
	if rooms[0].DisplayName == "originalname" {
		t.Error("display name should NOT equal the original (should be suffixed)")
	}
}

// TestGenerateRetiredSuffix_ProducesCorrectLength verifies the helper
// produces a suffix of exactly the requested length.
func TestGenerateRetiredSuffix_ProducesCorrectLength(t *testing.T) {
	for _, n := range []int{1, 4, 8, 16} {
		s := generateRetiredSuffix(n)
		if len(s) != n {
			t.Errorf("generateRetiredSuffix(%d) length = %d, want %d", n, len(s), n)
		}
	}
}

// TestGenerateRetiredSuffix_Base62Only verifies the helper produces
// only base62 characters (no underscore or dash from the full
// idAlphabet — those could introduce display name oddities).
func TestGenerateRetiredSuffix_Base62Only(t *testing.T) {
	const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	for i := 0; i < 100; i++ {
		s := generateRetiredSuffix(4)
		for _, c := range s {
			if !strings.ContainsRune(base62, c) {
				t.Errorf("suffix contains non-base62 char %q in %q", c, s)
			}
		}
	}
}

// TestGenerateRetiredSuffix_NotAllSame verifies the helper is actually
// random — 100 calls shouldn't all produce the same value.
func TestGenerateRetiredSuffix_NotAllSame(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		seen[generateRetiredSuffix(4)] = true
	}
	if len(seen) < 50 {
		t.Errorf("expected variety in 100 calls, got %d unique suffixes", len(seen))
	}
}
