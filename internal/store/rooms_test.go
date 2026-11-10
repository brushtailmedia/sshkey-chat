package store

import (
	"sort"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/testutil"
)

func TestRoomsDB_SchemaCreated(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	// Verify rooms table exists
	var name string
	err = st.roomsDB.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='rooms'`).Scan(&name)
	if err != nil || name != "rooms" {
		t.Errorf("rooms table not found: %v", err)
	}
}

func TestRoomsDB_UniqueDisplayNameIndex(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	// Insert a room
	_, err = st.roomsDB.Exec(`INSERT INTO rooms (id, display_name, topic) VALUES (?, ?, ?)`,
		"room_test1", "general", "General chat")
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Duplicate display name (same case) should fail
	_, err = st.roomsDB.Exec(`INSERT INTO rooms (id, display_name, topic) VALUES (?, ?, ?)`,
		"room_test2", "general", "Another general")
	if err == nil {
		t.Error("duplicate display name should be rejected")
	}

	// Duplicate display name (different case) should also fail
	_, err = st.roomsDB.Exec(`INSERT INTO rooms (id, display_name, topic) VALUES (?, ?, ?)`,
		"room_test3", "General", "Another general")
	if err == nil {
		t.Error("case-insensitive duplicate should be rejected")
	}
}

// TestGenerateRoomID and TestGenerateID_Prefix moved to nanoid_test.go
// in Phase 17 Step 1 — co-located with the code they exercise.

func TestSeedRooms_PopulatesDB(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	rooms := map[string]RoomSeed{
		"general": {Topic: "General chat"},
		"support": {Topic: "Help and requests"},
	}

	count, err := st.SeedRooms(rooms)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if count != 2 {
		t.Errorf("seeded %d rooms, want 2", count)
	}

	// Verify rooms are in the DB
	all, err := st.GetAllRooms()
	if err != nil {
		t.Fatalf("get all: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 rooms, got %d", len(all))
	}

	// Check fields
	found := map[string]bool{}
	for _, r := range all {
		found[r.DisplayName] = true
		if !strings.HasPrefix(r.ID, "room_") {
			t.Errorf("room ID should start with room_, got %q", r.ID)
		}
		if r.Retired {
			t.Error("seeded room should not be retired")
		}
	}
	if !found["general"] || !found["support"] {
		t.Errorf("expected general and support, got %v", found)
	}
}

func TestSeedRooms_SkipsIfNotEmpty(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	rooms := map[string]RoomSeed{
		"general": {Topic: "General chat"},
	}

	// First seed
	count, _ := st.SeedRooms(rooms)
	if count != 1 {
		t.Fatalf("first seed: %d", count)
	}

	// Second seed — should skip
	count, err = st.SeedRooms(map[string]RoomSeed{
		"engineering": {Topic: "Eng"},
		"design":      {Topic: "Design"},
	})
	if err != nil {
		t.Fatalf("second seed: %v", err)
	}
	if count != 0 {
		t.Errorf("second seed should return 0, got %d", count)
	}

	// DB should still have only general
	all, _ := st.GetAllRooms()
	if len(all) != 1 {
		t.Errorf("expected 1 room, got %d", len(all))
	}
}

func TestSeedRooms_EmptyMap(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	count, err := st.SeedRooms(map[string]RoomSeed{})
	if err != nil {
		t.Fatalf("seed empty: %v", err)
	}
	if count != 0 {
		t.Errorf("empty seed should return 0, got %d", count)
	}

	// DB is still empty — next seed should work
	if !st.RoomsDBEmpty() {
		t.Error("should be empty after seeding empty map")
	}
}

func TestRoomsDBEmpty_TrueOnFreshDB(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if !st.RoomsDBEmpty() {
		t.Error("fresh DB should be empty")
	}
}

func TestGetRoomByID(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.SeedRooms(map[string]RoomSeed{"general": {Topic: "Chat"}})

	all, _ := st.GetAllRooms()
	id := all[0].ID

	room, err := st.GetRoomByID(id)
	if err != nil || room == nil {
		t.Fatalf("get by ID: %v", err)
	}
	if room.DisplayName != "general" {
		t.Errorf("display_name = %q", room.DisplayName)
	}
	if room.Topic != "Chat" {
		t.Errorf("topic = %q", room.Topic)
	}

	// Not found
	room, _ = st.GetRoomByID(testutil.RoomID("nonexistent"))
	if room != nil {
		t.Error("should return nil for nonexistent ID")
	}
}

func TestGetRoomByID_PropagatesQueryError(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	st.SeedRooms(map[string]RoomSeed{"general": {Topic: "Chat"}})
	all, _ := st.GetAllRooms()
	id := all[0].ID

	if err := st.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	room, err := st.GetRoomByID(id)
	if err == nil {
		t.Fatal("expected query error on closed rooms DB, got nil")
	}
	if room != nil {
		t.Fatalf("room = %+v, want nil when query fails", room)
	}
}

func TestGetRoomByDisplayName(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.SeedRooms(map[string]RoomSeed{"general": {Topic: "Chat"}})

	// Exact match
	room, _ := st.GetRoomByDisplayName("general")
	if room == nil {
		t.Fatal("should find general")
	}
	if !strings.HasPrefix(room.ID, "room_") {
		t.Errorf("ID = %q", room.ID)
	}

	// Case-insensitive
	room, _ = st.GetRoomByDisplayName("General")
	if room == nil {
		t.Fatal("should find General (case-insensitive)")
	}

	// Not found
	room, _ = st.GetRoomByDisplayName("nonexistent")
	if room != nil {
		t.Error("should return nil")
	}
}

func TestRoomDisplayNameToID(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.SeedRooms(map[string]RoomSeed{"general": {Topic: "Chat"}})

	id := st.RoomDisplayNameToID("general")
	if !strings.HasPrefix(id, "room_") {
		t.Errorf("ID = %q", id)
	}

	// Case-insensitive
	id2 := st.RoomDisplayNameToID("GENERAL")
	if id2 != id {
		t.Errorf("case-insensitive lookup returned different ID: %q vs %q", id2, id)
	}

	// Not found
	id3 := st.RoomDisplayNameToID("nope")
	if id3 != "" {
		t.Errorf("should return empty, got %q", id3)
	}
}

func TestRoomMembersEmpty(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	if !st.RoomMembersEmpty() {
		t.Error("fresh DB should have empty room_members")
	}

	st.SeedRooms(map[string]RoomSeed{"general": {Topic: "Chat"}})
	generalID := st.RoomDisplayNameToID("general")
	if err := st.AddRoomMember(generalID, testutil.UserID("alice"), 0); err != nil {
		t.Fatalf("add member: %v", err)
	}

	if st.RoomMembersEmpty() {
		t.Error("should not be empty after AddRoomMember")
	}
}

func TestAddRoomMember(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.SeedRooms(map[string]RoomSeed{"general": {Topic: "Chat"}})
	roomID := st.RoomDisplayNameToID("general")

	err = st.AddRoomMember(roomID, testutil.UserID("alice"), 0)
	if err != nil {
		t.Fatalf("add: %v", err)
	}

	if !st.IsRoomMemberByID(roomID, testutil.UserID("alice")) {
		t.Error("alice should be a member")
	}

	// Idempotent — adding again should not error
	err = st.AddRoomMember(roomID, testutil.UserID("alice"), 0)
	if err != nil {
		t.Fatalf("add again: %v", err)
	}
}

// TestGetRoomMemberIDsByRoomID_DeterministicOrder verifies the V8
// ordering invariant: members come back in a stable (joined_at, user_id)
// order, so persisted client-side snapshots don't jitter across reconnects.
func TestGetRoomMemberIDsByRoomID_DeterministicOrder(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.SeedRooms(map[string]RoomSeed{"general": {Topic: "Chat"}})
	roomID := st.RoomDisplayNameToID("general")

	// Insert out of alphabetical order. joined_at has second granularity,
	// so same-second inserts tie-break by user_id — the result must be
	// sorted by user_id within the tie. The inserts are pinned to one
	// joined_at afterwards: left to the clock, three inserts straddling a
	// second boundary (seen once under a parallel race run) would make the
	// order follow insertion and fail the test for a reason it is not about.
	for _, uid := range []string{testutil.UserID("charlie"), testutil.UserID("alice"), testutil.UserID("bob")} {
		if err := st.AddRoomMember(roomID, uid, 0); err != nil {
			t.Fatalf("add %s: %v", uid, err)
		}
	}
	if _, err := st.roomsDB.Exec(`UPDATE room_members SET joined_at = ? WHERE room_id = ?`, "2026-01-01 00:00:00", roomID); err != nil {
		t.Fatalf("pin joined_at: %v", err)
	}

	first := st.GetRoomMemberIDsByRoomID(roomID)
	want := []string{testutil.UserID("alice"), testutil.UserID("bob"), testutil.UserID("charlie")}
	sort.Strings(want)
	if len(first) != len(want) {
		t.Fatalf("got %d members, want %d: %v", len(first), len(want), first)
	}
	for i := range want {
		if first[i] != want[i] {
			t.Fatalf("order[%d] = %q, want %q (full: %v)", i, first[i], want[i], first)
		}
	}

	// Stability: a second call returns the identical order.
	second := st.GetRoomMemberIDsByRoomID(roomID)
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("non-deterministic order: call1=%v call2=%v", first, second)
		}
	}
}

func TestRemoveRoomMember(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.SeedRooms(map[string]RoomSeed{"general": {Topic: "Chat"}})
	roomID := st.RoomDisplayNameToID("general")

	st.AddRoomMember(roomID, testutil.UserID("alice"), 0)
	st.AddRoomMember(roomID, testutil.UserID("bob"), 0)

	err = st.RemoveRoomMember(roomID, testutil.UserID("alice"))
	if err != nil {
		t.Fatalf("remove: %v", err)
	}

	if st.IsRoomMemberByID(roomID, testutil.UserID("alice")) {
		t.Error("alice should be removed")
	}
	if !st.IsRoomMemberByID(roomID, testutil.UserID("bob")) {
		t.Error("bob should still be a member")
	}

	// Remove non-member — should not error
	err = st.RemoveRoomMember(roomID, testutil.UserID("nobody"))
	if err != nil {
		t.Fatalf("remove non-member: %v", err)
	}
}

func TestRemoveAllRoomMembers(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.SeedRooms(map[string]RoomSeed{
		"general": {Topic: "Chat"},
		"support": {Topic: "Help"},
	})
	generalID := st.RoomDisplayNameToID("general")
	supportID := st.RoomDisplayNameToID("support")

	st.AddRoomMember(generalID, testutil.UserID("alice"), 0)
	st.AddRoomMember(supportID, testutil.UserID("alice"), 0)
	st.AddRoomMember(generalID, testutil.UserID("bob"), 0)

	st.RemoveAllRoomMembers(testutil.UserID("alice"))

	if st.IsRoomMemberByID(generalID, testutil.UserID("alice")) {
		t.Error("alice should be removed from general")
	}
	if st.IsRoomMemberByID(supportID, testutil.UserID("alice")) {
		t.Error("alice should be removed from support")
	}
	if !st.IsRoomMemberByID(generalID, testutil.UserID("bob")) {
		t.Error("bob should still be in general")
	}
}

func TestRoomsDBEmpty_FalseAfterSeed(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.SeedRooms(map[string]RoomSeed{"general": {Topic: "Chat"}})

	if st.RoomsDBEmpty() {
		t.Error("should not be empty after seed")
	}
}
