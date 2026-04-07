package store

import (
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
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

func TestGenerateRoomID(t *testing.T) {
	id := GenerateRoomID()
	if !strings.HasPrefix(id, "room_") {
		t.Errorf("room ID should start with room_, got %q", id)
	}
	if len(id) != 26 { // "room_" (5) + 21 chars
		t.Errorf("room ID length = %d, want 26", len(id))
	}

	// Should be unique
	id2 := GenerateRoomID()
	if id == id2 {
		t.Error("two generated IDs should not be equal")
	}
}

func TestGenerateID_Prefix(t *testing.T) {
	id := GenerateID("test_")
	if !strings.HasPrefix(id, "test_") {
		t.Errorf("should start with test_, got %q", id)
	}
}

func TestSeedRooms_PopulatesDB(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	rooms := map[string]config.Room{
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

	rooms := map[string]config.Room{
		"general": {Topic: "General chat"},
	}

	// First seed
	count, _ := st.SeedRooms(rooms)
	if count != 1 {
		t.Fatalf("first seed: %d", count)
	}

	// Second seed — should skip
	count, err = st.SeedRooms(map[string]config.Room{
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

	count, err := st.SeedRooms(map[string]config.Room{})
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

	st.SeedRooms(map[string]config.Room{"general": {Topic: "Chat"}})

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
	room, _ = st.GetRoomByID("room_nonexistent")
	if room != nil {
		t.Error("should return nil for nonexistent ID")
	}
}

func TestGetRoomByDisplayName(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.SeedRooms(map[string]config.Room{"general": {Topic: "Chat"}})

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

	st.SeedRooms(map[string]config.Room{"general": {Topic: "Chat"}})

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

func TestIsRoomRetired(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.SeedRooms(map[string]config.Room{"general": {Topic: "Chat"}})

	all, _ := st.GetAllRooms()
	id := all[0].ID

	if st.IsRoomRetired(id) {
		t.Error("fresh room should not be retired")
	}

	// Manually set retired
	st.roomsDB.Exec(`UPDATE rooms SET retired = 1 WHERE id = ?`, id)

	if !st.IsRoomRetired(id) {
		t.Error("should be retired after update")
	}

	// Nonexistent room
	if st.IsRoomRetired("room_fake") {
		t.Error("nonexistent room should not be retired")
	}
}

func TestSeedRoomMembers_PopulatesDB(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	// Seed rooms first
	st.SeedRooms(map[string]config.Room{
		"general": {Topic: "General"},
		"support": {Topic: "Help"},
	})

	// Seed members
	users := map[string]config.User{
		"usr_alice": {DisplayName: "Alice", Rooms: []string{"general", "support"}},
		"usr_bob":   {DisplayName: "Bob", Rooms: []string{"general"}},
	}
	count, err := st.SeedRoomMembers(users)
	if err != nil {
		t.Fatalf("seed members: %v", err)
	}
	if count != 3 { // alice in 2 rooms + bob in 1
		t.Errorf("seeded %d memberships, want 3", count)
	}

	// Verify via direct query
	generalID := st.RoomDisplayNameToID("general")
	supportID := st.RoomDisplayNameToID("support")

	var generalCount, supportCount int
	st.roomsDB.QueryRow(`SELECT COUNT(*) FROM room_members WHERE room_id = ?`, generalID).Scan(&generalCount)
	st.roomsDB.QueryRow(`SELECT COUNT(*) FROM room_members WHERE room_id = ?`, supportID).Scan(&supportCount)

	if generalCount != 2 {
		t.Errorf("general should have 2 members, got %d", generalCount)
	}
	if supportCount != 1 {
		t.Errorf("support should have 1 member, got %d", supportCount)
	}
}

func TestSeedRoomMembers_SkipsRetiredUsers(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.SeedRooms(map[string]config.Room{"general": {Topic: "Chat"}})

	users := map[string]config.User{
		"usr_alice": {DisplayName: "Alice", Rooms: []string{"general"}},
		"usr_old":   {DisplayName: "Old", Rooms: []string{"general"}, Retired: true},
	}
	count, _ := st.SeedRoomMembers(users)
	if count != 1 {
		t.Errorf("should skip retired, got %d memberships", count)
	}
}

func TestSeedRoomMembers_SkipsUnknownRooms(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.SeedRooms(map[string]config.Room{"general": {Topic: "Chat"}})

	users := map[string]config.User{
		"usr_alice": {DisplayName: "Alice", Rooms: []string{"general", "nonexistent"}},
	}
	count, err := st.SeedRoomMembers(users)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if count != 1 { // only general, nonexistent skipped
		t.Errorf("should skip unknown room, got %d", count)
	}
}

func TestSeedRoomMembers_SkipsIfNotEmpty(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.SeedRooms(map[string]config.Room{"general": {Topic: "Chat"}})

	users := map[string]config.User{
		"usr_alice": {DisplayName: "Alice", Rooms: []string{"general"}},
	}
	st.SeedRoomMembers(users)

	// Second seed should skip
	count, _ := st.SeedRoomMembers(map[string]config.User{
		"usr_bob": {DisplayName: "Bob", Rooms: []string{"general"}},
	})
	if count != 0 {
		t.Errorf("second seed should skip, got %d", count)
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

	st.SeedRooms(map[string]config.Room{"general": {Topic: "Chat"}})
	st.SeedRoomMembers(map[string]config.User{
		"usr_alice": {DisplayName: "Alice", Rooms: []string{"general"}},
	})

	if st.RoomMembersEmpty() {
		t.Error("should not be empty after seed")
	}
}

func TestRoomsDBEmpty_FalseAfterSeed(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer st.Close()

	st.SeedRooms(map[string]config.Room{"general": {Topic: "Chat"}})

	if st.RoomsDBEmpty() {
		t.Error("should not be empty after seed")
	}
}
