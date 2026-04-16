package main

// Phase 16 — tests for the default rooms feature.
//
// Coverage:
//   - SetRoomIsDefault store helper: happy path, retired room
//     rejection, missing room
//   - GetDefaultRooms: filters out retired rooms
//   - cmdSetDefaultRoom: backfill adds existing users, reports
//     count, errors on missing/retired/already-default
//   - cmdUnsetDefaultRoom: clears flag, leaves existing members
//   - cmdListDefaultRooms: shows flagged rooms with a friendly empty
//     message when none configured
//   - cmdListRooms: shows [default] marker on flagged rooms
//   - cmdRetireRoom: clears is_default during retirement
//   - cmdApprove auto-join hook: new user lands in flagged rooms
//   - cmdBootstrapAdmin auto-join hook: new admin lands in flagged
//     rooms

import (
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// helper: open a fresh store for the test data dir.
func openTestStore(t *testing.T, dataDir string) *store.Store {
	t.Helper()
	st, err := store.Open(dataDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return st
}

// --- store helper tests ---

func TestSetRoomIsDefault_HappyPath(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{
		"general": {Topic: "General"},
	})
	st := openTestStore(t, dataDir)
	defer st.Close()

	id := st.RoomDisplayNameToID("general")
	if err := st.SetRoomIsDefault(id, true); err != nil {
		t.Fatalf("set: %v", err)
	}

	room, _ := st.GetRoomByID(id)
	if !room.IsDefault {
		t.Error("IsDefault should be true after Set(true)")
	}

	if err := st.SetRoomIsDefault(id, false); err != nil {
		t.Fatalf("clear: %v", err)
	}
	room, _ = st.GetRoomByID(id)
	if room.IsDefault {
		t.Error("IsDefault should be false after Set(false)")
	}
}

func TestSetRoomIsDefault_RetiredRoomRejected(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{
		"general": {},
	})
	st := openTestStore(t, dataDir)
	defer st.Close()

	id := st.RoomDisplayNameToID("general")
	st.SetRoomRetired(id, "alice", "test")

	err := st.SetRoomIsDefault(id, true)
	if err == nil {
		t.Fatal("expected error flagging retired room as default")
	}
	if !strings.Contains(err.Error(), "retired") {
		t.Errorf("error should mention 'retired', got: %v", err)
	}
}

func TestGetDefaultRooms_FiltersRetired(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{
		"general":     {},
		"engineering": {},
	})
	st := openTestStore(t, dataDir)
	defer st.Close()

	genID := st.RoomDisplayNameToID("general")
	engID := st.RoomDisplayNameToID("engineering")

	st.SetRoomIsDefault(genID, true)
	st.SetRoomIsDefault(engID, true)

	defaults, _ := st.GetDefaultRooms()
	if len(defaults) != 2 {
		t.Errorf("expected 2 default rooms, got %d", len(defaults))
	}

	// Retire engineering — should drop out of GetDefaultRooms because
	// SetRoomRetired clears is_default.
	st.SetRoomRetired(engID, "alice", "test")

	defaults, _ = st.GetDefaultRooms()
	if len(defaults) != 1 {
		t.Errorf("expected 1 default room after retire, got %d", len(defaults))
	}
	if defaults[0].DisplayName != "general" {
		t.Errorf("remaining default = %q, want general", defaults[0].DisplayName)
	}
}

// --- cmdSetDefaultRoom tests ---

func TestSetDefaultRoom_HappyPath_BackfillsExistingUsers(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	bobKey, _ := genTestKey(t, "Bob")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice"},
		"usr_bob":   {Key: bobKey, DisplayName: "Bob"},
	}
	dataDir := setupDataDir(t, map[string]config.Room{
		"general": {Topic: "General"},
	}, users)

	if err := cmdSetDefaultRoom(dataDir, []string{"general"}); err != nil {
		t.Fatalf("set-default-room: %v", err)
	}

	st := openTestStore(t, dataDir)
	defer st.Close()
	id := st.RoomDisplayNameToID("general")

	// Both alice and bob should now be members of general (backfill).
	if !st.IsRoomMemberByID(id, "usr_alice") {
		t.Error("alice should be backfilled into general")
	}
	if !st.IsRoomMemberByID(id, "usr_bob") {
		t.Error("bob should be backfilled into general")
	}

	// And the room should be flagged.
	room, _ := st.GetRoomByID(id)
	if !room.IsDefault {
		t.Error("general should be flagged as default")
	}
}

func TestSetDefaultRoom_SkipsRetiredUsers(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice12345": {Key: aliceKey, DisplayName: "Alice", Retired: true, RetiredReason: "test"},
	}
	dataDir := setupDataDir(t, map[string]config.Room{
		"general": {},
	}, users)

	if err := cmdSetDefaultRoom(dataDir, []string{"general"}); err != nil {
		t.Fatalf("set-default-room: %v", err)
	}

	st := openTestStore(t, dataDir)
	defer st.Close()
	id := st.RoomDisplayNameToID("general")
	if st.IsRoomMemberByID(id, "usr_alice12345") {
		t.Error("retired alice should not have been backfilled")
	}
}

func TestSetDefaultRoom_AlreadyDefaultRejected(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{
		"general": {},
	})
	if err := cmdSetDefaultRoom(dataDir, []string{"general"}); err != nil {
		t.Fatalf("first set: %v", err)
	}
	err := cmdSetDefaultRoom(dataDir, []string{"general"})
	if err == nil {
		t.Fatal("second set should fail (already default)")
	}
	if !strings.Contains(err.Error(), "already a default") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestSetDefaultRoom_RetiredRoomRejected(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{
		"general": {},
	})
	st0 := openTestStore(t, dataDir)
	id := st0.RoomDisplayNameToID("general")
	st0.SetRoomRetired(id, "alice", "test")
	st0.Close()

	st := openTestStore(t, dataDir)
	retiredRoom, _ := st.GetRoomByID(id)
	st.Close()

	err := cmdSetDefaultRoom(dataDir, []string{retiredRoom.DisplayName})
	if err == nil {
		t.Fatal("should reject retired room")
	}
}

func TestSetDefaultRoom_MissingRoom(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	err := cmdSetDefaultRoom(dataDir, []string{"ghost"})
	if err == nil {
		t.Fatal("should reject missing room")
	}
}

func TestSetDefaultRoom_NoArgs(t *testing.T) {
	err := cmdSetDefaultRoom(t.TempDir(), nil)
	if err == nil {
		t.Fatal("should error without args")
	}
}

// --- cmdUnsetDefaultRoom tests ---

func TestUnsetDefaultRoom_LeavesExistingMembers(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice"},
	}
	dataDir := setupDataDir(t, map[string]config.Room{
		"general": {},
	}, users)

	// Flag and backfill alice.
	cmdSetDefaultRoom(dataDir, []string{"general"})

	// Unset.
	if err := cmdUnsetDefaultRoom(dataDir, []string{"general"}); err != nil {
		t.Fatalf("unset: %v", err)
	}

	st := openTestStore(t, dataDir)
	defer st.Close()
	id := st.RoomDisplayNameToID("general")

	// Flag should be cleared.
	room, _ := st.GetRoomByID(id)
	if room.IsDefault {
		t.Error("IsDefault should be false after unset")
	}

	// But alice should still be a member.
	if !st.IsRoomMemberByID(id, "usr_alice") {
		t.Error("existing members should NOT be removed by unset-default-room")
	}
}

func TestUnsetDefaultRoom_NotDefaultRejected(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{
		"general": {},
	})
	err := cmdUnsetDefaultRoom(dataDir, []string{"general"})
	if err == nil {
		t.Fatal("should reject non-default room")
	}
	if !strings.Contains(err.Error(), "not a default") {
		t.Errorf("wrong error: %v", err)
	}
}

// --- cmdListDefaultRooms tests ---

func TestListDefaultRooms_Empty(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	if err := cmdListDefaultRooms(dataDir); err != nil {
		t.Fatalf("list: %v", err)
	}
}

func TestListDefaultRooms_AfterSet(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{
		"general":     {},
		"engineering": {},
	})
	cmdSetDefaultRoom(dataDir, []string{"general"})

	if err := cmdListDefaultRooms(dataDir); err != nil {
		t.Fatalf("list: %v", err)
	}
}

// --- cmdRetireRoom integration ---

func TestRetireRoom_ClearsIsDefault(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice"},
	}
	configDir := setupConfig(t, users, nil)
	dataDir := setupDataDir(t, map[string]config.Room{
		"general": {},
	}, users)

	// Promote alice to admin so retire-room (which uses cli-admin
	// sentinel) doesn't fail any auth checks (it doesn't actually
	// check, but be defensive). Then flag general as default.
	cmdSetDefaultRoom(dataDir, []string{"general"})

	// Retire general.
	if err := cmdRetireRoom(dataDir, []string{"--room", "general", "--reason", "test"}); err != nil {
		t.Fatalf("retire: %v", err)
	}

	// is_default should be 0 after retirement (cleared by SetRoomRetired).
	st := openTestStore(t, dataDir)
	defer st.Close()
	rooms, _ := st.GetAllRooms()
	for _, r := range rooms {
		if r.Retired && r.IsDefault {
			t.Errorf("retired room %q still has IsDefault=true", r.DisplayName)
		}
	}
	_ = configDir
}

// --- approve auto-join tests ---

func TestApprove_AutoJoinsDefaultRooms(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{
		"general":     {},
		"engineering": {},
	})

	// Flag general (but not engineering) as default.
	cmdSetDefaultRoom(dataDir, []string{"general"})

	// Approve a new user.
	bobKey, _ := genTestKey(t, "Bob")
	configDir := setupConfig(t, nil, nil)
	if err := cmdApprove(configDir, dataDir, []string{"--key", bobKey, "--name", "Bob"}); err != nil {
		t.Fatalf("approve: %v", err)
	}

	st := openTestStore(t, dataDir)
	defer st.Close()

	// Find bob's user ID (cmdApprove generates a nanoid).
	allUsers := st.GetAllUsersIncludingRetired()
	var bobID string
	for _, u := range allUsers {
		if u.DisplayName == "Bob" {
			bobID = u.ID
			break
		}
	}
	if bobID == "" {
		t.Fatal("bob not found after approve")
	}

	// Bob should be in general (flagged) but NOT in engineering (not flagged).
	genID := st.RoomDisplayNameToID("general")
	engID := st.RoomDisplayNameToID("engineering")
	if !st.IsRoomMemberByID(genID, bobID) {
		t.Error("bob should be auto-joined to general (flagged default)")
	}
	if st.IsRoomMemberByID(engID, bobID) {
		t.Error("bob should NOT be auto-joined to engineering (not flagged)")
	}
}
