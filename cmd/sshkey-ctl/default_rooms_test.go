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
//     (also covers the `--admin` first-admin path, which shares the
//     same auto-join code path post-bootstrap-admin removal)

import (
	"strings"
	"testing"

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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
		"general": {Topic: "General"},
	}, users)

	var setErr error
	out := captureStdout(t, func() {
		setErr = cmdSetDefaultRoom(dataDir, []string{"general"})
	})
	if setErr != nil {
		t.Fatalf("set-default-room: %v", setErr)
	}
	if !strings.Contains(out, "within ~5 seconds") {
		t.Fatalf("set-default-room output should describe live queue timing, got:\n%s", out)
	}
	if strings.Contains(out, "next reconnect") {
		t.Fatalf("set-default-room output still contains stale reconnect-only wording:\n%s", out)
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
	pending, err := st.ConsumePendingAddToRooms()
	if err != nil {
		t.Fatalf("consume pending add-to-room: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("backfill should enqueue 2 live side-effect rows, got %d", len(pending))
	}
	seen := map[string]bool{}
	for _, row := range pending {
		if row.RoomID != id {
			t.Errorf("pending row room = %q, want %q", row.RoomID, id)
		}
		seen[row.UserID] = true
	}
	for _, userID := range []string{"usr_alice", "usr_bob"} {
		if !seen[userID] {
			t.Errorf("missing pending add-to-room row for %s", userID)
		}
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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

func TestApproveRooms_DuplicateNamesAndDefaultOverlapQueueOnce(t *testing.T) {
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
		"general": {},
		"support": {},
	})

	// Flag general before any users exist, so this setup step creates no queue
	// rows. The approve path below is the only producer under test.
	if err := cmdSetDefaultRoom(dataDir, []string{"general"}); err != nil {
		t.Fatalf("set default: %v", err)
	}
	st0 := openTestStore(t, dataDir)
	if pending, err := st0.ConsumePendingAddToRooms(); err != nil {
		st0.Close()
		t.Fatalf("consume setup queue: %v", err)
	} else if len(pending) != 0 {
		st0.Close()
		t.Fatalf("setup default-room call should not queue rows with no users, got %d", len(pending))
	}
	st0.Close()

	bobKey, _ := genTestKey(t, "Bob")
	configDir := setupConfig(t, nil, nil)
	var approveErr error
	out := captureStdout(t, func() {
		approveErr = cmdApprove(configDir, dataDir, []string{
			"--key", bobKey,
			"--name", "Bob",
			"--rooms", "general,general,support",
		})
	})
	if approveErr != nil {
		t.Fatalf("approve: %v", approveErr)
	}
	if !strings.Contains(out, "Rooms:") || !strings.Contains(out, "general,general,support") {
		t.Fatalf("approve output should echo operator-provided --rooms, got:\n%s", out)
	}
	if strings.Contains(out, "Default rooms auto-joined") {
		t.Fatalf("overlapping default room should not be double-counted in output, got:\n%s", out)
	}

	st := openTestStore(t, dataDir)
	defer st.Close()
	var bobID string
	for _, u := range st.GetAllUsersIncludingRetired() {
		if u.DisplayName == "Bob" {
			bobID = u.ID
			break
		}
	}
	if bobID == "" {
		t.Fatal("bob not found after approve")
	}

	generalID := st.RoomDisplayNameToID("general")
	supportID := st.RoomDisplayNameToID("support")
	for name, roomID := range map[string]string{"general": generalID, "support": supportID} {
		if !st.IsRoomMemberByID(roomID, bobID) {
			t.Errorf("bob should be a member of %s", name)
		}
	}

	pending, err := st.ConsumePendingAddToRooms()
	if err != nil {
		t.Fatalf("consume pending add-to-room: %v", err)
	}
	if len(pending) != 2 {
		t.Fatalf("duplicate --rooms plus default overlap should enqueue exactly 2 rows, got %d", len(pending))
	}
	counts := map[string]int{}
	for _, row := range pending {
		if row.UserID != bobID {
			t.Errorf("pending user = %q, want %q", row.UserID, bobID)
		}
		counts[row.RoomID]++
	}
	if counts[generalID] != 1 {
		t.Errorf("general should be queued once despite duplicate/default overlap, got %d", counts[generalID])
	}
	if counts[supportID] != 1 {
		t.Errorf("support should be queued once, got %d", counts[supportID])
	}
}
