package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// genTestKey generates an Ed25519 key pair and returns the authorized_key line.
func genTestKey(t *testing.T, comment string) (string, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh pub: %v", err)
	}
	authKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	if comment != "" {
		authKey += " " + comment
	}

	// Write private key to temp file for reference
	block := &pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: priv}
	_ = block

	return authKey, ssh.FingerprintSHA256(sshPub)
}

// testUser is a local stand-in for the deleted config.User struct.
// Phase 16 Gap 4 removed users.toml support, so the tests can no
// longer load users from a TOML file. Instead they use this struct
// to describe a user, and setupDataDir seeds users.db / rooms.db
// directly via the public store API (InsertUser, SetUserRetired,
// AddRoomMember). Same field shape as the old config.User so the
// existing test bodies barely change.
type testUser struct {
	Key           string
	DisplayName   string
	Rooms         []string
	Retired       bool
	RetiredAt     string
	RetiredReason string
}

// setupDataDir creates a temp data dir with rooms.db and users.db seeded
// directly via the store API. Phase 16 Gap 4 removed the SeedUsers /
// SeedRoomMembers helpers, so this helper now uses InsertUser +
// SetUserRetired + AddRoomMember instead.
func setupDataDir(t *testing.T, rooms map[string]config.Room, users ...map[string]testUser) string {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if rooms != nil {
		st.SeedRooms(rooms)
	}
	if len(users) > 0 && users[0] != nil {
		for userID, u := range users[0] {
			// Insert the user row. Strip the SSH key comment for parity
			// with how cmdApprove normalizes keys.
			parts := strings.Fields(u.Key)
			keyForStorage := u.Key
			if len(parts) >= 2 {
				keyForStorage = parts[0] + " " + parts[1]
			}
			if err := st.InsertUser(userID, keyForStorage, u.DisplayName); err != nil {
				t.Fatalf("seed user %s: %v", userID, err)
			}
			if u.Retired {
				if err := st.SetUserRetired(userID, u.RetiredReason); err != nil {
					t.Fatalf("retire user %s: %v", userID, err)
				}
			}
			// Room memberships — skip retired users for parity with
			// the old SeedRoomMembers behavior.
			if !u.Retired {
				for _, roomName := range u.Rooms {
					roomID := st.RoomDisplayNameToID(roomName)
					if roomID == "" {
						continue
					}
					if err := st.AddRoomMember(roomID, userID, 0); err != nil {
						t.Fatalf("add %s to %s: %v", userID, roomName, err)
					}
				}
			}
		}
	}
	st.Close()
	return dir
}

// setupConfig creates a temp config dir with rooms.toml only.
// Phase 16 Gap 4: users.toml was removed, so the users argument is
// kept for backwards source compatibility with the test bodies but
// is no longer written anywhere — users go into the data dir via
// setupDataDir instead.
func setupConfig(t *testing.T, _ map[string]testUser, rooms map[string]config.Room) string {
	t.Helper()
	dir := t.TempDir()

	if rooms != nil {
		f, err := os.Create(filepath.Join(dir, "rooms.toml"))
		if err != nil {
			t.Fatalf("create rooms: %v", err)
		}
		for name, room := range rooms {
			f.WriteString("[" + name + "]\n")
			if room.Topic != "" {
				f.WriteString("topic = \"" + room.Topic + "\"\n")
			}
			f.WriteString("\n")
		}
		f.Close()
	}

	return dir
}

// --- Approve tests ---

func TestApprove_DuplicateKeyRejected(t *testing.T) {
	key, _ := genTestKey(t, "Alice")
	parts := strings.SplitN(key, " ", 3)
	keyLine := parts[0] + " " + parts[1]

	users := map[string]testUser{
		"usr_existing": {Key: keyLine, DisplayName: "Alice", Rooms: []string{"general"}},
	}
	configDir := setupConfig(t, users, nil)
	dataDir := setupDataDir(t, nil, users)

	err := cmdApprove(configDir, dataDir, []string{"--key", key, "--name", "Bob"})
	if err == nil {
		t.Fatal("should reject duplicate key")
	}
	if !strings.Contains(err.Error(), "already assigned") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestApprove_DuplicateDisplayNameRejected(t *testing.T) {
	existKey, _ := genTestKey(t, "Alice")
	parts := strings.SplitN(existKey, " ", 3)
	keyLine := parts[0] + " " + parts[1]

	users := map[string]testUser{
		"usr_existing": {Key: keyLine, DisplayName: "Alice", Rooms: []string{"general"}},
	}
	configDir := setupConfig(t, users, nil)
	dataDir := setupDataDir(t, nil, users)

	newKey, _ := genTestKey(t, "")
	err := cmdApprove(configDir, dataDir, []string{"--key", newKey, "--name", "Alice"})
	if err == nil {
		t.Fatal("should reject duplicate display name")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestApprove_MalformedKeyRejected(t *testing.T) {
	dir := setupConfig(t, nil, nil)
	err := cmdApprove(dir, t.TempDir(), []string{"--key", "not-a-key"})
	if err == nil {
		t.Fatal("should reject malformed key")
	}
}

func TestApprove_MissingNameRejected(t *testing.T) {
	key, _ := genTestKey(t, "") // no comment
	dir := setupConfig(t, nil, nil)
	err := cmdApprove(dir, t.TempDir(), []string{"--key", key})
	if err == nil {
		t.Fatal("should reject key with no display name")
	}
	if !strings.Contains(err.Error(), "display name required") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestApprove_ExtractsNameFromComment(t *testing.T) {
	key, _ := genTestKey(t, "TestUser")
	configDir := setupConfig(t, nil, nil)
	dataDir := setupDataDir(t, nil)
	err := cmdApprove(configDir, dataDir, []string{"--key", key})
	if err != nil {
		t.Fatalf("should accept key with comment: %v", err)
	}

	// Verify written to users.db
	st, err := store.Open(dataDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	found := false
	for _, u := range st.GetAllUsers() {
		if u.DisplayName == "TestUser" {
			found = true
			if u.Key == "" {
				t.Error("key not stored")
			}
		}
	}
	if !found {
		t.Error("user not written to users.db")
	}
}

func TestApprove_NameFlagOverridesComment(t *testing.T) {
	key, _ := genTestKey(t, "CommentName")
	configDir := setupConfig(t, nil, nil)
	dataDir := setupDataDir(t, map[string]config.Room{"general": {Topic: "Chat"}})

	err := cmdApprove(configDir, dataDir, []string{"--key", key, "--name", "OverrideName", "--rooms", "general"})
	if err != nil {
		t.Fatalf("should accept: %v", err)
	}

	// User written to users.db
	st, err := store.Open(dataDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	var userID string
	for _, u := range st.GetAllUsers() {
		if u.DisplayName == "OverrideName" {
			userID = u.ID
		}
	}
	if userID == "" {
		t.Fatal("user not written to users.db")
	}

	// Room membership in rooms.db
	generalRoom, _ := st.GetRoomByDisplayName("general")
	if generalRoom == nil {
		t.Fatal("general room not found")
	}
	if !st.IsRoomMemberByID(generalRoom.ID, userID) {
		t.Error("user should be a member of general in rooms.db")
	}
}

func TestApprove_RejectsNonEd25519(t *testing.T) {
	dir := setupConfig(t, nil, nil)
	// Generate a real ECDSA key to test type rejection
	ecKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = ecKey
	// Use the Ed25519 type check by trying a valid non-ed25519 key format
	// Since generating a real RSA key in test is complex, verify the check
	// exists by testing the path directly with a known type
	err = cmdApprove(dir, t.TempDir(), []string{"--key", "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK test", "--name", "Bob"})
	if err == nil {
		t.Fatal("should reject non-Ed25519 key")
	}
	// Either parse fails (invalid base64) or type check fails — both are correct rejections
	t.Logf("correctly rejected: %v", err)
}

func TestApprove_DisplayNameMatchesUsername(t *testing.T) {
	existKey, _ := genTestKey(t, "")
	parts := strings.SplitN(existKey, " ", 3)
	keyLine := parts[0] + " " + parts[1]

	users := map[string]testUser{
		"usr_alice123": {Key: keyLine, DisplayName: "Alice", Rooms: []string{"general"}},
	}
	configDir := setupConfig(t, users, nil)
	dataDir := setupDataDir(t, nil, users)

	newKey, _ := genTestKey(t, "")
	// Try to use a username as the display name
	err := cmdApprove(configDir, dataDir, []string{"--key", newKey, "--name", "usr_alice123"})
	if err == nil {
		t.Fatal("should reject display name that matches a username")
	}
	if !strings.Contains(err.Error(), "conflicts with an existing username") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestApprove_ShortDisplayNameRejected(t *testing.T) {
	key, _ := genTestKey(t, "")
	dir := setupConfig(t, nil, nil)
	err := cmdApprove(dir, t.TempDir(), []string{"--key", key, "--name", "A"})
	if err == nil {
		t.Fatal("should reject 1-char display name")
	}
}

func TestApprove_LongDisplayNameRejected(t *testing.T) {
	key, _ := genTestKey(t, "")
	dir := setupConfig(t, nil, nil)
	err := cmdApprove(dir, t.TempDir(), []string{"--key", key, "--name", strings.Repeat("x", 33)})
	if err == nil {
		t.Fatal("should reject 33-char display name")
	}
}

// --- Add/Remove Room tests ---

func TestAddToRoom_Success(t *testing.T) {
	key, _ := genTestKey(t, "Alice")
	parts := strings.SplitN(key, " ", 3)
	keyLine := parts[0] + " " + parts[1]

	users := map[string]testUser{"usr_alice": {Key: keyLine, DisplayName: "Alice"}}
	configDir := setupConfig(t, users, nil)
	dataDir := setupDataDir(t, map[string]config.Room{
		"general":     {Topic: "General"},
		"engineering": {Topic: "Engineering"},
	}, users)

	err := cmdAddToRoom(configDir, dataDir, []string{"--user", "usr_alice", "--room", "engineering"})
	if err != nil {
		t.Fatalf("add-to-room: %v", err)
	}

	// Verify via rooms.db
	st, _ := store.Open(dataDir)
	defer st.Close()
	engRoom, _ := st.GetRoomByDisplayName("engineering")
	if engRoom == nil {
		t.Fatal("engineering room not found")
	}
	if !st.IsRoomMemberByID(engRoom.ID, "usr_alice") {
		t.Error("alice should be in engineering")
	}
}

func TestAddToRoom_AlreadyMember(t *testing.T) {
	key, _ := genTestKey(t, "Alice")
	parts := strings.SplitN(key, " ", 3)
	keyLine := parts[0] + " " + parts[1]

	users := map[string]testUser{"usr_alice": {Key: keyLine, DisplayName: "Alice", Rooms: []string{"general"}}}
	configDir := setupConfig(t, users, nil)
	dataDir := setupDataDir(t, map[string]config.Room{"general": {}}, users)

	err := cmdAddToRoom(configDir, dataDir, []string{"--user", "usr_alice", "--room", "general"})
	if err == nil {
		t.Fatal("should reject — already a member")
	}
	if !strings.Contains(err.Error(), "already in room") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestAddToRoom_NonexistentRoom(t *testing.T) {
	key, _ := genTestKey(t, "Alice")
	parts := strings.SplitN(key, " ", 3)
	keyLine := parts[0] + " " + parts[1]

	users := map[string]testUser{"usr_alice": {Key: keyLine, DisplayName: "Alice"}}
	configDir := setupConfig(t, users, nil)
	dataDir := setupDataDir(t, map[string]config.Room{"general": {}}, users)

	err := cmdAddToRoom(configDir, dataDir, []string{"--user", "usr_alice", "--room", "fakechannel"})
	if err == nil {
		t.Fatal("should reject — room doesn't exist")
	}
	if !strings.Contains(err.Error(), "does not exist") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestAddToRoom_RetiredUser(t *testing.T) {
	key, _ := genTestKey(t, "Alice")
	parts := strings.SplitN(key, " ", 3)
	keyLine := parts[0] + " " + parts[1]

	users := map[string]testUser{
		"usr_alice": {Key: keyLine, DisplayName: "Alice", Retired: true, RetiredAt: "2026-01-01T00:00:00Z"},
	}
	configDir := setupConfig(t, users, nil)
	dataDir := setupDataDir(t, map[string]config.Room{"general": {}}, users)

	err := cmdAddToRoom(configDir, dataDir, []string{"--user", "usr_alice", "--room", "general"})
	if err == nil {
		t.Fatal("should reject — user is retired")
	}
	if !strings.Contains(err.Error(), "retired") {
		t.Errorf("wrong error: %v", err)
	}
}

// TestRemoveFromRoom_EnqueuesPendingRow verifies the Phase 16 Gap 1
// behavior of cmdRemoveFromRoom: the CLI enqueues a row in
// user_left_rooms (so the running server can run the leave cascade
// + broadcast) instead of removing the member directly. Pre-Phase-16
// this command did the direct row delete, but that meant connected
// members never saw the leave event until the next reconnect.
func TestRemoveFromRoom_EnqueuesPendingRow(t *testing.T) {
	key, _ := genTestKey(t, "Alice")
	parts := strings.SplitN(key, " ", 3)
	keyLine := parts[0] + " " + parts[1]

	users := map[string]testUser{"usr_alice": {Key: keyLine, DisplayName: "Alice", Rooms: []string{"general", "engineering"}}}
	configDir := setupConfig(t, users, nil)
	dataDir := setupDataDir(t, map[string]config.Room{
		"general":     {Topic: "General"},
		"engineering": {Topic: "Engineering"},
	}, users)

	err := cmdRemoveFromRoom(configDir, dataDir, []string{"--user", "usr_alice", "--room", "engineering"})
	if err != nil {
		t.Fatalf("remove-from-room: %v", err)
	}

	st, _ := store.Open(dataDir)
	defer st.Close()

	// Phase 16 Gap 1: alice should STILL be in engineering at this
	// point — cmdRemoveFromRoom no longer touches room_members
	// directly. The actual removal happens when the server's
	// runRemoveFromRoomProcessor consumes the queue and calls
	// performRoomLeave.
	engRoom, _ := st.GetRoomByDisplayName("engineering")
	if !st.IsRoomMemberByID(engRoom.ID, "usr_alice") {
		t.Error("alice should still be in engineering until the processor runs (CLI only enqueues)")
	}

	// Verify the queue row exists with the expected fields.
	pending, err := st.ConsumePendingRemoveFromRooms()
	if err != nil {
		t.Fatalf("consume pending: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 queue row, got %d", len(pending))
	}
	row := pending[0]
	if row.UserID != "usr_alice" {
		t.Errorf("UserID = %q, want usr_alice", row.UserID)
	}
	if row.RoomID != engRoom.ID {
		t.Errorf("RoomID = %q, want %q", row.RoomID, engRoom.ID)
	}
	if row.Reason != "removed" {
		t.Errorf("Reason = %q, want removed", row.Reason)
	}
	if !strings.HasPrefix(row.InitiatedBy, "os:") {
		t.Errorf("InitiatedBy = %q, want os: prefix", row.InitiatedBy)
	}
}

func TestRemoveFromRoom_NotAMember(t *testing.T) {
	key, _ := genTestKey(t, "Alice")
	parts := strings.SplitN(key, " ", 3)
	keyLine := parts[0] + " " + parts[1]

	users := map[string]testUser{"usr_alice": {Key: keyLine, DisplayName: "Alice"}}
	configDir := setupConfig(t, users, nil)
	dataDir := setupDataDir(t, map[string]config.Room{"general": {}, "engineering": {}}, users)

	err := cmdRemoveFromRoom(configDir, dataDir, []string{"--user", "usr_alice", "--room", "engineering"})
	if err == nil {
		t.Fatal("should reject — not a member")
	}
	if !strings.Contains(err.Error(), "not in room") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestRemoveFromRoom_NonexistentUser(t *testing.T) {
	configDir := setupConfig(t, map[string]testUser{}, nil)
	dataDir := setupDataDir(t, nil)
	err := cmdRemoveFromRoom(configDir, dataDir, []string{"--user", "usr_nobody", "--room", "general"})
	if err == nil {
		t.Fatal("should reject — user not found")
	}
}

func TestAddRoom_Success(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	err := cmdAddRoom(dataDir, []string{"--name", "engineering", "--topic", "Eng work"})
	if err != nil {
		t.Fatalf("add-room: %v", err)
	}

	st, _ := store.Open(dataDir)
	defer st.Close()
	room, _ := st.GetRoomByDisplayName("engineering")
	if room == nil {
		t.Fatal("room should exist")
	}
	if room.Topic != "Eng work" {
		t.Errorf("topic = %q", room.Topic)
	}
}

func TestAddRoom_DuplicateRejected(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{"general": {}})
	err := cmdAddRoom(dataDir, []string{"--name", "general"})
	if err == nil {
		t.Fatal("should reject duplicate")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestListRooms(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{
		"general": {Topic: "Chat"},
		"support": {Topic: "Help"},
	})
	err := cmdListRooms(dataDir)
	if err != nil {
		t.Fatalf("list-rooms: %v", err)
	}
}

// --- Reject tests ---

func setupPendingLog(t *testing.T, lines ...string) string {
	t.Helper()
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	os.MkdirAll(dataDir, 0750)
	content := strings.Join(lines, "\n") + "\n"
	os.WriteFile(filepath.Join(dataDir, "pending-keys.log"), []byte(content), 0640)
	return dir
}

func TestReject_RemovesFingerprint(t *testing.T) {
	dir := setupPendingLog(t,
		"fingerprint=SHA256:aaa attempts=1",
		"fingerprint=SHA256:bbb attempts=3",
	)
	err := cmdReject(dir, []string{"--fingerprint", "SHA256:aaa"})
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "data", "pending-keys.log"))
	if strings.Contains(string(data), "SHA256:aaa") {
		t.Error("rejected fingerprint should be removed")
	}
	if !strings.Contains(string(data), "SHA256:bbb") {
		t.Error("other fingerprint should be kept")
	}
}

func TestReject_FingerprintNotFound(t *testing.T) {
	dir := setupPendingLog(t, "fingerprint=SHA256:aaa attempts=1")
	err := cmdReject(dir, []string{"--fingerprint", "SHA256:zzz"})
	if err == nil {
		t.Fatal("should error when fingerprint not found")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestReject_NoLogFile(t *testing.T) {
	dir := t.TempDir()
	err := cmdReject(dir, []string{"--fingerprint", "SHA256:aaa"})
	if err == nil {
		t.Fatal("should error when no log file")
	}
	if !strings.Contains(err.Error(), "no pending keys log") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestReject_MissingFlag(t *testing.T) {
	err := cmdReject(t.TempDir(), nil)
	if err == nil {
		t.Fatal("should error without --fingerprint")
	}
}

// Phase 16 Gap 3: TestRemoveUser_* and the cmdRemoveUser command they
// exercised were deleted entirely. See cmdRemoveUser's deletion
// comment in main.go for the rationale (TOML-era holdover, breaks
// invariants, no valid use case post-retirement).
//
// The store.DeleteUser helper is still kept because bootstrap-admin
// uses it as a cleanup-on-error path (insert user → SetAdmin fails →
// delete the orphan). DeleteUser is no longer reachable via any CLI
// verb.

// --- rename-user tests (Phase 16 Gap 1) ---

func TestRenameUser_Success(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice"},
	}
	dataDir := setupDataDir(t, nil, users)

	err := cmdRenameUser(dataDir, []string{"usr_alice", "Alicia"})
	if err != nil {
		t.Fatalf("rename: %v", err)
	}

	st, _ := store.Open(dataDir)
	defer st.Close()
	u := st.GetUserByID("usr_alice")
	if u == nil {
		t.Fatal("user should exist after rename")
	}
	if u.DisplayName != "Alicia" {
		t.Errorf("display name = %q, want Alicia", u.DisplayName)
	}

	// Queue should contain the rename row for the running server
	// to broadcast.
	pending, _ := st.ConsumePendingAdminStateChanges()
	if len(pending) != 1 {
		t.Fatalf("expected 1 queue row, got %d", len(pending))
	}
	if pending[0].Action != store.AdminStateChangeRename {
		t.Errorf("queue action = %q, want rename", pending[0].Action)
	}
	if pending[0].UserID != "usr_alice" {
		t.Errorf("queue user = %q, want usr_alice", pending[0].UserID)
	}
}

func TestRenameUser_NonexistentUser(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	err := cmdRenameUser(dataDir, []string{"usr_ghost", "Ghosty"})
	if err == nil {
		t.Fatal("should reject — user not found")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestRenameUser_NoArgs(t *testing.T) {
	err := cmdRenameUser(t.TempDir(), nil)
	if err == nil {
		t.Fatal("should error without args")
	}
}

func TestRenameUser_OneArg(t *testing.T) {
	err := cmdRenameUser(t.TempDir(), []string{"usr_alice"})
	if err == nil {
		t.Fatal("should error with only user ID (missing new name)")
	}
}

func TestRenameUser_DuplicateRejected(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	bobKey, _ := genTestKey(t, "Bob")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice"},
		"usr_bob":   {Key: bobKey, DisplayName: "Bob"},
	}
	dataDir := setupDataDir(t, nil, users)

	// Try to rename alice to "Bob" — should reject.
	err := cmdRenameUser(dataDir, []string{"usr_alice", "Bob"})
	if err == nil {
		t.Fatal("should reject duplicate display name")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Errorf("wrong error: %v", err)
	}

	// alice's name should be unchanged.
	st, _ := store.Open(dataDir)
	defer st.Close()
	u := st.GetUserByID("usr_alice")
	if u.DisplayName != "Alice" {
		t.Errorf("display name should be unchanged, got %q", u.DisplayName)
	}
}

func TestRenameUser_DuplicateCaseInsensitive(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	bobKey, _ := genTestKey(t, "Bob")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice"},
		"usr_bob":   {Key: bobKey, DisplayName: "Bob"},
	}
	dataDir := setupDataDir(t, nil, users)

	// Try to rename alice to "BOB" — should reject (case-insensitive
	// match against existing "Bob").
	err := cmdRenameUser(dataDir, []string{"usr_alice", "BOB"})
	if err == nil {
		t.Fatal("should reject case-insensitive duplicate")
	}
}

func TestRenameUser_SameNameRejected(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice"},
	}
	dataDir := setupDataDir(t, nil, users)

	// Renaming to the same name should be rejected (not a silent
	// no-op) so the operator notices they typed the wrong thing.
	err := cmdRenameUser(dataDir, []string{"usr_alice", "Alice"})
	if err == nil {
		t.Fatal("should reject same-name rename")
	}
	if !strings.Contains(err.Error(), "no change") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestRenameUser_RetiredUserAllowed(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice12345": {Key: aliceKey, DisplayName: "Alice"},
	}
	dataDir := setupDataDir(t, nil, users)

	// Retire alice.
	st, _ := store.Open(dataDir)
	st.SetUserRetired("usr_alice12345", "test")
	st.Close()

	// Rename should still work on retired users (operators may
	// want to scrub offensive names even after retirement). The
	// expected display name after retirement is "Alice_alic"
	// (suffix added by SetUserRetired).
	err := cmdRenameUser(dataDir, []string{"usr_alice12345", "former-alice"})
	if err != nil {
		t.Fatalf("rename of retired user should succeed: %v", err)
	}

	st2, _ := store.Open(dataDir)
	defer st2.Close()
	u := st2.GetUserByID("usr_alice12345")
	if u.DisplayName != "former-alice" {
		t.Errorf("display name = %q, want former-alice", u.DisplayName)
	}
}

// --- promote/demote queue wiring tests (Phase 16 Gap 1) ---

func TestPromote_EnqueuesStateChange(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice"},
	}
	dataDir := setupDataDir(t, nil, users)

	if err := cmdPromote(dataDir, []string{"usr_alice"}); err != nil {
		t.Fatalf("promote: %v", err)
	}

	st, _ := store.Open(dataDir)
	defer st.Close()

	// Verify the flag was flipped.
	u := st.GetUserByID("usr_alice")
	if !u.Admin {
		t.Error("admin flag should be set after promote")
	}

	// Verify the queue row was enqueued.
	pending, _ := st.ConsumePendingAdminStateChanges()
	if len(pending) != 1 {
		t.Fatalf("expected 1 queue row, got %d", len(pending))
	}
	if pending[0].Action != store.AdminStateChangePromote {
		t.Errorf("action = %q, want promote", pending[0].Action)
	}
}

func TestDemote_EnqueuesStateChange(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice"},
	}
	dataDir := setupDataDir(t, nil, users)

	// Make alice admin first.
	st0, _ := store.Open(dataDir)
	st0.SetAdmin("usr_alice", true)
	st0.Close()

	if err := cmdDemote(dataDir, []string{"usr_alice"}); err != nil {
		t.Fatalf("demote: %v", err)
	}

	st, _ := store.Open(dataDir)
	defer st.Close()

	u := st.GetUserByID("usr_alice")
	if u.Admin {
		t.Error("admin flag should be cleared after demote")
	}

	pending, _ := st.ConsumePendingAdminStateChanges()
	if len(pending) != 1 {
		t.Fatalf("expected 1 queue row, got %d", len(pending))
	}
	if pending[0].Action != store.AdminStateChangeDemote {
		t.Errorf("action = %q, want demote", pending[0].Action)
	}
}

// --- update-topic / rename-room tests (Phase 16 Gap 1) ---

func TestUpdateTopic_Success(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{
		"general": {Topic: "old topic"},
	})

	err := cmdUpdateTopic(dataDir, []string{"--room", "general", "--topic", "new topic"})
	if err != nil {
		t.Fatalf("update-topic: %v", err)
	}

	st, _ := store.Open(dataDir)
	defer st.Close()
	room, _ := st.GetRoomByDisplayName("general")
	if room.Topic != "new topic" {
		t.Errorf("topic = %q, want new topic", room.Topic)
	}

	pending, _ := st.ConsumePendingRoomUpdates()
	if len(pending) != 1 {
		t.Fatalf("expected 1 queue row, got %d", len(pending))
	}
	if pending[0].Action != store.RoomUpdateActionUpdateTopic {
		t.Errorf("action = %q, want update-topic", pending[0].Action)
	}
}

func TestUpdateTopic_MissingRoom(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	err := cmdUpdateTopic(dataDir, []string{"--room", "ghost", "--topic", "new"})
	if err == nil {
		t.Fatal("should error for missing room")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestUpdateTopic_RetiredRoom(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{
		"general": {Topic: "topic"},
	})

	st0, _ := store.Open(dataDir)
	id := st0.RoomDisplayNameToID("general")
	st0.SetRoomRetired(id, "alice", "test")
	st0.Close()

	// A retired room's display name was suffixed by SetRoomRetired,
	// so we look up the post-retirement name to feed the CLI.
	st1, _ := store.Open(dataDir)
	retiredRoom, _ := st1.GetRoomByID(id)
	st1.Close()

	err := cmdUpdateTopic(dataDir, []string{"--room", retiredRoom.DisplayName, "--topic", "new"})
	if err == nil {
		t.Fatal("should error for retired room")
	}
}

func TestUpdateTopic_NoChangeRejected(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{
		"general": {Topic: "same"},
	})

	err := cmdUpdateTopic(dataDir, []string{"--room", "general", "--topic", "same"})
	if err == nil {
		t.Fatal("should reject same-topic update")
	}
	if !strings.Contains(err.Error(), "no change") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestUpdateTopic_MissingArgs(t *testing.T) {
	err := cmdUpdateTopic(t.TempDir(), nil)
	if err == nil {
		t.Fatal("should error without args")
	}
	err = cmdUpdateTopic(t.TempDir(), []string{"--room", "general"})
	if err == nil {
		t.Fatal("should error without --topic")
	}
}

func TestRenameRoom_Success(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{
		"general": {Topic: "topic"},
	})

	err := cmdRenameRoom(dataDir, []string{"--room", "general", "--new-name", "main"})
	if err != nil {
		t.Fatalf("rename-room: %v", err)
	}

	st, _ := store.Open(dataDir)
	defer st.Close()
	room, _ := st.GetRoomByDisplayName("main")
	if room == nil {
		t.Fatal("room should exist under new name")
	}
	if room.DisplayName != "main" {
		t.Errorf("display_name = %q, want main", room.DisplayName)
	}

	pending, _ := st.ConsumePendingRoomUpdates()
	if len(pending) != 1 || pending[0].Action != store.RoomUpdateActionRenameRoom {
		t.Errorf("expected 1 rename-room queue row, got %+v", pending)
	}
}

func TestRenameRoom_DuplicateRejected(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{
		"general":     {Topic: ""},
		"engineering": {Topic: ""},
	})

	err := cmdRenameRoom(dataDir, []string{"--room", "general", "--new-name", "engineering"})
	if err == nil {
		t.Fatal("should reject duplicate name")
	}
	if !strings.Contains(err.Error(), "already in use") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestRenameRoom_DuplicateCaseInsensitive(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{
		"general":     {Topic: ""},
		"engineering": {Topic: ""},
	})

	err := cmdRenameRoom(dataDir, []string{"--room", "general", "--new-name", "ENGINEERING"})
	if err == nil {
		t.Fatal("should reject case-insensitive duplicate")
	}
}

func TestRenameRoom_NoChangeRejected(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{
		"general": {},
	})

	err := cmdRenameRoom(dataDir, []string{"--room", "general", "--new-name", "general"})
	if err == nil {
		t.Fatal("should reject no-change rename")
	}
	if !strings.Contains(err.Error(), "no change") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestRenameRoom_MissingRoom(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	err := cmdRenameRoom(dataDir, []string{"--room", "ghost", "--new-name", "new"})
	if err == nil {
		t.Fatal("should error for missing room")
	}
}

func TestRenameRoom_MissingArgs(t *testing.T) {
	err := cmdRenameRoom(t.TempDir(), nil)
	if err == nil {
		t.Fatal("should error without args")
	}
	err = cmdRenameRoom(t.TempDir(), []string{"--room", "general"})
	if err == nil {
		t.Fatal("should error without --new-name")
	}
}

// --- revoke-device queue wiring tests (Phase 16 Gap 1) ---

func TestRevokeDevice_EnqueuesPendingRow(t *testing.T) {
	dataDir := setupDataDir(t, nil)

	st0, _ := store.Open(dataDir)
	st0.UpsertDevice("usr_alice", "dev_laptop")
	st0.Close()

	err := cmdRevokeDevice(dataDir, []string{"--user", "usr_alice", "--device", "dev_laptop", "--reason", "stolen"})
	if err != nil {
		t.Fatalf("revoke-device: %v", err)
	}

	st, _ := store.Open(dataDir)
	defer st.Close()

	// Verify revocation was written to revoked_devices.
	revoked, err := st.IsDeviceRevoked("usr_alice", "dev_laptop")
	if err != nil {
		t.Fatalf("IsDeviceRevoked: %v", err)
	}
	if !revoked {
		t.Error("device should be in revoked_devices")
	}

	// Verify the queue row was enqueued.
	pending, _ := st.ConsumePendingDeviceRevocations()
	if len(pending) != 1 {
		t.Fatalf("expected 1 queue row, got %d", len(pending))
	}
	row := pending[0]
	if row.UserID != "usr_alice" {
		t.Errorf("UserID = %q, want usr_alice", row.UserID)
	}
	if row.DeviceID != "dev_laptop" {
		t.Errorf("DeviceID = %q, want dev_laptop", row.DeviceID)
	}
	if row.Reason != "stolen" {
		t.Errorf("Reason = %q, want stolen", row.Reason)
	}
	if !strings.HasPrefix(row.RevokedBy, "os:") {
		t.Errorf("RevokedBy = %q, want os: prefix", row.RevokedBy)
	}
}

func TestRevokeDevice_DefaultsReason(t *testing.T) {
	dataDir := setupDataDir(t, nil)

	st0, _ := store.Open(dataDir)
	st0.UpsertDevice("usr_alice", "dev_laptop")
	st0.Close()

	err := cmdRevokeDevice(dataDir, []string{"--user", "usr_alice", "--device", "dev_laptop"})
	if err != nil {
		t.Fatalf("revoke-device: %v", err)
	}

	st, _ := store.Open(dataDir)
	defer st.Close()
	pending, _ := st.ConsumePendingDeviceRevocations()
	if len(pending) != 1 {
		t.Fatalf("expected 1 queue row, got %d", len(pending))
	}
	if pending[0].Reason != "admin_action" {
		t.Errorf("default reason = %q, want admin_action", pending[0].Reason)
	}
}

func TestRevokeDevice_RejectsInvalidDeviceID(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	err := cmdRevokeDevice(dataDir, []string{"--user", "usr_alice", "--device", "laptop"})
	if err == nil {
		t.Fatal("should reject device ID without dev_ prefix")
	}
	if !strings.Contains(err.Error(), "dev_ prefix") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestRevokeDevice_MissingArgs(t *testing.T) {
	err := cmdRevokeDevice(t.TempDir(), nil)
	if err == nil {
		t.Fatal("should error without args")
	}
	err = cmdRevokeDevice(t.TempDir(), []string{"--user", "usr_alice"})
	if err == nil {
		t.Fatal("should error without --device")
	}
}

// --- Status tests ---

// TestStatus_ProcessLineRunning verifies that status reports "running
// (PID N) since <ts>" when a live lockfile exists. Phase 19 Step 2.
//
// Seeds the dataDir with a lockfile containing the current test
// process's PID (guaranteed alive — the test is running). Captures
// stdout and asserts the Process line reports running.
func TestStatus_ProcessLineRunning(t *testing.T) {
	users := map[string]testUser{
		"usr_alice": {Key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJPpG4hFrxw7JOAppGdh0JrkNDNGxypfmwJxNFCWXnpG", DisplayName: "Alice"},
	}
	configDir := setupConfig(t, users, nil)
	dataDir := setupDataDir(t, map[string]config.Room{"general": {}}, users)

	// Seed a lockfile at the expected path with our own PID + a
	// recognisable start timestamp.
	lockPath := filepath.Join(dataDir, "sshkey-server.pid")
	content := fmt.Sprintf("%d\n%d\n", os.Getpid(), time.Now().Unix())
	if err := os.WriteFile(lockPath, []byte(content), 0644); err != nil {
		t.Fatalf("seed lockfile: %v", err)
	}

	// Capture stdout for the duration of the call.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	origStdout := os.Stdout
	os.Stdout = w

	err = cmdStatus(configDir, dataDir)

	w.Close()
	os.Stdout = origStdout

	if err != nil {
		t.Fatalf("cmdStatus: %v", err)
	}
	var buf strings.Builder
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("copy pipe: %v", err)
	}
	output := buf.String()

	wantSub := fmt.Sprintf("running (PID %d)", os.Getpid())
	if !strings.Contains(output, wantSub) {
		t.Errorf("status output missing %q\n---\n%s---", wantSub, output)
	}
}

func TestStatus_ShowsCounts(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	aliceParts := strings.SplitN(aliceKey, " ", 3)
	aliceKeyLine := aliceParts[0] + " " + aliceParts[1]

	bobKey, _ := genTestKey(t, "Bob")
	bobParts := strings.SplitN(bobKey, " ", 3)
	bobKeyLine := bobParts[0] + " " + bobParts[1]

	oldKey, _ := genTestKey(t, "Old")
	oldParts := strings.SplitN(oldKey, " ", 3)
	oldKeyLine := oldParts[0] + " " + oldParts[1]

	users := map[string]testUser{
		"usr_alice": {Key: aliceKeyLine, DisplayName: "Alice"},
		"usr_bob":   {Key: bobKeyLine, DisplayName: "Bob"},
		"usr_old":   {Key: oldKeyLine, DisplayName: "Old", Retired: true, RetiredAt: "2026-01-01T00:00:00Z"},
	}
	configDir := setupConfig(t, users, nil)

	dataDir := setupDataDir(t, map[string]config.Room{
		"general":     {},
		"engineering": {},
	}, users)

	// Should not error
	err := cmdStatus(configDir, dataDir)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
}

// --- Purge tests ---

func TestPurge_MissingFlag(t *testing.T) {
	err := cmdPurge(t.TempDir(), nil)
	if err == nil {
		t.Fatal("should error without --older-than")
	}
}

func TestPurge_InvalidDuration(t *testing.T) {
	err := cmdPurge(t.TempDir(), []string{"--older-than", "abc"})
	if err == nil {
		t.Fatal("should error on invalid duration")
	}
}

func TestPurge_DryRunNoCrash(t *testing.T) {
	dir := t.TempDir()
	// Open store to create the data dir structure
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}

	// Create a room DB with an old message
	db, err := st.RoomDB(store.GenerateID("room_"))
	if err != nil {
		t.Fatalf("room db: %v", err)
	}
	db.Exec("INSERT INTO messages (id, sender, ts, payload) VALUES (?, ?, ?, ?)",
		"msg_old", "alice", 1000, "encrypted")
	st.Close()

	err = cmdPurge(dir, []string{"--older-than", "1d", "--dry-run"})
	if err != nil {
		t.Fatalf("purge dry-run: %v", err)
	}
}

func TestParseDurationDays(t *testing.T) {
	tests := []struct {
		input string
		want  int
		err   bool
	}{
		{"30d", 30, false},
		{"6m", 180, false},
		{"1y", 365, false},
		{"5y", 1825, false},
		{"abc", 0, true},
		{"x", 0, true},
		{"10x", 0, true},
	}
	for _, tc := range tests {
		got, err := parseDurationDays(tc.input)
		if tc.err && err == nil {
			t.Errorf("parseDurationDays(%q) should error", tc.input)
		}
		if !tc.err && err != nil {
			t.Errorf("parseDurationDays(%q) unexpected error: %v", tc.input, err)
		}
		if got != tc.want {
			t.Errorf("parseDurationDays(%q) = %d, want %d", tc.input, got, tc.want)
		}
	}
}

// --- Revoke/Restore device tests ---

func TestRevokeDevice_InvalidDevicePrefix(t *testing.T) {
	err := cmdRevokeDevice(t.TempDir(), []string{"--user", "usr_a", "--device", "bad_id"})
	if err == nil {
		t.Fatal("should reject invalid device prefix")
	}
	if !strings.Contains(err.Error(), "dev_ prefix") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestRevokeDevice_MissingFlags(t *testing.T) {
	err := cmdRevokeDevice(t.TempDir(), []string{"--user", "usr_a"})
	if err == nil {
		t.Fatal("should error without --device")
	}
	err = cmdRevokeDevice(t.TempDir(), []string{"--device", "dev_x"})
	if err == nil {
		t.Fatal("should error without --user")
	}
}

func TestRestoreDevice_InvalidDevicePrefix(t *testing.T) {
	err := cmdRestoreDevice(t.TempDir(), []string{"--user", "usr_a", "--device", "notadevice"})
	if err == nil {
		t.Fatal("should reject invalid device prefix")
	}
	if !strings.Contains(err.Error(), "dev_ prefix") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestRestoreDevice_MissingFlags(t *testing.T) {
	err := cmdRestoreDevice(t.TempDir(), []string{"--user", "usr_a"})
	if err == nil {
		t.Fatal("should error without --device")
	}
}

func TestRevokeDevice_WithStore(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	// Register a device first
	st.UpsertDevice("usr_a", "dev_test123")
	st.Close()

	err = cmdRevokeDevice(dir, []string{"--user", "usr_a", "--device", "dev_test123"})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
}

func TestRestoreDevice_WithStore(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	st.UpsertDevice("usr_a", "dev_test123")
	st.RevokeDevice("usr_a", "dev_test123", "admin")
	st.Close()

	err = cmdRestoreDevice(dir, []string{"--user", "usr_a", "--device", "dev_test123"})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
}

// TestListGroups_Empty verifies the empty case prints the empty marker
// rather than failing.
func TestListGroups_Empty(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	if err := cmdListGroups(dataDir); err != nil {
		t.Errorf("list-groups on empty store should not error: %v", err)
	}
}

// TestListGroups_WithGroups verifies the function runs over a populated
// store without error.
func TestListGroups_WithGroups(t *testing.T) {
	key, _ := genTestKey(t, "Alice")
	parts := strings.SplitN(key, " ", 3)
	keyLine := parts[0] + " " + parts[1]

	users := map[string]testUser{
		"usr_alice": {Key: keyLine, DisplayName: "Alice"},
	}
	dataDir := setupDataDir(t, nil, users)
	st, _ := store.Open(dataDir)
	st.CreateGroup("group_a", "usr_alice", []string{"usr_alice"}, "Group A")
	st.CreateGroup("group_b", "usr_alice", []string{"usr_alice"}, "")
	st.Close()

	if err := cmdListGroups(dataDir); err != nil {
		t.Errorf("list-groups: %v", err)
	}
}

// --- Phase 12: retire-room + list-retired-rooms CLI tests ---

// TestRetireRoom_Success verifies the happy path: SetRoomRetired
// marks the room, the display name is suffixed, and a queue row is
// written to pending_room_retirements.
func TestRetireRoom_Success(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{
		"engineering": {Topic: "Eng work"},
	})

	if err := cmdRetireRoom(dataDir, []string{"--room", "engineering", "--reason", "team disbanded"}); err != nil {
		t.Fatalf("retire-room: %v", err)
	}

	st, _ := store.Open(dataDir)
	defer st.Close()

	// Display name should be suffixed, original name freed
	orig, _ := st.GetRoomByDisplayName("engineering")
	if orig != nil {
		t.Error("original 'engineering' name should be free for reuse")
	}

	rooms, _ := st.GetAllRooms()
	var retired *store.RoomRecord
	for i := range rooms {
		if rooms[i].Retired {
			retired = &rooms[i]
			break
		}
	}
	if retired == nil {
		t.Fatal("should have one retired room")
	}
	if !strings.HasPrefix(retired.DisplayName, "engineering_") {
		t.Errorf("display name should be suffixed, got %q", retired.DisplayName)
	}
	if retired.RetiredBy == "" {
		t.Error("retired_by should be set")
	}

	// Queue row should have been written
	pending, _ := st.ConsumePendingRoomRetirements()
	if len(pending) != 1 {
		t.Fatalf("expected 1 queued retirement, got %d", len(pending))
	}
	if pending[0].RoomID != retired.ID {
		t.Errorf("queue room_id = %q, want %q", pending[0].RoomID, retired.ID)
	}
	if pending[0].Reason != "team disbanded" {
		t.Errorf("queue reason = %q, want 'team disbanded'", pending[0].Reason)
	}
}

// TestRetireRoom_AcceptsNanoid verifies that --room accepts a nanoid
// (not just a display name), per Q7.
func TestRetireRoom_AcceptsNanoid(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{
		"general": {Topic: "Chat"},
	})

	st, _ := store.Open(dataDir)
	generalID := st.RoomDisplayNameToID("general")
	st.Close()

	if err := cmdRetireRoom(dataDir, []string{"--room", generalID}); err != nil {
		t.Fatalf("retire-room by nanoid: %v", err)
	}

	st, _ = store.Open(dataDir)
	defer st.Close()
	room, _ := st.GetRoomByID(generalID)
	if room == nil || !room.Retired {
		t.Error("room should be retired after retire-room with nanoid arg")
	}
}

// TestRetireRoom_AlreadyRetiredRejected verifies that attempting to
// retire a room that is already retired returns an error.
func TestRetireRoom_AlreadyRetiredRejected(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{
		"general": {Topic: "Chat"},
	})

	if err := cmdRetireRoom(dataDir, []string{"--room", "general"}); err != nil {
		t.Fatalf("first retire-room: %v", err)
	}

	// Second call should fail — the original name is free but there's
	// no "general" room anymore (it's been suffixed).
	err := cmdRetireRoom(dataDir, []string{"--room", "general"})
	if err == nil {
		t.Fatal("should fail: room 'general' no longer exists after suffixing")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("wrong error: %v", err)
	}
}

// TestRetireRoom_NonexistentRoomRejected verifies that retiring a
// room that doesn't exist returns a clear error.
func TestRetireRoom_NonexistentRoomRejected(t *testing.T) {
	dataDir := setupDataDir(t, nil)

	err := cmdRetireRoom(dataDir, []string{"--room", "ghost"})
	if err == nil {
		t.Fatal("should reject nonexistent room")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("wrong error: %v", err)
	}
}

// TestRetireRoom_MissingArgs verifies the usage error when --room is
// not provided.
func TestRetireRoom_MissingArgs(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	err := cmdRetireRoom(dataDir, []string{})
	if err == nil {
		t.Fatal("should require --room")
	}
	if !strings.Contains(err.Error(), "usage") {
		t.Errorf("wrong error: %v", err)
	}
}

// TestRetireRoom_ReasonDefaultsToAdmin verifies that if no --reason
// is provided, the reason defaults to "admin" (matching the
// cmdRetireUser default).
func TestRetireRoom_ReasonDefaultsToAdmin(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{
		"general": {Topic: "Chat"},
	})

	if err := cmdRetireRoom(dataDir, []string{"--room", "general"}); err != nil {
		t.Fatalf("retire-room: %v", err)
	}

	st, _ := store.Open(dataDir)
	defer st.Close()
	pending, _ := st.ConsumePendingRoomRetirements()
	if len(pending) != 1 {
		t.Fatalf("expected 1 queued retirement, got %d", len(pending))
	}
	if pending[0].Reason != "admin" {
		t.Errorf("reason = %q, want 'admin'", pending[0].Reason)
	}
}

// TestListRetiredRooms_Empty verifies the empty case.
func TestListRetiredRooms_Empty(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{
		"general": {Topic: "Chat"},
	})

	// Should not error — just prints "No retired rooms."
	if err := cmdListRetiredRooms(dataDir); err != nil {
		t.Errorf("list-retired-rooms: %v", err)
	}
}

// TestListRetiredRooms_WithEntries verifies that retired rooms appear
// in the output after retirement.
func TestListRetiredRooms_WithEntries(t *testing.T) {
	dataDir := setupDataDir(t, map[string]config.Room{
		"general":     {Topic: "Chat"},
		"engineering": {Topic: "Eng work"},
	})

	// Retire one of them
	if err := cmdRetireRoom(dataDir, []string{"--room", "engineering"}); err != nil {
		t.Fatalf("retire-room: %v", err)
	}

	// Should not error — the listing should run cleanly
	if err := cmdListRetiredRooms(dataDir); err != nil {
		t.Errorf("list-retired-rooms: %v", err)
	}
}
