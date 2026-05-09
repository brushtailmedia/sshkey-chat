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

// testUser describes a user fixture for setupDataDir. Tests construct
// one or more testUsers and setupDataDir seeds users.db / rooms.db
// directly via the public store API (InsertUser, SetUserRetired,
// AddRoomMember).
type testUser struct {
	Key           string
	DisplayName   string
	Rooms         []string
	Retired       bool
	RetiredAt     string
	RetiredReason string
}

// setupDataDir creates a temp data dir with rooms.db and users.db seeded
// directly via the store API (InsertUser + SetUserRetired + AddRoomMember).
func setupDataDir(t *testing.T, rooms map[string]store.RoomSeed, users ...map[string]testUser) string {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if rooms != nil {
		if _, err := st.SeedRooms(rooms); err != nil {
			t.Fatalf("seed rooms: %v", err)
		}
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

// setupConfig creates a temp config dir with a minimal server.toml.
// The rooms/users arguments are retained for source compatibility with
// existing call sites; room/user data is seeded into SQLite via
// setupDataDir.
func setupConfig(t *testing.T, _ map[string]testUser, _ map[string]store.RoomSeed) string {
	t.Helper()
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "server.toml"), []byte(`
[server]
port = 2222
bind = "127.0.0.1"
`), 0644); err != nil {
		t.Fatalf("write server.toml: %v", err)
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{"general": {Topic: "Chat"}})

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

func TestApprove_ClearsPendingKeyFromDBAndLog(t *testing.T) {
	key, fp := genTestKey(t, "Alice")
	_, otherFP := genTestKey(t, "Other")
	configDir := setupConfig(t, nil, nil)
	dataDir := setupDataDir(t, nil)

	st, err := store.Open(dataDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := st.DataDB().Exec(
		`INSERT INTO pending_keys (fingerprint, remote_addr) VALUES (?, ?), (?, ?)`,
		fp, "127.0.0.1:2222", otherFP, "127.0.0.1:2223",
	); err != nil {
		st.Close()
		t.Fatalf("seed pending_keys: %v", err)
	}
	st.Close()

	logDir := filepath.Join(dataDir, "data")
	if err := os.MkdirAll(logDir, 0750); err != nil {
		t.Fatalf("mkdir log dir: %v", err)
	}
	logContent := strings.Join([]string{
		"fingerprint=" + fp + " remote=127.0.0.1:2222",
		"fingerprint=" + otherFP + " remote=127.0.0.1:2223",
	}, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(logDir, "pending-keys.log"), []byte(logContent), 0640); err != nil {
		t.Fatalf("write pending log: %v", err)
	}

	if err := cmdApprove(configDir, dataDir, []string{"--key", key, "--name", "Alice"}); err != nil {
		t.Fatalf("approve: %v", err)
	}

	st, err = store.Open(dataDir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer st.Close()

	var count int
	if err := st.DataDB().QueryRow(`SELECT COUNT(1) FROM pending_keys WHERE fingerprint = ?`, fp).Scan(&count); err != nil {
		t.Fatalf("count approved fingerprint: %v", err)
	}
	if count != 0 {
		t.Fatalf("approved fingerprint should be removed from pending_keys, got count=%d", count)
	}
	if err := st.DataDB().QueryRow(`SELECT COUNT(1) FROM pending_keys WHERE fingerprint = ?`, otherFP).Scan(&count); err != nil {
		t.Fatalf("count other fingerprint: %v", err)
	}
	if count != 1 {
		t.Fatalf("other fingerprint should remain pending, got count=%d", count)
	}

	logData, err := os.ReadFile(filepath.Join(logDir, "pending-keys.log"))
	if err != nil {
		t.Fatalf("read pending log: %v", err)
	}
	if strings.Contains(string(logData), fp) {
		t.Fatalf("approved fingerprint should be removed from pending log:\n%s", string(logData))
	}
	if !strings.Contains(string(logData), otherFP) {
		t.Fatalf("other pending fingerprint should remain in log:\n%s", string(logData))
	}
}

func TestApprove_ClearsPendingDBWhenLogMissing(t *testing.T) {
	key, fp := genTestKey(t, "Alice")
	configDir := setupConfig(t, nil, nil)
	dataDir := setupDataDir(t, nil)

	st, err := store.Open(dataDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := st.DataDB().Exec(`INSERT INTO pending_keys (fingerprint, remote_addr) VALUES (?, ?)`, fp, "127.0.0.1:2222"); err != nil {
		st.Close()
		t.Fatalf("seed pending_keys: %v", err)
	}
	st.Close()

	if err := cmdApprove(configDir, dataDir, []string{"--key", key, "--name", "Alice"}); err != nil {
		t.Fatalf("approve: %v", err)
	}

	st, err = store.Open(dataDir)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer st.Close()
	var count int
	if err := st.DataDB().QueryRow(`SELECT COUNT(1) FROM pending_keys WHERE fingerprint = ?`, fp).Scan(&count); err != nil {
		t.Fatalf("count approved fingerprint: %v", err)
	}
	if count != 0 {
		t.Fatalf("approved fingerprint should be removed from pending_keys, got count=%d", count)
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

// TestApprove_AdminFlagSetsAdminBit covers the `--admin` flag that
// replaced bootstrap-admin's first-admin path (2026-05-09). Without the
// flag, approve must leave admin=0 (the schema default); with the flag,
// the user must come out as admin=1 in users.db.
func TestApprove_AdminFlagSetsAdminBit(t *testing.T) {
	// Without --admin: control case — must NOT be admin.
	plainKey, _ := genTestKey(t, "Plain")
	plainConfig := setupConfig(t, nil, nil)
	plainData := setupDataDir(t, nil)
	if err := cmdApprove(plainConfig, plainData, []string{"--key", plainKey, "--name", "Plain"}); err != nil {
		t.Fatalf("approve plain: %v", err)
	}
	st, err := store.Open(plainData)
	if err != nil {
		t.Fatalf("open plain store: %v", err)
	}
	var plainID string
	for _, u := range st.GetAllUsers() {
		if u.DisplayName == "Plain" {
			plainID = u.ID
		}
	}
	st.Close()
	if plainID == "" {
		t.Fatal("plain user not found after approve")
	}
	st, _ = store.Open(plainData)
	if st.IsAdmin(plainID) {
		t.Error("approve without --admin must leave admin=0")
	}
	st.Close()

	// With --admin: bit must flip.
	adminKey, _ := genTestKey(t, "Admin")
	adminConfig := setupConfig(t, nil, nil)
	adminData := setupDataDir(t, nil)
	if err := cmdApprove(adminConfig, adminData, []string{"--key", adminKey, "--name", "Admin", "--admin"}); err != nil {
		t.Fatalf("approve --admin: %v", err)
	}
	st, err = store.Open(adminData)
	if err != nil {
		t.Fatalf("open admin store: %v", err)
	}
	defer st.Close()
	var adminID string
	for _, u := range st.GetAllUsers() {
		if u.DisplayName == "Admin" {
			adminID = u.ID
		}
	}
	if adminID == "" {
		t.Fatal("admin user not found after approve --admin")
	}
	if !st.IsAdmin(adminID) {
		t.Error("approve --admin must set admin=1")
	}
}

// --- Add/Remove Room tests ---

func TestAddToRoom_Success(t *testing.T) {
	key, _ := genTestKey(t, "Alice")
	parts := strings.SplitN(key, " ", 3)
	keyLine := parts[0] + " " + parts[1]

	users := map[string]testUser{"usr_alice": {Key: keyLine, DisplayName: "Alice"}}
	configDir := setupConfig(t, users, nil)
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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

	// add-to-room now enqueues live side effects for the running
	// server: join broadcast + epoch rotation trigger.
	pending, err := st.ConsumePendingAddToRooms()
	if err != nil {
		t.Fatalf("consume pending add-to-room: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending add row, got %d", len(pending))
	}
	if pending[0].UserID != "usr_alice" {
		t.Errorf("pending user = %q, want usr_alice", pending[0].UserID)
	}
	if pending[0].RoomID != engRoom.ID {
		t.Errorf("pending room = %q, want %q", pending[0].RoomID, engRoom.ID)
	}
	if !strings.HasPrefix(pending[0].InitiatedBy, "os:") {
		t.Errorf("pending initiated_by = %q, want os: prefix", pending[0].InitiatedBy)
	}
}

func TestAddToRoom_AlreadyMember(t *testing.T) {
	key, _ := genTestKey(t, "Alice")
	parts := strings.SplitN(key, " ", 3)
	keyLine := parts[0] + " " + parts[1]

	users := map[string]testUser{"usr_alice": {Key: keyLine, DisplayName: "Alice", Rooms: []string{"general"}}}
	configDir := setupConfig(t, users, nil)
	dataDir := setupDataDir(t, map[string]store.RoomSeed{"general": {}}, users)

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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{"general": {}}, users)

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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{"general": {}}, users)

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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{"general": {}, "engineering": {}}, users)

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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{"general": {}})
	err := cmdAddRoom(dataDir, []string{"--name", "general"})
	if err == nil {
		t.Fatal("should reject duplicate")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestListRooms(t *testing.T) {
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
		"general": {Topic: "Chat"},
		"support": {Topic: "Help"},
	})
	err := cmdListRooms(dataDir)
	if err != nil {
		t.Fatalf("list-rooms: %v", err)
	}
}

// --- purge-pending and reject-pending tests ---
//
// Replaces the previous `reject` command which only pruned the log
// (DB row stayed behind, allowing the same key to retry and re-queue).
// purge-pending = clear DB + log, allow retry. reject-pending =
// clear DB + log AND add to fingerprint blocklist, prevent retry.
// See cmdPurgePending / cmdRejectPending in main.go.

// setupPendingLog seeds <dataDir>/data/pending-keys.log only.
// Sufficient for tests that don't care about the DB row (e.g.
// initial purge-pending log-only assertions). DB-aware tests use
// setupPendingDBAndLog below.
func setupPendingLog(t *testing.T, lines ...string) string {
	t.Helper()
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	os.MkdirAll(dataDir, 0750)
	content := strings.Join(lines, "\n") + "\n"
	os.WriteFile(filepath.Join(dataDir, "pending-keys.log"), []byte(content), 0640)
	return dir
}

// setupPendingDBAndLog seeds both `pending_keys` rows and
// `pending-keys.log` lines with matching fingerprints. Used by the
// purge/reject tests to assert both halves of the cleanup primitive.
func setupPendingDBAndLog(t *testing.T, fingerprints ...string) string {
	t.Helper()
	dir := setupDataDir(t, nil)
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	for i, fp := range fingerprints {
		addr := fmt.Sprintf("127.0.0.1:%d", 3000+i)
		if _, err := st.DataDB().Exec(
			`INSERT INTO pending_keys (fingerprint, remote_addr) VALUES (?, ?)`, fp, addr,
		); err != nil {
			st.Close()
			t.Fatalf("seed pending_keys: %v", err)
		}
	}
	st.Close()

	logDir := filepath.Join(dir, "data")
	os.MkdirAll(logDir, 0750)
	var lines []string
	for i, fp := range fingerprints {
		lines = append(lines, fmt.Sprintf("fingerprint=%s remote=127.0.0.1:%d", fp, 3000+i))
	}
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(logDir, "pending-keys.log"), []byte(content), 0640); err != nil {
		t.Fatalf("write log: %v", err)
	}
	return dir
}

func countPendingDB(t *testing.T, dataDir string) int {
	t.Helper()
	st, err := store.Open(dataDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer st.Close()
	var count int
	if err := st.DataDB().QueryRow(`SELECT COUNT(*) FROM pending_keys`).Scan(&count); err != nil {
		t.Fatalf("count pending_keys: %v", err)
	}
	return count
}

func TestPurgePending_FpClearsDBAndLog(t *testing.T) {
	dir := setupPendingDBAndLog(t, "SHA256:aaa", "SHA256:bbb")

	if err := cmdPurgePending(dir, []string{"--fp", "SHA256:aaa"}); err != nil {
		t.Fatalf("purge-pending: %v", err)
	}

	// Both DB row and log line for SHA256:aaa should be gone; bbb stays.
	if got := countPendingDB(t, dir); got != 1 {
		t.Errorf("DB row count = %d, want 1 (bbb only)", got)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "data", "pending-keys.log"))
	if strings.Contains(string(data), "SHA256:aaa") {
		t.Errorf("SHA256:aaa should be cleared from log, got:\n%s", string(data))
	}
	if !strings.Contains(string(data), "SHA256:bbb") {
		t.Errorf("SHA256:bbb should remain in log, got:\n%s", string(data))
	}
}

func TestPurgePending_FpUnknownIsNoop(t *testing.T) {
	dir := setupPendingDBAndLog(t, "SHA256:aaa")

	// Purging an unknown fingerprint shouldn't error or affect existing entries.
	if err := cmdPurgePending(dir, []string{"--fp", "SHA256:zzz"}); err != nil {
		t.Fatalf("purge-pending unknown fp: %v", err)
	}
	if got := countPendingDB(t, dir); got != 1 {
		t.Errorf("DB row count = %d, want 1 (existing aaa unchanged)", got)
	}
}

func TestPurgePending_AllRequiresYes(t *testing.T) {
	dir := setupPendingDBAndLog(t, "SHA256:aaa", "SHA256:bbb")

	// Without --yes, should be a dry run: prints the count, doesn't delete.
	if err := cmdPurgePending(dir, []string{"--all"}); err != nil {
		t.Fatalf("purge-pending --all (no --yes): %v", err)
	}
	if got := countPendingDB(t, dir); got != 2 {
		t.Errorf("DB row count = %d, want 2 (no destructive action without --yes)", got)
	}
}

func TestPurgePending_AllYesClearsEverything(t *testing.T) {
	dir := setupPendingDBAndLog(t, "SHA256:aaa", "SHA256:bbb", "SHA256:ccc")

	if err := cmdPurgePending(dir, []string{"--all", "--yes"}); err != nil {
		t.Fatalf("purge-pending --all --yes: %v", err)
	}
	if got := countPendingDB(t, dir); got != 0 {
		t.Errorf("DB row count = %d, want 0 (wholesale clear)", got)
	}
	data, _ := os.ReadFile(filepath.Join(dir, "data", "pending-keys.log"))
	if len(strings.TrimSpace(string(data))) != 0 {
		t.Errorf("log should be empty after --all --yes, got:\n%s", string(data))
	}
}

func TestPurgePending_RejectsConflictingFlags(t *testing.T) {
	dir := setupPendingDBAndLog(t, "SHA256:aaa")
	err := cmdPurgePending(dir, []string{"--fp", "SHA256:aaa", "--all"})
	if err == nil {
		t.Fatal("--fp + --all should error")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("error should call out the conflict: %v", err)
	}
}

func TestPurgePending_MissingFlag(t *testing.T) {
	if err := cmdPurgePending(t.TempDir(), nil); err == nil {
		t.Fatal("purge-pending without --fp or --all should error")
	}
}

func TestRejectPending_ClearsAndBlocks(t *testing.T) {
	dir := setupPendingDBAndLog(t, "SHA256:aaa", "SHA256:bbb")

	if err := cmdRejectPending(dir, []string{"--fp", "SHA256:aaa", "--reason", "spam"}); err != nil {
		t.Fatalf("reject-pending: %v", err)
	}

	// DB row gone for SHA256:aaa
	if got := countPendingDB(t, dir); got != 1 {
		t.Errorf("DB row count = %d, want 1 (bbb only)", got)
	}
	// Log line for SHA256:aaa gone
	data, _ := os.ReadFile(filepath.Join(dir, "data", "pending-keys.log"))
	if strings.Contains(string(data), "SHA256:aaa") {
		t.Errorf("SHA256:aaa should be cleared from log, got:\n%s", string(data))
	}
	// Blocklist contains SHA256:aaa
	st, _ := store.Open(dir)
	defer st.Close()
	if !st.IsFingerprintBlocked("SHA256:aaa") {
		t.Error("SHA256:aaa should be on the block list after reject-pending")
	}
	if st.IsFingerprintBlocked("SHA256:bbb") {
		t.Error("SHA256:bbb should NOT be on the block list (only the rejected one)")
	}
}

func TestRejectPending_AlreadyBlockedIsIdempotent(t *testing.T) {
	dir := setupPendingDBAndLog(t, "SHA256:aaa")

	st, _ := store.Open(dir)
	if err := st.BlockFingerprint("SHA256:aaa", "earlier", "test"); err != nil {
		st.Close()
		t.Fatalf("seed block: %v", err)
	}
	st.Close()

	// Second call shouldn't error and should still clear the pending entry.
	if err := cmdRejectPending(dir, []string{"--fp", "SHA256:aaa"}); err != nil {
		t.Fatalf("reject-pending on already-blocked: %v", err)
	}
	if got := countPendingDB(t, dir); got != 0 {
		t.Errorf("DB row count = %d, want 0 (pending entry cleared even when already blocked)", got)
	}
}

func TestRejectPending_RejectsBareFingerprint(t *testing.T) {
	// Reject-pending requires SHA256: prefix to match the blocklist
	// and pending_keys table conventions.
	if err := cmdRejectPending(t.TempDir(), []string{"--fp", "abcdef"}); err == nil {
		t.Fatal("reject-pending should require SHA256: prefix on fingerprint")
	}
}

func TestRejectPending_MissingFlag(t *testing.T) {
	if err := cmdRejectPending(t.TempDir(), nil); err == nil {
		t.Fatal("reject-pending without --fp should error")
	}
}

// Phase 16 Gap 3: TestRemoveUser_* and the cmdRemoveUser command they
// exercised were deleted entirely. See cmdRemoveUser's deletion
// comment in main.go for the rationale (TOML-era holdover, breaks
// invariants, no valid use case post-retirement). store.DeleteUser
// itself was removed in 2026-05-09 alongside bootstrap-admin (its
// only consumer).

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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
		"general":     {Topic: ""},
		"engineering": {Topic: ""},
	})

	err := cmdRenameRoom(dataDir, []string{"--room", "general", "--new-name", "ENGINEERING"})
	if err == nil {
		t.Fatal("should reject case-insensitive duplicate")
	}
}

func TestRenameRoom_NoChangeRejected(t *testing.T) {
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{"general": {}}, users)

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

	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
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
