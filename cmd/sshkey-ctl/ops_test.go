package main

// Phase 16 — tests for operational + maintenance commands.
//
// Coverage:
//   - list-devices: happy path (with revoked device shown), empty,
//     missing user, missing args
//   - room-stats: happy path with rooms, empty
//   - check-integrity: passes on fresh DBs, reports missing DB
//     correctly

import (
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// --- list-devices tests ---

func TestListDevices_HappyPath(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice"},
	}
	dataDir := setupDataDir(t, nil, users)

	st0, _ := store.Open(dataDir)
	st0.UpsertDevice("usr_alice", "dev_laptop")
	st0.UpsertDevice("usr_alice", "dev_phone")
	st0.RevokeDevice("usr_alice", "dev_phone", "stolen")
	st0.Close()

	out := captureStdout(t, func() {
		if err := cmdListDevices(dataDir, []string{"--user", "usr_alice"}); err != nil {
			t.Fatalf("list-devices: %v", err)
		}
	})
	if !strings.Contains(out, "dev_laptop") {
		t.Errorf("should list laptop, got: %q", out)
	}
	if !strings.Contains(out, "dev_phone") {
		t.Errorf("should list phone, got: %q", out)
	}
	if !strings.Contains(out, "[REVOKED]") {
		t.Errorf("phone should be marked revoked, got: %q", out)
	}
	if !strings.Contains(out, "2 total") {
		t.Errorf("should show total count, got: %q", out)
	}
}

func TestListDevices_NoDevices(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice"},
	}
	dataDir := setupDataDir(t, nil, users)

	out := captureStdout(t, func() {
		cmdListDevices(dataDir, []string{"--user", "usr_alice"})
	})
	if !strings.Contains(out, "no registered devices") {
		t.Errorf("should say no devices, got: %q", out)
	}
}

func TestListDevices_MissingUser(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	err := cmdListDevices(dataDir, []string{"--user", "usr_ghost"})
	if err == nil {
		t.Fatal("should error for missing user")
	}
}

func TestListDevices_MissingArgs(t *testing.T) {
	err := cmdListDevices(t.TempDir(), nil)
	if err == nil {
		t.Fatal("should error without --user")
	}
}

// --- room-stats tests ---

func TestRoomStats_HappyPath(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice", Rooms: []string{"general"}},
	}
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
		"general": {Topic: "Chat"},
	}, users)

	out := captureStdout(t, func() {
		if err := cmdRoomStats(dataDir); err != nil {
			t.Fatalf("room-stats: %v", err)
		}
	})
	if !strings.Contains(out, "general") {
		t.Errorf("should list general, got: %q", out)
	}
	if !strings.Contains(out, "ROOM") {
		t.Errorf("should have header, got: %q", out)
	}
}

func TestRoomStats_Empty(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	out := captureStdout(t, func() {
		cmdRoomStats(dataDir)
	})
	if !strings.Contains(out, "No rooms") {
		t.Errorf("should say no rooms, got: %q", out)
	}
}

// --- prune-devices tests ---

func TestPruneDevices_DryRun(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice"},
	}
	dataDir := setupDataDir(t, nil, users)

	// Register a device with an old created_at (2020).
	st0, _ := store.Open(dataDir)
	st0.UpsertDevice("usr_alice", "dev_old")
	// Force the created_at to an old timestamp.
	st0.DataDB().Exec(`UPDATE devices SET created_at = '2020-01-01T00:00:00Z' WHERE device_id = 'dev_old'`)
	st0.Close()

	out := captureStdout(t, func() {
		if err := cmdPruneDevices(dataDir, []string{"--dry-run"}); err != nil {
			t.Fatalf("prune: %v", err)
		}
	})
	if !strings.Contains(out, "dry-run") || !strings.Contains(out, "would") {
		t.Errorf("should show dry-run output, got: %q", out)
	}
	if !strings.Contains(out, "dev_old") {
		t.Errorf("should list dev_old, got: %q", out)
	}

	// Verify the device was NOT actually revoked.
	st1, _ := store.Open(dataDir)
	defer st1.Close()
	revoked, _ := st1.IsDeviceRevoked("usr_alice", "dev_old")
	if revoked {
		t.Error("dry-run should not revoke the device")
	}
}

func TestPruneDevices_HappyPath(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice"},
	}
	dataDir := setupDataDir(t, nil, users)

	st0, _ := store.Open(dataDir)
	st0.UpsertDevice("usr_alice", "dev_old")
	st0.UpsertDevice("usr_alice", "dev_new")
	// Force dev_old to be stale, keep dev_new fresh.
	st0.DataDB().Exec(`UPDATE devices SET created_at = '2020-01-01T00:00:00Z' WHERE device_id = 'dev_old'`)
	st0.Close()

	if err := cmdPruneDevices(dataDir, []string{"--stale-for", "90d"}); err != nil {
		t.Fatalf("prune: %v", err)
	}

	st1, _ := store.Open(dataDir)
	defer st1.Close()

	// dev_old should be revoked.
	revoked, _ := st1.IsDeviceRevoked("usr_alice", "dev_old")
	if !revoked {
		t.Error("dev_old should be revoked after prune")
	}

	// dev_new should NOT be revoked (it's fresh).
	revokedNew, _ := st1.IsDeviceRevoked("usr_alice", "dev_new")
	if revokedNew {
		t.Error("dev_new should NOT be revoked (it's recent)")
	}

	// Queue should have a row for the server processor to kick
	// any active session.
	pending, _ := st1.ConsumePendingDeviceRevocations()
	if len(pending) != 1 {
		t.Errorf("expected 1 queue row, got %d", len(pending))
	}
}

func TestPruneDevices_SkipsAlreadyRevoked(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice"},
	}
	dataDir := setupDataDir(t, nil, users)

	st0, _ := store.Open(dataDir)
	st0.UpsertDevice("usr_alice", "dev_old")
	st0.DataDB().Exec(`UPDATE devices SET created_at = '2020-01-01T00:00:00Z' WHERE device_id = 'dev_old'`)
	st0.RevokeDevice("usr_alice", "dev_old", "manual") // already revoked
	st0.Close()

	out := captureStdout(t, func() {
		cmdPruneDevices(dataDir, nil)
	})
	if !strings.Contains(out, "already revoked") {
		t.Errorf("should report already-revoked count, got: %q", out)
	}
	if strings.Contains(out, "pruned:") {
		t.Errorf("should not prune already-revoked device, got: %q", out)
	}
}

func TestPruneDevices_NoDevices(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	out := captureStdout(t, func() {
		cmdPruneDevices(dataDir, nil)
	})
	if !strings.Contains(out, "No devices") {
		t.Errorf("should say no devices, got: %q", out)
	}
}

// --- check-integrity tests ---

func TestCheckIntegrity_FreshDBsPasses(t *testing.T) {
	aliceKey, _ := genTestKey(t, "Alice")
	users := map[string]testUser{
		"usr_alice": {Key: aliceKey, DisplayName: "Alice"},
	}
	dataDir := setupDataDir(t, map[string]store.RoomSeed{
		"general": {},
	}, users)

	out := captureStdout(t, func() {
		if err := cmdCheckIntegrity(dataDir, nil); err != nil {
			t.Fatalf("check-integrity: %v", err)
		}
	})
	if !strings.Contains(out, "passed") {
		t.Errorf("should report passed, got: %q", out)
	}
	// Should check all three main DBs.
	for _, db := range []string{"users.db", "rooms.db", "data.db"} {
		if !strings.Contains(out, db) {
			t.Errorf("should check %s, got: %q", db, out)
		}
	}
}

func TestCheckIntegrity_SpecificDB(t *testing.T) {
	dataDir := setupDataDir(t, nil)

	out := captureStdout(t, func() {
		if err := cmdCheckIntegrity(dataDir, []string{"--db", "users.db"}); err != nil {
			t.Fatalf("check-integrity: %v", err)
		}
	})
	if !strings.Contains(out, "users.db") {
		t.Errorf("should check users.db, got: %q", out)
	}
	// Should NOT check rooms.db when --db is specified.
	if strings.Contains(out, "rooms.db") {
		t.Errorf("should only check users.db, got: %q", out)
	}
}

func TestCheckIntegrity_NoDB(t *testing.T) {
	// Empty temp dir with no data/. Should report "no databases."
	out := captureStdout(t, func() {
		cmdCheckIntegrity(t.TempDir(), nil)
	})
	if !strings.Contains(out, "No databases") {
		t.Errorf("should say no databases, got: %q", out)
	}
}
