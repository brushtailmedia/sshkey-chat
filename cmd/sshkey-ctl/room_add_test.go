package main

// V3: the shared addRoomMemberAndQueueSideEffects helper — inserted-vs-existing
// gating, the server-authoritative retired-room/retired-user gates, and the
// unique-index defensive (AlreadyQueued) branch.

import (
	"sync"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

func openHelperStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(t.TempDir())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.SeedRooms(map[string]store.RoomSeed{"general": {Topic: "Chat"}}); err != nil {
		t.Fatalf("seed rooms: %v", err)
	}
	if err := st.InsertUser("usr_alice", "ssh-ed25519 AAAAalice", "Alice"); err != nil {
		t.Fatalf("insert alice: %v", err)
	}
	return st
}

func helperRoom(t *testing.T, st *store.Store, name string) store.RoomRecord {
	t.Helper()
	r, err := st.GetRoomByID(st.RoomDisplayNameToID(name))
	if err != nil || r == nil {
		t.Fatalf("get room %q: %v", name, err)
	}
	return *r
}

// A genuinely new membership → Inserted + Queued, one queue row.
func TestAddRoomMemberAndQueueSideEffects_NewMembership(t *testing.T) {
	st := openHelperStore(t)
	room := helperRoom(t, st, "general")

	result, err := addRoomMemberAndQueueSideEffects(st, "usr_alice", room, "os:1000")
	if err != nil {
		t.Fatalf("helper: %v", err)
	}
	if !result.Inserted || !result.Queued || result.AlreadyQueued {
		t.Fatalf("want {Inserted:true, Queued:true}, got %+v", result)
	}
	if !st.IsRoomMemberByID(room.ID, "usr_alice") {
		t.Error("alice should be a member")
	}
	pending, err := st.ConsumePendingAddToRooms()
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("want exactly 1 queue row, got %d", len(pending))
	}
}

// Existing membership → Inserted:false, no enqueue (no fake side effects).
func TestAddRoomMemberAndQueueSideEffects_ExistingMembershipIsNoOp(t *testing.T) {
	st := openHelperStore(t)
	room := helperRoom(t, st, "general")

	// First add inserts + queues; drain so the second call is clean.
	if _, err := addRoomMemberAndQueueSideEffects(st, "usr_alice", room, "os:1000"); err != nil {
		t.Fatalf("first add: %v", err)
	}
	if _, err := st.ConsumePendingAddToRooms(); err != nil {
		t.Fatalf("drain: %v", err)
	}

	result, err := addRoomMemberAndQueueSideEffects(st, "usr_alice", room, "os:1000")
	if err != nil {
		t.Fatalf("second add: %v", err)
	}
	if result.Inserted || result.Queued || result.AlreadyQueued {
		t.Fatalf("existing membership should be a pure no-op, got %+v", result)
	}
	pending, _ := st.ConsumePendingAddToRooms()
	if len(pending) != 0 {
		t.Fatalf("existing membership must not enqueue, got %d rows", len(pending))
	}
}

// Concurrent duplicate adds for the same (user, room) must produce one
// membership insert and one queue row. This locks the V3 race boundary at the
// INSERT itself (RowsAffected), not at a stale pre-check.
func TestAddRoomMemberAndQueueSideEffects_ConcurrentDuplicateAddsQueueOnce(t *testing.T) {
	st := openHelperStore(t)
	room := helperRoom(t, st, "general")

	const callers = 2
	results := make(chan roomAddQueueResult, callers)
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := addRoomMemberAndQueueSideEffects(st, "usr_alice", room, "os:1000")
			results <- result
			errs <- err
		}()
	}
	wg.Wait()
	close(results)
	close(errs)

	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent helper returned error: %v", err)
		}
	}
	inserted := 0
	queued := 0
	for result := range results {
		if result.Inserted {
			inserted++
		}
		if result.Queued {
			queued++
		}
	}
	if inserted != 1 {
		t.Fatalf("concurrent duplicate adds inserted %d memberships, want 1", inserted)
	}
	if queued != 1 {
		t.Fatalf("concurrent duplicate adds queued %d rows, want 1", queued)
	}

	pending, err := st.ConsumePendingAddToRooms()
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("want exactly 1 pending row after concurrent duplicate adds, got %d", len(pending))
	}
}

// Retired room → error, no membership, no enqueue.
func TestAddRoomMemberAndQueueSideEffects_RejectsRetiredRoom(t *testing.T) {
	st := openHelperStore(t)
	roomID := st.RoomDisplayNameToID("general")
	if err := st.SetRoomRetired(roomID, "os:1000", ""); err != nil {
		t.Fatalf("retire room: %v", err)
	}
	// Re-read by the stable ID (retirement suffixes the display name, so a
	// by-name lookup would now miss) so room.Retired is set.
	rr, err := st.GetRoomByID(roomID)
	if err != nil || rr == nil {
		t.Fatalf("get room by id: %v", err)
	}
	room := *rr

	result, err := addRoomMemberAndQueueSideEffects(st, "usr_alice", room, "os:1000")
	if err == nil {
		t.Fatal("adding to a retired room should error")
	}
	if result.Inserted {
		t.Error("retired room: nothing should be inserted")
	}
	if st.IsRoomMemberByID(roomID, "usr_alice") {
		t.Error("retired room: alice must not become a member")
	}
}

// Retired user → error, no membership, no enqueue (server-authoritative gate).
func TestAddRoomMemberAndQueueSideEffects_RejectsRetiredUser(t *testing.T) {
	st := openHelperStore(t)
	room := helperRoom(t, st, "general")
	if err := st.SetUserRetired("usr_alice", "test_policy"); err != nil {
		t.Fatalf("retire user: %v", err)
	}

	result, err := addRoomMemberAndQueueSideEffects(st, "usr_alice", room, "os:1000")
	if err == nil {
		t.Fatal("adding a retired user should error")
	}
	if result.Inserted {
		t.Error("retired user: nothing should be inserted")
	}
	if st.IsRoomMemberByID(room.ID, "usr_alice") {
		t.Error("retired user: must not become a member")
	}
}

// Unique-index defensive branch: a pre-existing queue row for (user, room)
// makes the helper return {Inserted:true, AlreadyQueued:true} (membership is
// still written) and the caller must NOT treat it as a partial failure.
func TestAddRoomMemberAndQueueSideEffects_AlreadyQueuedDefensiveBranch(t *testing.T) {
	st := openHelperStore(t)
	room := helperRoom(t, st, "general")

	// Seed a queue row first, while alice is NOT yet a member, so the helper's
	// AddRoomMemberIfMissing genuinely inserts and only the queue write trips
	// the unique index.
	if err := st.RecordPendingAddToRoom("usr_alice", room.ID, "os:earlier"); err != nil {
		t.Fatalf("seed queue row: %v", err)
	}

	result, err := addRoomMemberAndQueueSideEffects(st, "usr_alice", room, "os:1000")
	if err != nil {
		t.Fatalf("helper should not return an error for the defensive branch, got %v", err)
	}
	if !result.Inserted || result.Queued || !result.AlreadyQueued {
		t.Fatalf("want {Inserted:true, AlreadyQueued:true}, got %+v", result)
	}
	if !st.IsRoomMemberByID(room.ID, "usr_alice") {
		t.Error("membership should still be durable in the defensive branch")
	}
	// The pre-existing row is the only queue row (no duplicate landed).
	pending, _ := st.ConsumePendingAddToRooms()
	if len(pending) != 1 {
		t.Fatalf("want exactly the one pre-existing queue row, got %d", len(pending))
	}
	if pending[0].InitiatedBy != "os:earlier" {
		t.Errorf("the pre-existing row's initiated_by should win, got %q", pending[0].InitiatedBy)
	}
}
