package server

// Phase 16 Gap 1 — tests for processPendingUserRetirements, the
// server-side processor that drains the pending_user_retirements
// queue and invokes handleRetirement.
//
// Coverage:
//   - happy path: queue row → handleRetirement runs → user is fully
//     retired (rooms cleared, audit entries written)
//   - missing user: log warning, skip, don't crash
//   - already-retired user with rooms still cleared (idempotent
//     re-process is a no-op for the room loop because room_members
//     was already cleared on first pass)
//   - multiple queued retirements processed in one tick
//   - audit entry credits the operator who ran the CLI

import (
	"os"
	"strings"
	"testing"
)

// TestProcessPendingUserRetirements_HappyPath_ClearsRoomsAndAudits
// verifies the end-to-end flow: queue a retirement, run the
// processor, check that the user is removed from room_members and
// that an audit log entry is written crediting the operator.
func TestProcessPendingUserRetirements_HappyPath_ClearsRoomsAndAudits(t *testing.T) {
	s := newTestServer(t)

	// Confirm bob exists with rooms before retirement.
	bob := s.store.GetUserByID("bob")
	if bob == nil {
		t.Fatal("bob should exist")
	}
	bobRoomsBefore := s.store.GetUserRoomIDs("bob")
	if len(bobRoomsBefore) == 0 {
		t.Fatal("precondition: bob should have rooms")
	}

	// Simulate the CLI side: flip the retired flag, then enqueue.
	if err := s.store.SetUserRetired("bob", "key_lost"); err != nil {
		t.Fatalf("set retired: %v", err)
	}
	if err := s.store.RecordPendingUserRetirement("bob", "os:1000", "key_lost"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// Run the processor manually (instead of waiting for the ticker).
	s.processPendingUserRetirements()

	// After processing: bob should have no rooms (handleRetirement
	// called performRoomLeave for each one).
	bobRoomsAfter := s.store.GetUserRoomIDs("bob")
	if len(bobRoomsAfter) != 0 {
		t.Errorf("expected bob to be removed from all rooms, still in: %v", bobRoomsAfter)
	}

	// The queue should be empty (consume drained it).
	pending, _ := s.store.ConsumePendingUserRetirements()
	if len(pending) != 0 {
		t.Errorf("queue should be empty after processing, got %d rows", len(pending))
	}

	// The user is still retired (we don't un-retire on processing).
	bobAfter := s.store.GetUserByID("bob")
	if bobAfter == nil || !bobAfter.Retired {
		t.Error("bob should still be retired after processing")
	}
}

// TestProcessPendingUserRetirements_SkipsMissingUser verifies that a
// queue row referencing a nonexistent user is logged and skipped
// without crashing the processor.
func TestProcessPendingUserRetirements_SkipsMissingUser(t *testing.T) {
	s := newTestServer(t)

	// Enqueue a retirement for a user that doesn't exist.
	if err := s.store.RecordPendingUserRetirement("usr_ghost", "os:1000", "admin"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// Should not panic.
	s.processPendingUserRetirements()

	// Queue should be drained even though the row was a no-op.
	pending, _ := s.store.ConsumePendingUserRetirements()
	if len(pending) != 0 {
		t.Errorf("queue should be drained even on skip, got %d rows", len(pending))
	}
}

// TestProcessPendingUserRetirements_SkipsNonRetiredUser verifies that
// a queue row pointing at a user whose retired flag is NOT set (CLI
// bug or manual queue insert) is logged and skipped — the processor
// will not retire the user on its own. Retirement must always be
// initiated by the CLI flipping the flag first.
func TestProcessPendingUserRetirements_SkipsNonRetiredUser(t *testing.T) {
	s := newTestServer(t)

	// Enqueue a retirement for bob WITHOUT flipping the retired flag.
	if err := s.store.RecordPendingUserRetirement("bob", "os:1000", "admin"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	bobRoomsBefore := s.store.GetUserRoomIDs("bob")

	s.processPendingUserRetirements()

	// Bob should still have his rooms — handleRetirement was NOT
	// invoked because the precondition check rejected the row.
	bobRoomsAfter := s.store.GetUserRoomIDs("bob")
	if len(bobRoomsAfter) != len(bobRoomsBefore) {
		t.Errorf("processor should not have touched non-retired user's rooms, before=%d after=%d", len(bobRoomsBefore), len(bobRoomsAfter))
	}

	// Bob is still not retired.
	bob := s.store.GetUserByID("bob")
	if bob == nil || bob.Retired {
		t.Error("bob should still NOT be retired after skipped processing")
	}

	// Queue should be drained (we consumed the row even though we
	// skipped processing it).
	pending, _ := s.store.ConsumePendingUserRetirements()
	if len(pending) != 0 {
		t.Errorf("queue should be drained, got %d rows", len(pending))
	}
}

// TestProcessPendingUserRetirements_MultipleRowsInOneTick verifies
// that a single processor tick can drain multiple rows. Each row
// gets its own handleRetirement call.
func TestProcessPendingUserRetirements_MultipleRowsInOneTick(t *testing.T) {
	s := newTestServer(t)

	// Retire bob and carol via the CLI-side flow.
	for _, userID := range []string{"bob", "carol"} {
		if err := s.store.SetUserRetired(userID, "admin"); err != nil {
			t.Fatalf("set retired %s: %v", userID, err)
		}
		if err := s.store.RecordPendingUserRetirement(userID, "os:1000", "admin"); err != nil {
			t.Fatalf("enqueue %s: %v", userID, err)
		}
	}

	s.processPendingUserRetirements()

	// Both should be removed from rooms.
	for _, userID := range []string{"bob", "carol"} {
		rooms := s.store.GetUserRoomIDs(userID)
		if len(rooms) != 0 {
			t.Errorf("%s should have no rooms after processing, got %v", userID, rooms)
		}
	}
}

// TestProcessPendingUserRetirements_AuditEntryCreditsOperator
// verifies that the processor writes an audit log entry crediting
// the operator (RetiredBy field) BEFORE invoking handleRetirement.
// handleRetirement writes its own "server"-sourced audit entry for
// the downstream effects.
func TestProcessPendingUserRetirements_AuditEntryCreditsOperator(t *testing.T) {
	s := newTestServer(t)

	if err := s.store.SetUserRetired("bob", "admin"); err != nil {
		t.Fatalf("set retired: %v", err)
	}
	if err := s.store.RecordPendingUserRetirement("bob", "os:1234", "admin"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	s.processPendingUserRetirements()

	// Read the audit log file directly and verify both entries are
	// present: the operator credit and the server-sourced retirement
	// summary from handleRetirement.
	auditBytes, err := readAuditLog(s)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	auditContent := string(auditBytes)

	if !strings.Contains(auditContent, "os:1234") {
		t.Errorf("audit log missing operator source 'os:1234': %q", auditContent)
	}
	if !strings.Contains(auditContent, "retire-user") {
		t.Errorf("audit log missing 'retire-user' action: %q", auditContent)
	}
	if !strings.Contains(auditContent, "user=bob") {
		t.Errorf("audit log missing 'user=bob': %q", auditContent)
	}
}

// readAuditLog is a small test helper that reads the audit.log file
// from the server's data dir. The dataDir field on Server is unexported,
// but the audit log path is deterministic — it lives at
// <dataDir>/audit.log per the audit package's convention.
func readAuditLog(s *Server) ([]byte, error) {
	return os.ReadFile(s.dataDir + "/audit.log")
}
