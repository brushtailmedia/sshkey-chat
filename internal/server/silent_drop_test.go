package server

// Phase 17c Step 3 — silent-drop regression tests.
//
// Pre-Step-3, 14 handlers silently dropped malformed frames via bare
// `return` with no log, no counter, no client response. The plan's
// classification-walk activity identified these and the step fixes
// them by routing each through rejectAndLog with SignalMalformedFrame.
// These tests lock in that fix — a regression that restores the bare
// return would be caught by the counter assertion.
//
// Handlers covered (14):
//   session.go: handleTyping, handleRead, handleUnreact, handlePin,
//               handleUnpin, handleDelete, handleLeaveGroup,
//               handleDeleteGroup, handleLeaveRoom, handleDeleteRoom,
//               handleRenameGroup, handleLeaveDM, handleSetProfile,
//               handleSetStatus

import (
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
)

func TestHandleTyping_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_typing_malformed")
	s.handleTyping(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_typing_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handleTyping = %d, want 1", got)
	}
}

func TestHandleRead_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_read_malformed")
	s.handleRead(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_read_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handleRead = %d, want 1", got)
	}
}

func TestHandleUnreact_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_unreact_malformed")
	s.handleUnreact(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_unreact_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handleUnreact = %d, want 1", got)
	}
}

func TestHandlePin_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_pin_malformed")
	s.handlePin(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_pin_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handlePin = %d, want 1", got)
	}
}

func TestHandleUnpin_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_unpin_malformed")
	s.handleUnpin(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_unpin_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handleUnpin = %d, want 1", got)
	}
}

func TestHandleDelete_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_delete_malformed")
	s.handleDelete(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_delete_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handleDelete = %d, want 1", got)
	}
}

func TestHandleLeaveGroup_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_leavegroup_malformed")
	s.handleLeaveGroup(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_leavegroup_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handleLeaveGroup = %d, want 1", got)
	}
}

func TestHandleDeleteGroup_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_deletegroup_malformed")
	s.handleDeleteGroup(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_deletegroup_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handleDeleteGroup = %d, want 1", got)
	}
}

func TestHandleLeaveRoom_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_leaveroom_malformed")
	s.handleLeaveRoom(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_leaveroom_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handleLeaveRoom = %d, want 1", got)
	}
}

func TestHandleDeleteRoom_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_deleteroom_malformed")
	s.handleDeleteRoom(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_deleteroom_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handleDeleteRoom = %d, want 1", got)
	}
}

func TestHandleRenameGroup_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_rename_malformed")
	s.handleRenameGroup(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_rename_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handleRenameGroup = %d, want 1", got)
	}
}

func TestHandleLeaveDM_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_leavedm_malformed")
	s.handleLeaveDM(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_leavedm_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handleLeaveDM = %d, want 1", got)
	}
}

func TestHandleSetProfile_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_setprofile_malformed")
	s.handleSetProfile(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_setprofile_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handleSetProfile = %d, want 1", got)
	}
}

func TestHandleSetStatus_MalformedFrameFiresSignal(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_setstatus_malformed")
	s.handleSetStatus(alice.Client, malformedRaw())
	if got := s.counters.Get(counters.SignalMalformedFrame, "dev_alice_setstatus_malformed"); got != 1 {
		t.Errorf("SignalMalformedFrame on handleSetStatus = %d, want 1", got)
	}
}
