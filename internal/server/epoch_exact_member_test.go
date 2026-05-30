package server

import (
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// TestHandleEpochRotate_ExtraNonMemberWrappedKeyRejected guards the audit-S8
// fix: epoch_rotate must reject a wrapped_keys map that includes an entry for a
// user who is NOT a current room member (e.g. a member removed between the
// epoch_trigger and the rotate reply, leaving the rotating client's view
// stale). The pre-fix "covers" check alone would pass — every current member
// has a key — and the rotation would persist + distribute the extra key to the
// now-removed user. The exact-set check rejects the extra and re-triggers.
func TestHandleEpochRotate_ExtraNonMemberWrappedKeyRejected(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	alice := testClientFor("alice", "dev_alice_s8")
	if err := s.store.AddRoomMember(generalID, "alice", 0); err != nil {
		t.Fatalf("AddRoomMember: %v", err)
	}

	// Establish pending-rotation state directly (bypassing the async
	// epoch_trigger send), matching the failing-store epoch test.
	s.epochs.getOrCreate(generalID, 0)
	pendingEpoch := s.epochs.startRotation(generalID, func() {})
	if pendingEpoch == 0 {
		t.Fatal("startRotation returned 0")
	}

	// Cover every current member, then add an extra entry for a non-member.
	wk := make(map[string]string)
	for _, m := range s.store.GetRoomMemberIDsByRoomID(generalID) {
		wk[m] = "wk_" + m
	}
	wk["ghost"] = "wk_ghost" // not a current member

	raw, _ := json.Marshal(protocol.EpochRotate{
		Type:        "epoch_rotate",
		Room:        generalID,
		Epoch:       pendingEpoch,
		WrappedKeys: wk,
	})
	s.handleEpochRotate(alice.Client, raw)

	var sawStale, sawConfirmed bool
	for _, m := range alice.messages() {
		var kind struct {
			Type string `json:"type"`
			Code string `json:"code,omitempty"`
		}
		_ = json.Unmarshal(m, &kind)
		if kind.Type == "error" && kind.Code == protocol.ErrStaleMemberList {
			sawStale = true
		}
		if kind.Type == "epoch_confirmed" {
			sawConfirmed = true
		}
	}
	if !sawStale {
		t.Errorf("extra non-member wrapped key must be rejected with ErrStaleMemberList; got %v", alice.messages())
	}
	if sawConfirmed {
		t.Errorf("rotation must NOT confirm when wrapped_keys includes a non-member")
	}
}
