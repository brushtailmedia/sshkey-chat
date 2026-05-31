package server

import (
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// TestHandleEpochRotate_AttestationStoredAndForwarded covers F7 Phase A
// (server store-and-forward): on a valid epoch_rotate the server persists the
// rotator's member attestation (generator/member_hash/member_sig) atomically
// with the key batch, and forwards it unchanged on the epoch_key distributed
// to every other online member. The server treats the sig as opaque (no crypto)
// — verification is entirely client-side (Phase B).
func TestHandleEpochRotate_AttestationStoredAndForwarded(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	alice := testClientFor("alice", "dev_alice_f7") // the rotator
	bob := testClientFor("bob", "dev_bob_f7")       // another online member
	for _, u := range []string{"alice", "bob"} {
		if err := s.store.AddRoomMember(generalID, u, 0); err != nil {
			t.Fatalf("AddRoomMember(%s): %v", u, err)
		}
	}
	// bob must be registered to receive the distributed epoch_key.
	s.mu.Lock()
	s.clients["dev_alice_f7"] = alice.Client
	s.clients["dev_bob_f7"] = bob.Client
	s.mu.Unlock()

	s.epochs.getOrCreate(generalID, 0)
	pendingEpoch := s.epochs.startRotation(generalID, func() {})
	if pendingEpoch == 0 {
		t.Fatal("startRotation returned 0")
	}

	// wrapped_keys must exactly cover current members (S8).
	wk := map[string]string{}
	for _, m := range s.store.GetRoomMemberIDsByRoomID(generalID) {
		wk[m] = "wk_" + m
	}
	const memberHash = "SHA256:deadbeef"
	const memberSig = "c2lnbmF0dXJl" // base64("signature") — opaque to the server
	raw, _ := json.Marshal(protocol.EpochRotate{
		Type:        "epoch_rotate",
		Room:        generalID,
		Epoch:       pendingEpoch,
		WrappedKeys: wk,
		MemberHash:  memberHash,
		MemberSig:   memberSig,
	})
	s.handleEpochRotate(alice.Client, raw)

	// (1) attestation persisted (atomically with the keys).
	gen, mh, ms, err := s.store.GetEpochAttestation(generalID, pendingEpoch)
	if err != nil {
		t.Fatalf("GetEpochAttestation: %v", err)
	}
	if gen != "alice" || mh != memberHash || ms != memberSig {
		t.Errorf("stored attestation = (%q,%q,%q), want (alice,%q,%q)", gen, mh, ms, memberHash, memberSig)
	}

	// (2) bob's distributed epoch_key carries the attestation verbatim.
	sawKey := false
	for _, m := range bob.messages() {
		var ek protocol.EpochKey
		if json.Unmarshal(m, &ek) == nil && ek.Type == "epoch_key" {
			sawKey = true
			if ek.Generator != "alice" || ek.MemberHash != memberHash || ek.MemberSig != memberSig {
				t.Errorf("forwarded epoch_key attestation = (%q,%q,%q), want (alice,%q,%q)",
					ek.Generator, ek.MemberHash, ek.MemberSig, memberHash, memberSig)
			}
		}
	}
	if !sawKey {
		t.Errorf("bob should have received an epoch_key; got %v", bob.messages())
	}
}
