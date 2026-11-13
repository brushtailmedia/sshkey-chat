package main

// A rotation answered over the wire by a user who is not in the room.

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/testutil"
)

// rotateWait bounds every read in this file. The server answers in
// milliseconds; a frame that never comes must fail here, not at the package
// timeout.
const rotateWait = 10 * time.Second

// readUntilType reads frames until one of the given types arrives and
// returns its type and bytes, failing the test after rotateWait. Unlike
// readMessage it does not skip rotation frames. The reader stops before this
// returns, so it can be called again on the same client.
func (tc *testClient) readUntilType(types ...string) (string, json.RawMessage) {
	tc.t.Helper()
	type result struct {
		typ string
		raw json.RawMessage
		err error
	}
	out := make(chan result, 1)
	go func() {
		for {
			var raw json.RawMessage
			if err := tc.dec.Decode(&raw); err != nil {
				out <- result{err: err}
				return
			}
			typ, err := protocol.TypeOf(raw)
			if err != nil {
				out <- result{err: err}
				return
			}
			for _, want := range types {
				if typ == want {
					out <- result{typ: typ, raw: raw}
					return
				}
			}
		}
	}()
	select {
	case r := <-out:
		if r.err != nil {
			tc.t.Fatalf("read until %v: %v", types, r.err)
		}
		return r.typ, r.raw
	case <-time.After(rotateWait):
		tc.t.Fatalf("no %v frame within %s", types, rotateWait)
		return "", nil
	}
}

func TestEpochRotate_NonMemberCannotAnswerAPendingRotation(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test — run without -short")
	}
	env := newTestEnv(t)
	engineering := env.roomID("engineering") // alice is its only member

	bob := env.connect(fixtureKeyPath(t, "bob"), "dev_bob_rotate_outsider")
	alice := env.connect(fixtureKeyPath(t, "alice"), "dev_alice_rotate_member")

	// The server asks alice to rotate the fresh room once she is connected.
	var trigger protocol.EpochTrigger
	for trigger.Room != engineering {
		_, raw := alice.readUntilType("epoch_trigger")
		if err := json.Unmarshal(raw, &trigger); err != nil {
			t.Fatal(err)
		}
	}
	wk := make(map[string]string, len(trigger.Members))
	for _, m := range trigger.Members {
		wk[m.User] = testutil.WrappedKey(m.User)
	}
	answer := protocol.EpochRotate{
		Type: "epoch_rotate", Room: engineering, Epoch: trigger.NewEpoch, WrappedKeys: wk,
		MemberHash: "SHA256:deadbeef", MemberSig: "c2lnbmF0dXJl",
	}

	// Bob is not in the room. He answers first, with keys for exactly its members.
	if err := bob.enc.Encode(answer); err != nil {
		t.Fatal(err)
	}
	typ, raw := bob.readUntilType("error", "epoch_confirmed")
	var refusal protocol.Error
	_ = json.Unmarshal(raw, &refusal)
	if typ != "error" || refusal.Code != protocol.ErrEpochConflict {
		t.Errorf("non-member's answer got %s, want error %s", raw, protocol.ErrEpochConflict)
	}

	// Control: the rotation is still pending and the member's answer is taken.
	if err := alice.enc.Encode(answer); err != nil {
		t.Fatal(err)
	}
	typ, raw = alice.readUntilType("error", "epoch_confirmed")
	var confirmed protocol.EpochConfirmed
	_ = json.Unmarshal(raw, &confirmed)
	if typ != "epoch_confirmed" || confirmed.Room != engineering || confirmed.Epoch != trigger.NewEpoch {
		t.Errorf("member's answer got %s, want epoch_confirmed for epoch %d", raw, trigger.NewEpoch)
	}
}
