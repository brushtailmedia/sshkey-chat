package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/actionauth"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// TestDelete_SignedEndToEnd is the cross-repo delete-authentication contract over
// a real SSH session (the server half of client crypto audit F6, delete leg):
// a client signs (kind, contextID, msgID) with its identity key, the server
// verifies that signature BEFORE the destructive write, persists + relays it, and
// every connected room member receives a `deleted` broadcast carrying the relayed
// signature (which clients re-verify). A well-formed-but-cryptographically-invalid
// delete is rejected, never broadcast. Mirrors the react→unreact end-to-end
// coverage in auto_revoke_integration_test.go, and complements the in-package
// handler tests in internal/server/delete_test.go with a full transport round-trip.
func TestDelete_SignedEndToEnd(t *testing.T) {
	env := newTestEnv(t)
	alice := env.connect(fixtureKeyPath(t, "alice"), "dev_delete_alice")
	bob := env.connect(fixtureKeyPath(t, "bob"), "dev_delete_bob")
	roomID := env.roomIDByName("general")

	// Post a room message as alice; the server assigns its id and both members see it.
	mustSendRoom := func(payload string) protocol.Message {
		t.Helper()
		if err := alice.enc.Encode(protocol.Send{
			Type:      "send",
			Room:      roomID,
			Epoch:     1,
			Payload:   payload,
			Signature: "msg-sig", // message authenticity is a client-side concern (F1); the server stores the blob
		}); err != nil {
			t.Fatalf("room send: %v", err)
		}
		mt, raw := alice.readMessage()
		if mt != "message" {
			t.Fatalf("alice expected message echo, got %s: %s", mt, raw)
		}
		var m protocol.Message
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("unmarshal message: %v", err)
		}
		if mt, _ := bob.readMessage(); mt != "message" {
			t.Fatalf("bob expected room message, got %s", mt)
		}
		return m
	}

	// alice's identity key signs the canonical delete form — the same key the
	// server resolves from alice's stored authorized_key to verify against.
	signDelete := func(msgID string) string {
		return base64.StdEncoding.EncodeToString(
			ed25519.Sign(alice.priv, actionauth.BuildDeleteCanonical("room", roomID, msgID)),
		)
	}

	// --- Happy path: a valid signed delete is verified, persisted, and broadcast. ---
	msg := mustSendRoom("delete-me")
	wantSig := signDelete(msg.ID)
	if err := alice.enc.Encode(protocol.Delete{
		Type:      "delete",
		ID:        msg.ID,
		Room:      roomID,
		Signature: wantSig,
	}); err != nil {
		t.Fatalf("delete encode: %v", err)
	}
	for _, tc := range []struct {
		name string
		c    *testClient
	}{{"alice", alice}, {"bob", bob}} {
		mt, raw := tc.c.readMessage()
		if mt != "deleted" {
			t.Fatalf("%s expected deleted broadcast, got %s: %s", tc.name, mt, raw)
		}
		var d protocol.Deleted
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatalf("%s unmarshal deleted: %v", tc.name, err)
		}
		if d.ID != msg.ID || d.Room != roomID {
			t.Errorf("%s deleted id/room mismatch: got id=%s room=%s want id=%s room=%s",
				tc.name, d.ID, d.Room, msg.ID, roomID)
		}
		if d.DeletedBy == "" {
			t.Errorf("%s deleted must name the deleter", tc.name)
		}
		if d.Signature != wantSig {
			t.Errorf("%s deleted must carry the forwarded delete signature\n got  %s\n want %s",
				tc.name, d.Signature, wantSig)
		}
	}

	// --- Negative: a valid-length but cryptographically-wrong signature is rejected. ---
	// An all-zero 64-byte signature decodes cleanly (passes the dispatcher's length
	// check) but fails ed25519 verification — exercising the verify gate itself, not
	// merely the decode. The server must reject (an `error` frame to alice) and must
	// NOT broadcast a `deleted` to anyone.
	msg2 := mustSendRoom("do-not-delete")
	badSig := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if err := alice.enc.Encode(protocol.Delete{
		Type:      "delete",
		ID:        msg2.ID,
		Room:      roomID,
		Signature: badSig,
	}); err != nil {
		t.Fatalf("bad delete encode: %v", err)
	}
	if mt, raw := alice.readMessage(); mt == "deleted" {
		t.Errorf("a cryptographically-invalid delete must be rejected, not broadcast: %s", raw)
	}
}
