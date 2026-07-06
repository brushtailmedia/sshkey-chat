package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// readTypeWithTimeout decodes frames on tc until one of type `want` arrives,
// failing the test after `d`. Unlike drainUntil it cannot hang the suite —
// the regression this file guards (a live session dropped from the server's
// routing map) manifests as NOTHING ever arriving, which must fail loudly.
// Non-matching frames (presence, epoch, device events) are drained and skipped.
func readTypeWithTimeout(t *testing.T, tc *testClient, want string, d time.Duration) json.RawMessage {
	t.Helper()
	type frame struct {
		typ string
		raw json.RawMessage
		err error
	}
	frames := make(chan frame, 16)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			var raw json.RawMessage
			if err := tc.dec.Decode(&raw); err != nil {
				select {
				case frames <- frame{err: err}:
				case <-done:
				}
				return
			}
			typ, err := protocol.TypeOf(raw)
			if err != nil {
				select {
				case frames <- frame{err: err}:
				case <-done:
				}
				return
			}
			select {
			case frames <- frame{typ: typ, raw: raw}:
			case <-done:
				return
			}
		}
	}()
	deadline := time.After(d)
	for {
		select {
		case f := <-frames:
			if f.err != nil {
				t.Fatalf("read while waiting for %q: %v", want, f.err)
			}
			if f.typ == want {
				return f.raw
			}
			// skip unrelated async frames
		case <-deadline:
			t.Fatalf("timed out after %v waiting for %q — the live session is likely "+
				"missing from the server routing map (s.clients teardown-race regression)", d, want)
		}
	}
}

// TestDuplicateDeviceReconnectRace_KeepsLiveSessionRouted is the end-to-end
// regression for the unguarded s.clients teardown delete
// (docs/planning/open/device-identity-transparency.md §4.5). The reconnect
// race: a client reconnects with the SAME device_id (~1s retry) while the
// server hasn't yet noticed the old connection died (keepalive can take far
// longer). The new session's registration overwrites the routing entry; when
// the old session's teardown finally runs, it must NOT delete the live
// session's route. Before the guard, it did — leaving the reconnected session
// connected but receiving no broadcasts or DMs until its next reconnect.
func TestDuplicateDeviceReconnectRace_KeepsLiveSessionRouted(t *testing.T) {
	env := newTestEnv(t)

	// Session 1: alice connects.
	alice1 := env.connect(fixtureKeyPath(t, "alice"), "dev_race_alice")

	// Session 2: alice "reconnects" with the SAME device_id while session 1 is
	// still open — the reconnect race. Registration replaces the routing entry.
	alice2 := env.connect(fixtureKeyPath(t, "alice"), "dev_race_alice")

	// Session 1's connection dies; its server-side teardown runs. With the
	// guard it must leave session 2's route intact.
	alice1.conn.Close()
	time.Sleep(750 * time.Millisecond) // let the server process session 1's teardown

	// Another user posts to a shared room. Session 2 MUST receive the
	// broadcast — this is exactly what the unguarded delete broke.
	bob := env.connect(fixtureKeyPath(t, "bob"), "dev_race_bob")
	roomID := env.roomIDByName("general")
	if err := bob.enc.Encode(protocol.Send{
		Type:      "send",
		Room:      roomID,
		Epoch:     1,
		Payload:   "still-routed-payload",
		Signature: "still-routed-sig",
	}); err != nil {
		t.Fatalf("bob send: %v", err)
	}

	raw := readTypeWithTimeout(t, alice2, "message", 5*time.Second)
	var m protocol.Message
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal message: %v", err)
	}
	if m.Payload != "still-routed-payload" {
		t.Errorf("payload = %q, want the just-sent message (still-routed-payload)", m.Payload)
	}
	if m.Room != roomID {
		t.Errorf("room = %q, want %q", m.Room, roomID)
	}
}
