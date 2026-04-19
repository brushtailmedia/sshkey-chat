package protocol

// Fuzz harness for the NDJSON protocol decoder. Phase 21 F22 closure
// (2026-04-19): Phase 21 item 9b called for "a short fuzz run against
// the NDJSON protocol decoder" as a pre-launch gate. This harness
// exercises the full decode path:
//
//	NewDecoder(r) → DecodeRaw() → TypeOf(raw) → json.Unmarshal(raw, &TypedVerb)
//
// covering the 32 client-to-server verb structs. The contract under
// test is *no panic on any input*. Errors from any step are fine —
// the server's handler layer rejects malformed frames via
// `SignalMalformedFrame`; the fuzz only catches crashes, not
// rejection behaviour.
//
// Run via:
//
//	go test -fuzz=FuzzDecodeDispatch -fuzztime=5m ./internal/protocol/
//
// The seed corpus covers all 32 verbs with minimal-valid payloads and
// a handful of deliberate malformed shapes (truncated JSON, integer
// fields where strings expected, deeply nested RawMessage). New
// crashers (if any) are preserved under
// `testdata/fuzz/FuzzDecodeDispatch/` as permanent regression tests.
//
// Reference: docs/security/audit_v0.2.0.md#F22, refactor_plan.md
// Phase 21 item 9b.

import (
	"bytes"
	"encoding/json"
	"testing"
)

// clientVerbs maps each client-to-server verb name to a factory that
// returns a fresh typed struct pointer. Adding a new verb to this map
// extends the fuzz coverage for free.
var clientVerbs = map[string]func() any{
	"client_hello":        func() any { return new(ClientHello) },
	"send":                func() any { return new(Send) },
	"edit":                func() any { return new(Edit) },
	"create_group":        func() any { return new(CreateGroup) },
	"rename_group":        func() any { return new(RenameGroup) },
	"send_group":          func() any { return new(SendGroup) },
	"edit_group":          func() any { return new(EditGroup) },
	"leave_group":         func() any { return new(LeaveGroup) },
	"delete_group":        func() any { return new(DeleteGroup) },
	"add_to_group":        func() any { return new(AddToGroup) },
	"remove_from_group":   func() any { return new(RemoveFromGroup) },
	"promote_group_admin": func() any { return new(PromoteGroupAdmin) },
	"demote_group_admin":  func() any { return new(DemoteGroupAdmin) },
	"leave_room":          func() any { return new(LeaveRoom) },
	"delete_room":         func() any { return new(DeleteRoom) },
	"create_dm":           func() any { return new(CreateDM) },
	"send_dm":             func() any { return new(SendDM) },
	"edit_dm":             func() any { return new(EditDM) },
	"leave_dm":            func() any { return new(LeaveDM) },
	"delete":              func() any { return new(Delete) },
	"typing":              func() any { return new(Typing) },
	"read":                func() any { return new(Read) },
	"react":               func() any { return new(React) },
	"unreact":             func() any { return new(Unreact) },
	"pin":                 func() any { return new(Pin) },
	"unpin":               func() any { return new(Unpin) },
	"set_profile":         func() any { return new(SetProfile) },
	"set_status":          func() any { return new(SetStatus) },
	"history":             func() any { return new(History) },
	"epoch_rotate":        func() any { return new(EpochRotate) },
	"upload_start":        func() any { return new(UploadStart) },
	"download":            func() any { return new(Download) },
	"room_members":        func() any { return new(RoomMembers) },
}

// seedFrames are sample inputs the fuzzer starts from. Each line is
// one NDJSON frame. Coverage includes: minimal-valid frames for each
// verb (happy path), empty input, whitespace-only, malformed JSON
// (truncated / unbalanced braces), type-confusion (integer where
// string expected — per F10 the catch-net is the DB membership check,
// but the decoder must not panic), deeply nested RawMessage fields,
// and oversize frames near the 1 MB scanner limit.
var seedFrames = [][]byte{
	// Minimal-valid happy paths for each verb (sufficient to pass
	// json.Unmarshal; may fail later server-side validation).
	[]byte(`{"type":"client_hello","version":"1","user":"usr_a","device_id":"dev_a"}`),
	[]byte(`{"type":"send","room":"room_abc","payload":"p","signature":"s"}`),
	[]byte(`{"type":"edit","id":"msg_1","room":"room_abc","epoch":1,"payload":"p","signature":"s"}`),
	[]byte(`{"type":"create_group","members":["usr_a","usr_b"]}`),
	[]byte(`{"type":"rename_group","group":"group_a","name":"new"}`),
	[]byte(`{"type":"send_group","group":"group_a","wrapped_keys":{"usr_a":"k"},"payload":"p","signature":"s"}`),
	[]byte(`{"type":"edit_group","id":"msg_1","group":"group_a","wrapped_keys":{"usr_a":"k"},"payload":"p","signature":"s"}`),
	[]byte(`{"type":"leave_group","group":"group_a"}`),
	[]byte(`{"type":"delete_group","group":"group_a"}`),
	[]byte(`{"type":"add_to_group","group":"group_a","user":"usr_b"}`),
	[]byte(`{"type":"remove_from_group","group":"group_a","user":"usr_b"}`),
	[]byte(`{"type":"promote_group_admin","group":"group_a","user":"usr_b"}`),
	[]byte(`{"type":"demote_group_admin","group":"group_a","user":"usr_b"}`),
	[]byte(`{"type":"leave_room","room":"room_abc"}`),
	[]byte(`{"type":"delete_room","room":"room_abc"}`),
	[]byte(`{"type":"create_dm","user":"usr_b"}`),
	[]byte(`{"type":"send_dm","dm":"dm_a","wrapped_keys":{"usr_a":"k"},"payload":"p","signature":"s"}`),
	[]byte(`{"type":"edit_dm","id":"msg_1","dm":"dm_a","wrapped_keys":{"usr_a":"k"},"payload":"p","signature":"s"}`),
	[]byte(`{"type":"leave_dm","dm":"dm_a"}`),
	[]byte(`{"type":"delete","id":"msg_1"}`),
	[]byte(`{"type":"typing","room":"room_abc"}`),
	[]byte(`{"type":"read","room":"room_abc","id":"msg_1"}`),
	[]byte(`{"type":"react","id":"msg_1","emoji":"🎉"}`),
	[]byte(`{"type":"unreact","id":"msg_1","emoji":"🎉"}`),
	[]byte(`{"type":"pin","id":"msg_1","room":"room_abc"}`),
	[]byte(`{"type":"unpin","id":"msg_1","room":"room_abc"}`),
	[]byte(`{"type":"set_profile","display_name":"alice"}`),
	[]byte(`{"type":"set_status","status":"busy"}`),
	[]byte(`{"type":"history","room":"room_abc","before":100}`),
	[]byte(`{"type":"epoch_rotate","room":"room_abc","epoch":2}`),
	[]byte(`{"type":"upload_start","size":1024,"content_hash":"h"}`),
	[]byte(`{"type":"download","file_id":"file_abc"}`),
	[]byte(`{"type":"room_members","room":"room_abc"}`),

	// Malformed / adversarial shapes.
	[]byte(``),                                        // empty
	[]byte(`   `),                                     // whitespace only
	[]byte(`not-json-at-all`),                         // invalid JSON
	[]byte(`{`),                                       // unbalanced
	[]byte(`{"type":`),                                // truncated mid-key
	[]byte(`{"type":"send"`),                          // truncated after type
	[]byte(`{"type":"send"}`),                         // missing required fields
	[]byte(`{"type":"unknown_verb","x":1}`),           // unknown verb type
	[]byte(`{"type":123}`),                            // integer where string expected
	[]byte(`{"type":null}`),                           // null type
	[]byte(`{"type":"send","room":12345}`),            // F10 type-coercion case
	[]byte(`{"type":"send","room":null}`),             // F10 null-field case
	[]byte(`{"type":"send_group","wrapped_keys":[]}`), // array where object expected
	[]byte(`{"type":"send","payload":{"nested":{"deep":{"deeper":"v"}}}}`),
	// Multi-line NDJSON: two frames concatenated.
	[]byte("{\"type\":\"typing\",\"room\":\"r1\"}\n{\"type\":\"read\",\"room\":\"r1\",\"id\":\"m\"}\n"),
	// Trailing partial frame.
	[]byte("{\"type\":\"send\",\"room\":\"r1\",\"payload\":\"p\",\"signature\":\"s\"}\n{\"type\":\"edit"),
}

// FuzzDecodeDispatch runs arbitrary bytes through the full NDJSON
// decode path and asserts no panic. Scanner errors, JSON parse
// errors, and type-dispatch misses are all acceptable outcomes — the
// contract is "decoder is crash-resistant on hostile input."
func FuzzDecodeDispatch(f *testing.F) {
	for _, seed := range seedFrames {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		decoder := NewDecoder(bytes.NewReader(data))
		// Bound the frame-per-input loop: pathological inputs with
		// many short lines should not make this fuzz iteration run
		// unbounded. 1000 is comfortably above any realistic NDJSON
		// payload a fuzzer would generate in a single input block.
		for i := 0; i < 1000; i++ {
			raw, err := decoder.DecodeRaw()
			if err != nil {
				return
			}

			// Extract the type field. May fail on malformed JSON or
			// missing `type` key — that's fine, just skip dispatch.
			msgType, err := TypeOf(raw)
			if err != nil {
				continue
			}

			// Dispatch to typed unmarshal. Unknown verbs are skipped
			// (the server's handleMessage also rejects them; the fuzz
			// target is panic-freedom of the decode path).
			factory, known := clientVerbs[msgType]
			if !known {
				continue
			}
			// Errors from typed unmarshal are fine — e.g., a `send`
			// frame with `room:[1,2,3]` fails unmarshal cleanly.
			// Panics are not.
			_ = json.Unmarshal(raw, factory())
		}
	})
}

// FuzzTypeOf narrows the fuzz target to the TypeOf helper alone. It
// handles the common "inspect the type before dispatch" case and is
// worth a separate fuzz because every handler entry point calls it.
func FuzzTypeOf(f *testing.F) {
	for _, seed := range seedFrames {
		// TypeOf takes raw JSON (no NDJSON scanner), so feed the
		// first line of each seed.
		line := seed
		if i := bytes.IndexByte(seed, '\n'); i >= 0 {
			line = seed[:i]
		}
		f.Add(line)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// Any input must either return a type string + nil error, or
		// "" + error. Neither branch may panic.
		_, _ = TypeOf(json.RawMessage(data))
	})
}
