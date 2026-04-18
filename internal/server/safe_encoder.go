package server

// Phase 17b Step 5b — thread-safe encoder wrapper.
//
// Two goroutines may write to a Client's SSH channel concurrently:
//
//   1. Per-handler goroutines that send direct responses via
//      c.Encoder.Encode(msg) — 150+ call sites across 11 files
//      (responses to client requests, error replies, etc.).
//
//   2. The per-client writer goroutine that drains c.sendCh and
//      writes fanOut broadcasts via c.Encoder.Encode(msg).
//
// protocol.Encoder wraps a json.Encoder which is NOT safe for
// concurrent use (concurrent Encodes could interleave partial bytes
// into the wire output). safeEncoder serializes access at the whole-
// message level via a mutex.
//
// The wrapper preserves the .Encode(v) signature so existing call
// sites work unchanged — only the Client.Encoder field type changes
// (protocol.Encoder → safeEncoder).

import (
	"sync"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// safeEncoder serializes concurrent Encode calls to the underlying
// protocol.Encoder. All writes from the server to a given Client pass
// through an instance of this type.
type safeEncoder struct {
	mu  sync.Mutex
	enc *protocol.Encoder
}

// newSafeEncoder wraps a protocol.Encoder with mutex serialization.
// Callers receive the wrapper; the underlying encoder is not exposed.
func newSafeEncoder(enc *protocol.Encoder) *safeEncoder {
	return &safeEncoder{enc: enc}
}

// Encode serializes one message onto the underlying encoder. Returns
// the encoder's error (same contract as protocol.Encoder.Encode).
func (s *safeEncoder) Encode(v any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enc.Encode(v)
}
