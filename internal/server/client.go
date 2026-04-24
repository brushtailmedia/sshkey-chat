package server

import (
	"sync/atomic"

	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// Client represents a connected client session.
//
// Three SSH session channels are opened per connection, in fixed order:
//
//  1. Control / NDJSON (this struct's `Channel`). Long-lived control
//     plane — protocol verbs including `download` requests.
//  2. Download channel (`DownloadChannel`). Server writes raw file
//     bytes here in response to `download` verbs. One in-flight
//     download per session; client serializes.
//  3. Upload channel (handled elsewhere). Client writes raw bytes.
//
// Authorization (`authorizeDownload`), `file_contexts` binding, cascade
// cleanup, hash verification, and counter signals are all enforced on
// Channel 1's dispatch path before bytes move on Channel 2.
type Client struct {
	UserID   string // nanoid (usr_ prefix) — immutable identity
	DeviceID string
	// Encoder is the thread-safe write surface for this client's
	// SSH Channel 1. All writes to the client — whether from a
	// per-handler goroutine (direct response) or from the per-client
	// writer goroutine (fanOut broadcast) — go through this wrapper,
	// which serializes concurrent Encode calls via an internal mutex
	// so they never interleave on the wire.
	Encoder         *safeEncoder
	Decoder         *protocol.Decoder
	Channel         ssh.Channel // NDJSON control-plane channel (1st "session" channel)
	DownloadChannel ssh.Channel // shared download channel (2nd "session" channel); nil only if the client failed to open it within the grace period — downloads fail closed with not_found
	Conn            *ssh.ServerConn
	Capabilities    []string // negotiated capabilities

	// LastActivity is the unix-seconds timestamp of the most recent
	// successful NDJSON decode on Channel 1. Updated by messageLoop
	// on every frame; read by runIdleWatchdog (Phase 17b Step 5a)
	// to detect NDJSON-level idleness and close the channel if the
	// configured idle_timeout_seconds is exceeded.
	//
	// Zero value means "not yet stamped" — watchdog interprets 0 as
	// "fresh client, no activity yet" and grants one full timeout
	// window before closing.
	LastActivity atomic.Int64

	// sendCh (Phase 17b Step 5b) is the per-client outbound message
	// queue. fanOut enqueues non-blocking; the writer goroutine
	// drains it and encodes to the SSH channel. Capacity absorbs
	// bursty broadcasts; a full queue indicates a slow reader.
	// Nil for test-only Client values that don't exercise the
	// writer goroutine.
	sendCh chan any

	// sessionDone (Phase 17b Step 5b) signals the writer goroutine
	// to exit. Closed by handleSession on session teardown. Writer
	// selects on both sendCh and sessionDone; whichever fires first
	// wins, and sessionDone triggers a clean exit without draining
	// the remaining queue (client is gone; pending messages are
	// lost, which is correct).
	sessionDone chan struct{}

	// consecutiveDrops (Phase 17b Step 5b) counts consecutive
	// fanOut attempts that found sendCh full. Resets to 0 on any
	// successful enqueue. When it crosses the configured
	// ConsecutiveDropDisconnectThreshold, fanOut closes the SSH
	// channel (client disconnects; reconnect + sync-catchup
	// recovers). Atomic because fanOut can run concurrently from
	// multiple broadcast sites.
	consecutiveDrops atomic.Int32
}

// TryEnqueue attempts a non-blocking send of msg onto the outbound
// queue. Returns (true, 0) on success with consecutiveDrops reset;
// returns (false, drops) on full queue with the drops counter
// post-increment. Callers use the drops return to decide whether
// to trigger a consecutive-drop disconnect.
//
// Phase 17b Step 5b. Nil sendCh (test-mode Client) returns (false, 0)
// — no queueing, no drop tracking; direct-Encode sites see the call
// as a no-op in tests that don't exercise the queue.
func (c *Client) TryEnqueue(msg any) (queued bool, drops int32) {
	if c.sendCh == nil {
		return false, 0
	}
	select {
	case c.sendCh <- msg:
		c.consecutiveDrops.Store(0)
		return true, 0
	default:
		return false, c.consecutiveDrops.Add(1)
	}
}
