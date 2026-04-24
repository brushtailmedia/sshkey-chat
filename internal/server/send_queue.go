package server

// Phase 17b Step 5b — per-client outbound queue + writer goroutine.
//
// Writer goroutine lifecycle:
//   - Spawned by handleSession right after Client is registered in
//     s.clients (so fanOut sites can find the Client + enqueue).
//   - Drains c.sendCh, encoding each message to the SSH channel.
//     Uses c.Encoder which is a safeEncoder — writes serialize
//     cleanly against concurrent direct-Encode sites.
//   - Exits cleanly when c.sessionDone closes. Remaining queued
//     messages are discarded (the client is going away; they'd be
//     recovered on reconnect via sync-catchup).
//   - An Encode error (client channel already closed or SSH error)
//     increments SignalBroadcastDropped and exits the goroutine —
//     the session's normal cleanup path in handleSession will then
//     remove the Client from s.clients.
//
// Slow-reader disconnect (tryFanOutTo below) sits OUTSIDE this file
// in reject.go's fanOut update, because it's a broadcast-path policy
// decision rather than a writer-goroutine concern.

import (
	"github.com/brushtailmedia/sshkey-chat/internal/counters"
)

// runSendWriter drains c.sendCh and writes each message to the
// client's SSH channel. Exits when c.sessionDone closes.
//
// Called once per Client via `go s.runSendWriter(c)` from
// handleSession. The caller guarantees c.sendCh and c.sessionDone
// are non-nil before spawning.
func (s *Server) runSendWriter(c *Client) {
	for {
		select {
		case <-c.sessionDone:
			return
		case msg, ok := <-c.sendCh:
			if !ok {
				return
			}
			if err := c.Encoder.Encode(msg); err != nil {
				// Channel closed underneath us or SSH write
				// error. Count the drop and exit; session
				// cleanup will remove the Client from
				// s.clients.
				s.counters.Inc(counters.SignalBroadcastDropped, c.DeviceID)
				s.logger.Debug("send writer: encode error, exiting",
					"user", c.UserID,
					"device", c.DeviceID,
					"error", err,
				)
				return
			}
		}
	}
}
