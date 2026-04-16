package server

// Phase 16 Gap 1 — runDeviceRevocationProcessor and
// processPendingDeviceRevocations. Standalone processor for
// `sshkey-ctl revoke-device`.
//
// Different shape from the other Phase 16 Gap 1 processors: this one
// operates on live SSH session state (open channels) rather than on
// persisted protocol state (broadcast events). The data-layer effect
// of revocation is already done by the CLI before enqueue:
//
//   1. CLI calls store.RevokeDevice → writes to revoked_devices,
//      blocking future authentication attempts for this device
//   2. CLI calls store.RecordPendingDeviceRevocation → enqueues a
//      row here so the running server can terminate any active
//      session
//
// The processor's only job is to call kickRevokedDeviceSession,
// which finds any connected client matching (user, device) and
// closes its SSH channel after sending a device_revoked event so
// the TUI can show a notice.
//
// Mirrors the kick logic that lives in handleRevokeDevice (the
// protocol-path handler for user-initiated self-revoke) — that loop
// was extracted into kickRevokedDeviceSession so both paths share
// the same termination semantics.

import (
	"time"
)

// deviceRevocationPollInterval matches the other Phase 16 Gap 1
// processor cadences.
const deviceRevocationPollInterval = 5 * time.Second

// runDeviceRevocationProcessor polls pending_device_revocations and
// terminates active sessions for revoked devices.
func (s *Server) runDeviceRevocationProcessor() {
	ticker := time.NewTicker(deviceRevocationPollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.deviceRevocationStop:
			return
		case <-ticker.C:
			s.processPendingDeviceRevocations()
		}
	}
}

// processPendingDeviceRevocations consumes the queue and kicks any
// matching active sessions. Each call:
//   - Atomically reads + deletes the queue rows
//   - Writes an audit log entry crediting the operator
//   - Calls kickRevokedDeviceSession, which is a no-op if the
//     device isn't currently connected (the data-layer revocation
//     is sufficient to block future logins)
//
// Errors are logged but don't stop processing.
func (s *Server) processPendingDeviceRevocations() {
	if s.store == nil {
		return
	}

	pending, err := s.store.ConsumePendingDeviceRevocations()
	if err != nil {
		s.logger.Error("failed to consume device revocation queue", "error", err)
		return
	}
	if len(pending) == 0 {
		return
	}

	for _, p := range pending {
		s.logger.Info("processing device revocation",
			"user", p.UserID,
			"device", p.DeviceID,
			"reason", p.Reason,
			"revoked_by", p.RevokedBy,
			"queued_at", p.QueuedAt,
		)

		// Audit credit. The CLI verb ("revoke-device") is used as
		// the action label so operators reading the log see what
		// they typed.
		if s.audit != nil {
			s.audit.Log(p.RevokedBy, "revoke-device",
				"user="+p.UserID+" device="+p.DeviceID+" reason="+p.Reason)
		}

		// Kick any matching live session. No-op if not connected;
		// the data-layer revocation is what blocks future logins,
		// so processing has succeeded even when there's nothing to
		// kick.
		s.kickRevokedDeviceSession(p.UserID, p.DeviceID, p.Reason)
	}
}
