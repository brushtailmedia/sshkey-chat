package server

// Phase 16 Gap 4 — the audit log has been extracted into a standalone
// `internal/audit` package so the CLI (sshkey-ctl) can append entries
// for bootstrap-admin, retire-user, promote, etc. without reaching
// into server internals. This file is now a thin alias layer that
// keeps the existing call sites (s.audit.Log(...) in 5 places)
// working unchanged.

import (
	"github.com/brushtailmedia/sshkey-chat/internal/audit"
)

// auditLog is the in-server alias for *audit.Log. The unexported name
// is preserved so existing code continues to compile without changes.
type auditLog = audit.Log

// newAuditLog constructs an audit logger writing to <dataDir>/audit.log,
// matching the pre-extraction signature.
func newAuditLog(dataDir string) *auditLog {
	return audit.New(dataDir)
}
