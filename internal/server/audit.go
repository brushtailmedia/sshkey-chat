package server

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// auditLog is an append-only log of administrative actions.
type auditLog struct {
	mu   sync.Mutex
	path string
}

func newAuditLog(dataDir string) *auditLog {
	return &auditLog{
		path: filepath.Join(dataDir, "audit.log"),
	}
}

// Log writes an entry to the audit log.
func (a *auditLog) Log(source, action, details string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return
	}
	defer f.Close()

	ts := time.Now().UTC().Format(time.RFC3339)
	fmt.Fprintf(f, "%s  %-12s  %-15s  %s\n", ts, source, action, details)
}
