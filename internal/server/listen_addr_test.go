package server

// ListenAndServe on port 0 must report the address it actually bound (the
// configured string would read "127.0.0.1:0"), and Close must end it
// cleanly and leave the data dir reopenable. This is what the cross-repo
// end-to-end harness relies on to find a server it started as a process.

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// syncBuffer is a bytes.Buffer safe for the server's logging goroutines.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// listeningAddr scans the JSON log for the "server listening" record and
// returns its addr field, or "" when it has not been logged yet.
func listeningAddr(log string) string {
	for _, line := range strings.Split(log, "\n") {
		var rec struct {
			Msg  string `json:"msg"`
			Addr string `json:"addr"`
		}
		if json.Unmarshal([]byte(line), &rec) == nil && rec.Msg == "server listening" {
			return rec.Addr
		}
	}
	return ""
}

func TestListenAndServe_LogsBoundAddressAndClosesCleanly(t *testing.T) {
	configDir := t.TempDir()
	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(configDir, "server.toml"), []byte(`
[server]
port = 0
bind = "127.0.0.1"

[server.auto_revoke]
enabled = false

[shutdown]
grace_period = "100ms"
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(configDir)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	var logBuf syncBuffer
	logger := slog.New(slog.NewJSONHandler(io.MultiWriter(&logBuf), nil))
	s, err := New(cfg, logger, dataDir)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- s.ListenAndServe() }()

	// Wait for the listening record without sleeping: poll the log on a
	// ticker up to a deadline.
	var addr string
	deadline := time.After(10 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
wait:
	for {
		if addr = listeningAddr(logBuf.String()); addr != "" {
			break
		}
		select {
		case err := <-done:
			t.Fatalf("ListenAndServe returned before listening: %v\nlog:\n%s", err, logBuf.String())
		case <-deadline:
			t.Fatalf("no \"server listening\" record within 10s\nlog:\n%s", logBuf.String())
		case <-tick.C:
			continue wait
		}
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("logged addr %q is not host:port: %v", addr, err)
	}
	if host != "127.0.0.1" || port == "0" || port == "" {
		t.Fatalf("logged addr = %q, want the bound 127.0.0.1:<non-zero port>, not the configured port 0", addr)
	}
	// The logged port is really open.
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial logged addr %s: %v", addr, err)
	}
	conn.Close()

	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ListenAndServe after Close = %v, want nil (a clean exit)", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ListenAndServe did not return within 10s of Close")
	}

	// A completed Close removed the lockfile and closed every store cleanly
	// (SQLite deletes a database's -wal file when its last connection closes
	// cleanly), so the data dir is inspectable and reopens.
	if _, err := os.Stat(filepath.Join(dataDir, lockfileName)); !os.IsNotExist(err) {
		t.Fatalf("lockfile still present after Close (stat err=%v)", err)
	}
	if wals, _ := filepath.Glob(filepath.Join(dataDir, "data", "*-wal")); len(wals) != 0 {
		t.Fatalf("write-ahead logs left behind after Close: %v (stores not closed cleanly)", wals)
	}
	st, err := store.Open(dataDir)
	if err != nil {
		t.Fatalf("reopen store after Close: %v", err)
	}
	st.Close()
}
