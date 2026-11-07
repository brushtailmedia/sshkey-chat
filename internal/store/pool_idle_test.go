package store

import (
	"testing"
	"time"
)

// Idle pooled connections close after handleIdleTime (store-write Part 1
// follow-up): an idle room then holds no descriptors, and the next query
// reopens a connection with every DSN pragma re-applied. database/sql's
// cleaner runs on a one-second minimum interval, so this test shortens the
// idle time to a millisecond and waits on a ticker for the pool's
// MaxIdleTimeClosed counter rather than sleeping; it is bounded at five
// seconds and normally completes in about one.
func TestPoolIdle_ConnectionsCloseAndReopenWithPragmas(t *testing.T) {
	old := handleIdleTime
	handleIdleTime = time.Millisecond
	defer func() { handleIdleTime = old }()

	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	db, err := s.RoomDB("room_V1StGXR8_Z5jdHi6B-myT")
	if err != nil {
		t.Fatalf("RoomDB: %v", err)
	}
	// Use the connection once so there is something idle to close.
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&n); err != nil {
		t.Fatalf("first query: %v", err)
	}

	before := db.Stats()
	t.Logf("before the idle wait: open=%d idle=%d", before.OpenConnections, before.Idle)

	// The cleaner closes connections whose idle time has passed at each of
	// its ticks; wait until none is open, not merely until one has closed.
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for db.Stats().OpenConnections != 0 {
		select {
		case <-tick.C:
		case <-deadline.C:
			t.Fatalf("connections still open after 5 s: %+v", db.Stats())
		}
	}
	if closed := db.Stats().MaxIdleTimeClosed; closed == 0 {
		t.Fatalf("connections closed but not for idle time: %+v", db.Stats())
	}

	// The reopened connection carries the DSN pragmas, foreign keys included.
	var fk int
	if err := db.QueryRow(`PRAGMA foreign_keys`).Scan(&fk); err != nil || fk != 1 {
		t.Fatalf("reopened connection: foreign_keys = %d, err %v; want 1", fk, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&n); err != nil {
		t.Fatalf("query after reopen: %v", err)
	}
}
