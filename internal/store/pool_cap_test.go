package store

import (
	"fmt"
	"sync"
	"testing"
)

// Every handle the store opens has a two-connection pool and a per-handle
// write mutex: writers queue on the mutex while a read can overlap a write
// on the second connection. These tests pin the cap and write serialisation
// on every kind of handle and prove that a burst of concurrent writers
// through the production insert path neither errors nor loses rows. No
// timing assertions and no sleeps: the latency claims live in the
// env-gated write-burst benchmark.

func TestOpenDB_CapsEveryHandleAtOneConnection(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	room, err := s.RoomDB("room_V1StGXR8_Z5jdHi6B-myT")
	if err != nil {
		t.Fatalf("RoomDB: %v", err)
	}
	for name, db := range map[string]*DB{
		"data.db":   s.DataDB(),
		"rooms.db":  s.RoomsDB(),
		"users.db":  s.usersDB,
		"room file": room,
	} {
		if db == nil {
			t.Fatalf("%s: nil handle", name)
		}
		if got := db.Stats().MaxOpenConnections; got != handleConns {
			t.Errorf("%s: MaxOpenConnections = %d, want handleConns (%d)", name, got, handleConns)
		}
		if !db.serialize {
			t.Errorf("%s: writes are not serialised", name)
		}
	}
}

// Sixteen goroutines, a hundred inserts each, one room file: zero errors
// and exactly 1,600 rows. The write mutex queues writers instead of leaving
// them to SQLite's busy handler; without serialisation the same burst used
// to produce multi-hundred-millisecond stalls and, before busy_timeout was
// fixed, "database is locked" errors.
func TestPoolCap_ConcurrentWritersToOneFileLoseNothing(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	db, err := s.RoomDB("room_V1StGXR8_Z5jdHi6B-myT")
	if err != nil {
		t.Fatalf("RoomDB: %v", err)
	}

	const writers, each = 16, 100
	errs := make([]error, writers)
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				msg := StoredMessage{
					ID:        fmt.Sprintf("msg_w%02d_%04d", w, i),
					Sender:    "usr_bench_sender",
					TS:        int64(1_700_000_000 + w*each + i),
					Epoch:     1,
					Payload:   "cGF5bG9hZA==",
					Signature: "c2ln",
				}
				if _, err := insertMessage(db, msg); err != nil {
					errs[w] = fmt.Errorf("writer %d insert %d: %w", w, i, err)
					return
				}
			}
		}(w)
	}
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != writers*each {
		t.Fatalf("rows = %d, want %d", n, writers*each)
	}
}

// A read overlaps an open transaction: with two connections per handle
// and reads outside the write mutex, a read issued while a transaction is
// open takes the second connection at once, sees the committed state (WAL
// snapshot isolation: not the transaction's uncommitted row), and never
// blocks; after the commit it sees the row. Synchronous, so it cannot be
// racy, and it is exactly the overlap the mixed benchmark scenario chose
// the second connection for. (The pattern the nested-use guard forbids is
// a write, or a read on a handle with a single connection, from the SAME
// goroutine that holds the Tx.)
func TestPoolCap_ReadOverlapsAnOpenTransaction(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	db, err := s.RoomDB("room_V1StGXR8_Z5jdHi6B-myT")
	if err != nil {
		t.Fatalf("RoomDB: %v", err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := tx.Exec(benchInsertSQL, "msg_in_tx", "usr_a", int64(1), int64(1), "cA==", "", "c2ln", ""); err != nil {
		t.Fatalf("insert in tx: %v", err)
	}

	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&n); err != nil {
		t.Fatalf("read during the open transaction: %v", err)
	}
	if n != 0 {
		t.Fatalf("read during the open transaction saw %d rows, want 0 (snapshot isolation)", n)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("read after commit = %d, err %v; want 1", n, err)
	}
}
