package store

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// The write mutex on DB (store-write Part 1): writes and transactions
// serialise through it, a transaction releases it exactly once whatever
// order Commit and Rollback are called in, and the benchmark's unserialised
// mode leaves it out. No timing assertions and no sleeps.

func openTestRoomDB(t *testing.T) *DB {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	db, err := s.RoomDB("room_V1StGXR8_Z5jdHi6B-myT")
	if err != nil {
		t.Fatalf("RoomDB: %v", err)
	}
	if !db.serialize {
		t.Fatal("a production handle must serialise writes")
	}
	return db
}

// A write from another goroutine completes only after the transaction
// that holds the mutex commits, and it then sees the committed row.
func TestDB_WriteWaitsForAnOpenTransaction(t *testing.T) {
	db := openTestRoomDB(t)
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := tx.Exec(benchInsertSQL, "msg_in_tx", "usr_a", int64(1), int64(1), "cA==", "", "c2ln", ""); err != nil {
		t.Fatalf("insert in tx: %v", err)
	}

	var committed atomic.Bool
	type outcome struct {
		rowsSeen int
		err      error
		afterTx  bool
	}
	done := make(chan outcome, 1)
	go func() {
		// This Exec blocks on the mutex (and the pool) until Commit.
		_, err := db.Exec(benchInsertSQL, "msg_after", "usr_b", int64(2), int64(1), "cA==", "", "c2ln", "")
		var n int
		if err == nil {
			err = db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&n)
		}
		done <- outcome{rowsSeen: n, err: err, afterTx: committed.Load()}
	}()

	committed.Store(true)
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	got := <-done
	if got.err != nil {
		t.Fatalf("write after commit: %v", got.err)
	}
	if !got.afterTx {
		t.Fatal("the second write ran before the transaction committed")
	}
	if got.rowsSeen != 2 {
		t.Fatalf("rows after both writes = %d, want 2", got.rowsSeen)
	}
}

// Commit then Rollback (the `defer tx.Rollback()` idiom) releases the
// mutex once; a later write proceeds. Rollback alone releases it too.
func TestDB_TransactionReleasesTheMutexOnce(t *testing.T) {
	db := openTestRoomDB(t)

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := tx.Rollback(); err == nil {
		t.Fatal("Rollback after Commit should report the done transaction")
	}
	if _, err := db.Exec(benchInsertSQL, "msg_1", "usr_a", int64(1), int64(1), "cA==", "", "c2ln", ""); err != nil {
		t.Fatalf("write after commit+rollback: %v", err)
	}

	tx2, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin 2: %v", err)
	}
	if err := tx2.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if _, err := db.Exec(benchInsertSQL, "msg_2", "usr_a", int64(2), int64(1), "cA==", "", "c2ln", ""); err != nil {
		t.Fatalf("write after rollback: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("rows = %d, err %v; want 2", n, err)
	}
}

// A failing Begin (closed handle) must not leave the mutex held.
func TestDB_BeginErrorDoesNotLeakTheMutex(t *testing.T) {
	db := openTestRoomDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := db.Begin(); err == nil {
		t.Fatal("Begin on a closed handle succeeded")
	}
	// If the mutex had leaked this would block forever; TryLock proves it
	// is free without waiting.
	if !db.mu.TryLock() {
		t.Fatal("write mutex still held after a failed Begin")
	}
	db.mu.Unlock()
}

// Concurrent writers through the wrapper: no errors, every row present,
// and the mutex is never held by two goroutines at once (observed with a
// counter inside a probe that takes the same path as Exec).
func TestDB_WritesSerialise(t *testing.T) {
	db := openTestRoomDB(t)
	const writers, each = 16, 50
	var inside, maxInside atomic.Int32
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < each; i++ {
				db.mu.Lock()
				n := inside.Add(1)
				for {
					m := maxInside.Load()
					if n <= m || maxInside.CompareAndSwap(m, n) {
						break
					}
				}
				_, err := db.DB.Exec(benchInsertSQL, "msg_"+string(rune('a'+w))+"_"+itoa(i), "usr", int64(i), int64(1), "cA==", "", "c2ln", "")
				inside.Add(-1)
				db.mu.Unlock()
				if err != nil {
					errs[w] = err
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
	if got := maxInside.Load(); got != 1 {
		t.Fatalf("max goroutines inside the write section = %d, want 1", got)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM messages`).Scan(&n); err != nil || n != writers*each {
		t.Fatalf("rows = %d, err %v; want %d", n, err, writers*each)
	}
}

// The unserialised mode exists for the benchmark's baseline only: writes
// and transactions skip the mutex entirely.
func TestDB_UnserialisedModeSkipsTheMutex(t *testing.T) {
	db := openTestRoomDB(t)
	db.serialize = false
	db.mu.Lock() // held by "someone else": writes must not block on it
	defer db.mu.Unlock()
	if _, err := db.Exec(benchInsertSQL, "msg_free", "usr", int64(1), int64(1), "cA==", "", "c2ln", ""); err != nil {
		t.Fatalf("unserialised Exec: %v", err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("unserialised Begin: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := tx.Rollback(); !errors.Is(err, sql.ErrTxDone) {
		t.Fatalf("Rollback after Commit = %v, want sql.ErrTxDone", err)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// A store transaction takes SQLite's write lock at Begin (the DSN's
// _txlock=immediate): a second, independent handle on the same file — the
// shape of sshkey-ctl or a backup — cannot begin its own write transaction
// while ours is open, even before we have written anything, and can once we
// commit. Deferred transactions would let the probe in and fail our later
// upgrade with an unretryable busy error instead.
func TestDB_BeginTakesTheWriteLockImmediately(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	const room = "room_V1StGXR8_Z5jdHi6B-myT"
	db, err := s.RoomDB(room)
	if err != nil {
		t.Fatalf("RoomDB: %v", err)
	}
	abs, err := filepath.Abs(filepath.Join(s.dir, "room-"+room+".db"))
	if err != nil {
		t.Fatal(err)
	}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(0)")
	q.Set("_txlock", "immediate")
	probe, err := sql.Open("sqlite", (&url.URL{Scheme: "file", Path: abs, RawQuery: q.Encode()}).String())
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()

	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if ptx, err := probe.Begin(); err == nil {
		_ = ptx.Rollback()
		t.Fatal("another handle could begin a write transaction while ours was open and idle")
	} else if s := strings.ToLower(err.Error()); !strings.Contains(s, "locked") && !strings.Contains(s, "busy") {
		t.Fatalf("probe Begin error = %v, want busy/locked", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	ptx, err := probe.Begin()
	if err != nil {
		t.Fatalf("probe Begin after our commit: %v", err)
	}
	_ = ptx.Rollback()
}

// Both pooled connections of a handle have foreign keys on (the DSN carries
// the pragma); the old one-off Exec reached only one of them.
func TestDB_ForeignKeysOnEveryConnection(t *testing.T) {
	db := openTestRoomDB(t)
	ctx := context.Background()
	c1, err := db.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	c2, err := db.DB.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	for i, c := range []*sql.Conn{c1, c2} {
		var fk int
		if err := c.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil || fk != 1 {
			t.Errorf("connection %d: foreign_keys = %d, err %v; want 1", i, fk, err)
		}
	}
}
