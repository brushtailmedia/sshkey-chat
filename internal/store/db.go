package store

import (
	"context"
	"database/sql"
	"sync"
)

// handleConns is the connection cap on every handle the store opens: one
// connection for the serialised writer and one so a read can overlap it
// (WAL lets a reader run beside a writer). The write-burst benchmark's
// mixed scenario (D1, 16 writers and 4 history readers on one file)
// measured the choice on 2026-11-08: with a single connection the
// writers fell to ~2,000 ops/s with 13–47 ms worst waits because they
// queued behind every reader at the pool; with two, 3,500 ops/s with
// 7–8 ms worst waits and reads at 2 ms worst — nearly the four-connection
// numbers for half the descriptors. A pool is never a third writer: the
// mutex below admits one writer at a time, so SQLite's busy handler is
// never reached in-process.
const handleConns = 2

// DB is the store's handle to one SQLite file (store-write Part 1,
// 2026-11-08). It embeds *sql.DB, so every read method is the standard
// one, and it adds two things on the write side:
//
//  1. The pool behind it is capped at handleConns (openDB), so a
//     goroutine that meets the write lock queues in database/sql instead
//     of sleeping on SQLite's busy-handler back-off ladder.
//  2. Exec and Begin take a per-handle write mutex. database/sql hands a
//     freed connection to a *random* waiter; sync.Mutex goes
//     first-in-first-out once a waiter has waited a millisecond. The
//     benchmark measured the difference for sixteen writers on one file:
//     about 3 ms worst case with the mutex against 8–12 ms with the cap
//     alone, at the same throughput.
//
// Reads (Query, QueryRow) are not locked: they take the second
// connection while a write is in flight, and only queue at the pool when
// two of them meet.
//
// The rule this imposes (the same one the cap already imposed): never
// issue a query on this handle from the goroutine that holds a Tx or an
// open rows cursor on it — the inner call would wait for the connection,
// and now also for the mutex, that its own caller holds. The nested-use
// guard (.github/scripts/check_nested_db_use.sh) enforces it in CI.
// Prepare and Conn are deliberately not wrapped: the audit allows no
// db-level Prepare, and nothing takes a raw Conn.
//
// serialize is false only in the write-burst benchmark's uncapped
// baseline, which reproduces the pre-Part-1 behaviour; production handles
// are always serialised.
type DB struct {
	*sql.DB
	mu        sync.Mutex
	serialize bool
}

func newDB(db *sql.DB, serialize bool) *DB {
	return &DB{DB: db, serialize: serialize}
}

// Exec runs a write under the handle's write mutex.
func (d *DB) Exec(query string, args ...any) (sql.Result, error) {
	return d.ExecContext(context.Background(), query, args...)
}

// ExecContext runs a write under the handle's write mutex.
func (d *DB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if d.serialize {
		d.mu.Lock()
		defer d.mu.Unlock()
	}
	return d.DB.ExecContext(ctx, query, args...)
}

// Begin starts a transaction that holds the write mutex until Commit or
// Rollback (whichever comes first; the second is a no-op for the mutex).
func (d *DB) Begin() (*Tx, error) {
	return d.BeginTx(context.Background(), nil)
}

// BeginTx is Begin with a context and options.
func (d *DB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*Tx, error) {
	if d.serialize {
		d.mu.Lock()
	}
	tx, err := d.DB.BeginTx(ctx, opts)
	if err != nil {
		if d.serialize {
			d.mu.Unlock()
		}
		return nil, err
	}
	return &Tx{Tx: tx, db: d}, nil
}

// Tx is a transaction on a DB. It embeds *sql.Tx, so Exec, Query, QueryRow
// and Prepare are the standard ones; Commit and Rollback release the
// handle's write mutex exactly once between them, so the usual
// `defer tx.Rollback()` after a Commit is harmless.
type Tx struct {
	*sql.Tx
	db   *DB
	once sync.Once
}

// Commit commits and releases the write mutex.
func (t *Tx) Commit() error {
	err := t.Tx.Commit()
	t.release()
	return err
}

// Rollback rolls back and releases the write mutex (a no-op for the mutex
// if Commit already released it).
func (t *Tx) Rollback() error {
	err := t.Tx.Rollback()
	t.release()
	return err
}

func (t *Tx) release() {
	t.once.Do(func() {
		if t.db.serialize {
			t.db.mu.Unlock()
		}
	})
}
