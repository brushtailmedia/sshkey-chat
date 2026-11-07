// Package sqlitedsn builds modernc.org/sqlite DSN strings with the PRAGMAs the
// server actually relies on applied — and applied to every pooled connection.
//
// Why this exists: modernc.org/sqlite silently ignores mattn/go-sqlite3-style
// DSN params such as `_busy_timeout=5000` / `_journal_mode=WAL`. Pragmas must be
// passed via modernc's `_pragma=name(value)` form, which the driver re-applies
// on every connection it opens. busy_timeout in particular is a per-connection
// setting, so it MUST come from the DSN — a single `PRAGMA busy_timeout` Exec
// after open would only cover one connection in the pool, leaving the rest at 0
// (→ immediate SQLITE_BUSY under concurrent writers).
//
// Read-only enforcement (`mode=ro`) only takes effect on the `file:` URI form;
// a plain-path `?mode=ro` is silently ignored by modernc (writes still succeed).
// The helpers therefore always emit a `file:` URI built from an absolute path:
// read-only enforcement needs the file: form, and a relative file: URI does not
// open correctly under modernc, so the input path is normalized with
// filepath.Abs first (CLI/server `-data`/`--data` inputs can be relative).
//
// The package is side-effect free: it only builds DSN strings and does not
// import or register the SQLite driver. Callers keep their own
// `_ "modernc.org/sqlite"` import.
package sqlitedsn

import (
	"fmt"
	"net/url"
	"path/filepath"
)

// busyTimeoutMS is the per-connection SQLITE_BUSY wait. It matches the value the
// store has always intended — the previous mattn-style DSN never actually
// applied it, so contended writers failed immediately instead of waiting.
const busyTimeoutMS = 5000

// Writable builds a read-write DSN: WAL journal mode, a 5s busy timeout and
// foreign-key enforcement, all applied to every connection the pool opens,
// plus immediate write transactions.
//
// foreign_keys is per-connection like busy_timeout, so it belongs here too
// (store-write Part 1, 2026-11-08): the store used to set it with one Exec
// after open, which reached only the connection that happened to run it —
// a latent gap with an uncapped pool and a certainty with the store's
// two-connection handles, whose second connection would have had foreign
// keys off. The schema has three foreign-key constraints.
//
// _txlock=immediate makes every transaction take SQLite's write lock at
// BEGIN instead of at its first write. A deferred transaction that reads
// first and then upgrades can fail with a busy error that the busy handler
// cannot retry (in WAL, SQLITE_BUSY_SNAPSHOT); an immediate one simply waits
// out busy_timeout like any other writer. In-process the store's write
// mutex already admits one writer at a time; this covers the other
// processes that take the write lock — sshkey-ctl and the backup package.
// The store opens no read-only transactions, so there is nothing to lose.
func Writable(path string) (string, error) {
	q := url.Values{}
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busyTimeoutMS))
	q.Add("_pragma", "foreign_keys(1)")
	q.Set("_txlock", "immediate")
	return buildFileURI(path, q)
}

// ReadOnly builds a read-only DSN: opens with mode=ro (enforced via the file:
// URI form — a write returns SQLITE_READONLY) plus a 5s busy timeout. It does
// NOT set journal_mode, so it never mutates an existing database's journal mode
// (e.g. a read-only open of a non-WAL DB stays non-WAL).
func ReadOnly(path string) (string, error) {
	q := url.Values{}
	q.Set("mode", "ro")
	q.Add("_pragma", fmt.Sprintf("busy_timeout(%d)", busyTimeoutMS))
	return buildFileURI(path, q)
}

// buildFileURI normalizes path to absolute and assembles a `file:` URI DSN with
// the given query parameters. Absolute normalization is required: read-only
// enforcement needs the file: form, and a relative file: URI does not open
// correctly under modernc. url.URL escapes the path so spaces / `?` / other
// special characters in a data dir can't corrupt the DSN.
func buildFileURI(path string, q url.Values) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("sqlitedsn: resolve %q: %w", path, err)
	}
	u := url.URL{Scheme: "file", Path: abs, RawQuery: q.Encode()}
	return u.String(), nil
}
