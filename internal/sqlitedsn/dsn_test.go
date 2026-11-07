package sqlitedsn

import (
	"context"
	"database/sql"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func openProbe(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatalf("open %q: %v", dsn, err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func pragmaInt(t *testing.T, db *sql.DB, name string) int {
	t.Helper()
	var v int
	if err := db.QueryRow("PRAGMA " + name).Scan(&v); err != nil {
		t.Fatalf("PRAGMA %s: %v", name, err)
	}
	return v
}

func pragmaStr(t *testing.T, db *sql.DB, name string) string {
	t.Helper()
	var v string
	if err := db.QueryRow("PRAGMA " + name).Scan(&v); err != nil {
		t.Fatalf("PRAGMA %s: %v", name, err)
	}
	return v
}

func isReadOnlyErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "readonly") ||
		strings.Contains(strings.ToLower(err.Error()), "read-only") ||
		strings.Contains(strings.ToLower(err.Error()), "read only")
}

// Writable applies WAL + busy_timeout=5000.
func TestWritable_AppliesWALAndBusyTimeout(t *testing.T) {
	dsn, err := Writable(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	db := openProbe(t, dsn)
	if got := pragmaStr(t, db, "journal_mode"); got != "wal" {
		t.Errorf("journal_mode = %q, want wal", got)
	}
	if got := pragmaInt(t, db, "busy_timeout"); got != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", got)
	}
}

// busy_timeout is per-connection, so prove it applies to more than the first
// pooled connection (a single QueryRow only proves one).
func TestWritable_BusyTimeoutOnMultipleConnections(t *testing.T) {
	dsn, err := Writable(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	db := openProbe(t, dsn)
	ctx := context.Background()
	c1, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	c2, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	for i, c := range []*sql.Conn{c1, c2} {
		var bt int
		if err := c.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&bt); err != nil {
			t.Fatalf("conn %d: %v", i, err)
		}
		if bt != 5000 {
			t.Errorf("conn %d busy_timeout = %d, want 5000", i, bt)
		}
	}
}

// ReadOnly over a WAL DB created by Writable: read works, busy_timeout applies,
// journal_mode reads back without mutation, and writes are rejected.
func TestReadOnly_FromWritableDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ro.db")
	wdsn, err := Writable(path)
	if err != nil {
		t.Fatal(err)
	}
	w := openProbe(t, wdsn)
	if _, err := w.Exec(`CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Exec(`INSERT INTO t VALUES (1,'x')`); err != nil {
		t.Fatal(err)
	}
	w.Close()

	rdsn, err := ReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	r := openProbe(t, rdsn)
	var v string
	if err := r.QueryRow(`SELECT v FROM t WHERE id=1`).Scan(&v); err != nil {
		t.Fatalf("read: %v", err)
	}
	if v != "x" {
		t.Errorf("read %q, want x", v)
	}
	if got := pragmaInt(t, r, "busy_timeout"); got != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", got)
	}
	if got := pragmaStr(t, r, "journal_mode"); got != "wal" {
		t.Errorf("journal_mode = %q, want wal (read-only must not change it)", got)
	}
	if _, err := r.Exec(`INSERT INTO t VALUES (2,'y')`); !isReadOnlyErr(err) {
		t.Errorf("write through read-only handle: err = %v, want a readonly error", err)
	}
}

// ReadOnly over a plain DELETE-mode DB must NOT force WAL.
func TestReadOnly_FromDeleteModeDB(t *testing.T) {
	path := filepath.Join(t.TempDir(), "delete.db")
	abs, _ := filepath.Abs(path)
	plain, err := sql.Open("sqlite", "file:"+abs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := plain.Exec(`CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := plain.Exec(`INSERT INTO t VALUES (1,'x')`); err != nil {
		t.Fatal(err)
	}
	var pjm string
	plain.QueryRow("PRAGMA journal_mode").Scan(&pjm)
	plain.Close()
	if pjm != "delete" {
		t.Fatalf("precondition: plain DB journal_mode = %q, want delete", pjm)
	}

	rdsn, err := ReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	r := openProbe(t, rdsn)
	if got := pragmaStr(t, r, "journal_mode"); got != "delete" {
		t.Errorf("journal_mode = %q, want delete (ReadOnly must not force WAL)", got)
	}
	if got := pragmaInt(t, r, "busy_timeout"); got != 5000 {
		t.Errorf("busy_timeout = %d, want 5000", got)
	}
	var v string
	if err := r.QueryRow(`SELECT v FROM t WHERE id=1`).Scan(&v); err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, err := r.Exec(`INSERT INTO t VALUES (2,'y')`); !isReadOnlyErr(err) {
		t.Errorf("write through read-only handle: err = %v, want a readonly error", err)
	}
}

// busy_timeout per-connection check for ReadOnly too.
func TestReadOnly_BusyTimeoutOnMultipleConnections(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ro.db")
	wdsn, _ := Writable(path)
	w := openProbe(t, wdsn)
	if _, err := w.Exec(`CREATE TABLE t(id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	w.Close()
	rdsn, _ := ReadOnly(path)
	r := openProbe(t, rdsn)
	ctx := context.Background()
	c1, err := r.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	c2, err := r.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	for i, c := range []*sql.Conn{c1, c2} {
		var bt int
		if err := c.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&bt); err != nil {
			t.Fatalf("ro conn %d: %v", i, err)
		}
		if bt != 5000 {
			t.Errorf("ro conn %d busy_timeout = %d, want 5000", i, bt)
		}
	}
}

// Relative paths, paths with spaces, and paths containing `?` must all open
// correctly after absolute-path normalization (the file: URI must escape them).
func TestPathNormalization(t *testing.T) {
	for _, name := range []string{"rel.db", "dir with spaces/test db.sqlite", "question?mark.db"} {
		t.Run(name, func(t *testing.T) {
			tmp := t.TempDir()
			if dir := filepath.Dir(name); dir != "." {
				if err := os.MkdirAll(filepath.Join(tmp, dir), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			old, err := os.Getwd()
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chdir(tmp); err != nil {
				t.Fatal(err)
			}
			defer os.Chdir(old)

			wdsn, err := Writable(name)
			if err != nil {
				t.Fatal(err)
			}
			w := openProbe(t, wdsn)
			if _, err := w.Exec(`CREATE TABLE t(id INTEGER PRIMARY KEY)`); err != nil {
				t.Fatalf("create via Writable(%q): %v  dsn=%s", name, err, wdsn)
			}
			w.Close()
			if _, err := os.Stat(filepath.Join(tmp, name)); err != nil {
				t.Errorf("db file not created at expected path %q: %v", name, err)
			}

			rdsn, err := ReadOnly(name)
			if err != nil {
				t.Fatal(err)
			}
			r := openProbe(t, rdsn)
			if err := r.QueryRow(`SELECT count(*) FROM t`).Scan(new(int)); err != nil {
				t.Errorf("read via ReadOnly(%q): %v", name, err)
			}
			if _, err := r.Exec(`CREATE TABLE t2(x INTEGER)`); !isReadOnlyErr(err) {
				t.Errorf("write via ReadOnly(%q): err = %v, want a readonly error", name, err)
			}
		})
	}
}

// ReadOnly against a live WAL database with the writer still open (the online
// backup source shape): read succeeds, sees live commits, write is rejected.
func TestReadOnly_LiveWALWithWriterAlive(t *testing.T) {
	path := filepath.Join(t.TempDir(), "live.db")
	wdsn, _ := Writable(path)
	w := openProbe(t, wdsn) // stays open (t.Cleanup closes it)
	if _, err := w.Exec(`CREATE TABLE t(id INTEGER PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Exec(`INSERT INTO t VALUES (1,'first')`); err != nil {
		t.Fatal(err)
	}
	wConn, err := w.Conn(context.Background()) // hold a live conn so -shm stays mapped
	if err != nil {
		t.Fatal(err)
	}
	defer wConn.Close()

	rdsn, _ := ReadOnly(path)
	r := openProbe(t, rdsn)
	var v string
	if err := r.QueryRow(`SELECT v FROM t WHERE id=1`).Scan(&v); err != nil {
		t.Fatalf("read of live WAL DB failed: %v", err)
	}
	if _, err := w.Exec(`INSERT INTO t VALUES (2,'after')`); err != nil {
		t.Fatal(err)
	}
	var v2 string
	if err := r.QueryRow(`SELECT v FROM t WHERE id=2`).Scan(&v2); err != nil {
		t.Errorf("read-only did not see post-open commit: %v", err)
	} else if v2 != "after" {
		t.Errorf("post-open read = %q, want after", v2)
	}
	if _, err := r.Exec(`INSERT INTO t VALUES (3,'nope')`); !isReadOnlyErr(err) {
		t.Errorf("write through read-only handle: err = %v, want a readonly error", err)
	}
}

// foreign_keys is per-connection like busy_timeout (store-write Part 1): prove
// the DSN form reaches a second pooled connection, which a one-off Exec never
// did.
func TestWritable_ForeignKeysOnMultipleConnections(t *testing.T) {
	dsn, err := Writable(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	db := openProbe(t, dsn)
	ctx := context.Background()
	c1, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	c2, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	for i, c := range []*sql.Conn{c1, c2} {
		var fk int
		if err := c.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&fk); err != nil {
			t.Fatalf("conn %d: %v", i, err)
		}
		if fk != 1 {
			t.Errorf("conn %d foreign_keys = %d, want 1", i, fk)
		}
	}
}

// immediateProbeDSN is a second, independent handle on the same file — the
// shape of another process — with no busy wait, so a held write lock is
// reported at once instead of after five seconds.
func immediateProbeDSN(t *testing.T, path string) string {
	t.Helper()
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(0)")
	q.Set("_txlock", "immediate")
	u := url.URL{Scheme: "file", Path: abs, RawQuery: q.Encode()}
	return u.String()
}

func isBusyErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "locked") || strings.Contains(s, "busy")
}

// Writable's transactions take the write lock at BEGIN: a transaction that has
// written nothing yet already excludes another writer, so a later upgrade can
// never fail with the unretryable busy error a deferred transaction gets. The
// control shows the same probe succeeding against a deferred transaction.
func TestWritable_TransactionsBeginImmediate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "w.db")
	dsn, err := Writable(path)
	if err != nil {
		t.Fatal(err)
	}
	db := openProbe(t, dsn)
	if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	probe := openProbe(t, immediateProbeDSN(t, path))

	tx, err := db.Begin() // nothing written yet
	if err != nil {
		t.Fatal(err)
	}
	ptx, err := probe.Begin()
	if err == nil {
		_ = ptx.Rollback()
		t.Fatal("another writer could BEGIN IMMEDIATE while a Writable transaction was open: BEGIN is not immediate")
	}
	if !isBusyErr(err) {
		t.Fatalf("probe BEGIN error = %v, want a busy/locked error", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	ptx, err = probe.Begin()
	if err != nil {
		t.Fatalf("probe BEGIN after commit: %v", err)
	}
	_ = ptx.Rollback()

	// Control: a deferred transaction on the same file holds no write lock
	// until it writes, so the probe gets in.
	deferredDSN := strings.Replace(dsn, "_txlock=immediate", "_txlock=deferred", 1)
	if deferredDSN == dsn {
		t.Fatal("test setup: Writable DSN does not carry _txlock=immediate")
	}
	ddb := openProbe(t, deferredDSN)
	dtx, err := ddb.Begin()
	if err != nil {
		t.Fatal(err)
	}
	ptx, err = probe.Begin()
	if err != nil {
		t.Fatalf("control: probe BEGIN against a deferred transaction failed: %v", err)
	}
	_ = ptx.Rollback()
	_ = dtx.Rollback()
}

// journal_size_limit is per-connection too: prove the DSN form reaches a
// second pooled connection and carries the intended value.
func TestWritable_JournalSizeLimitOnMultipleConnections(t *testing.T) {
	dsn, err := Writable(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	db := openProbe(t, dsn)
	ctx := context.Background()
	c1, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	c2, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	for i, c := range []*sql.Conn{c1, c2} {
		var limit int64
		if err := c.QueryRowContext(ctx, "PRAGMA journal_size_limit").Scan(&limit); err != nil {
			t.Fatalf("conn %d: %v", i, err)
		}
		if limit != journalSizeLimitBytes {
			t.Errorf("conn %d journal_size_limit = %d, want %d", i, limit, journalSizeLimitBytes)
		}
	}
}

// With the limit set, a grown write-ahead log is truncated back under it
// when the log is next reset — the first write after a checkpoint has
// copied every frame back — where SQLite would otherwise keep the grown
// file for reuse. Uses a 64 KiB limit on a probe DSN so a small write
// grows past it.
func TestWritable_JournalSizeLimitTruncatesTheLogAfterCheckpoint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "w.db")
	dsn, err := Writable(path)
	if err != nil {
		t.Fatal(err)
	}
	const limit = 64 * 1024
	dsn = strings.Replace(dsn, "journal_size_limit%28"+itoa(journalSizeLimitBytes)+"%29", "journal_size_limit%28"+itoa(limit)+"%29", 1)
	if !strings.Contains(dsn, "journal_size_limit%28"+itoa(limit)+"%29") {
		t.Fatalf("test setup: could not lower the limit in %q", dsn)
	}
	db := openProbe(t, dsn)
	if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, body TEXT)`); err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("x", 4096)
	for i := 0; i < 200; i++ { // ~800 KiB through the log, well past 64 KiB
		if _, err := db.Exec(`INSERT INTO t (body) VALUES (?)`, body); err != nil {
			t.Fatal(err)
		}
	}
	wal := path + "-wal"
	grown, err := os.Stat(wal)
	if err != nil {
		t.Fatalf("stat wal: %v", err)
	}
	if grown.Size() <= limit {
		t.Fatalf("test setup: wal only %d bytes, want > %d", grown.Size(), limit)
	}
	if _, err := db.Exec(`PRAGMA wal_checkpoint(PASSIVE)`); err != nil {
		t.Fatal(err)
	}
	// The truncation happens on the reset, which the next writer performs
	// once the checkpoint has backfilled the whole log.
	if _, err := db.Exec(`INSERT INTO t (body) VALUES (?)`, "after"); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(wal)
	if err != nil {
		t.Fatalf("stat wal after checkpoint and reset: %v", err)
	}
	if after.Size() > limit {
		t.Fatalf("wal is %d bytes after a checkpoint and reset, want <= the %d limit", after.Size(), limit)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
