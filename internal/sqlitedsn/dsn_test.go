package sqlitedsn

import (
	"context"
	"database/sql"
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
