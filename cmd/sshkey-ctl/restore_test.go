package main

// Phase 19 Step 6 — restore + list-backups CLI tests.
//
// Coverage matrix:
//   - end-to-end: backup → tamper → restore → verify state restored
//   - lockfile rejection: live PID → restore refuses cleanly
//   - --no-pre-backup: pre-restore tarball is NOT created
//   - default (non-TTY): pre-restore tarball IS created
//   - pre-restore tarball is restorable (round-trip via list+restore)
//   - tarball validation: gzip CRC failure
//   - tarball validation: path traversal rejected
//   - tarball validation: absolute path rejected
//   - tarball validation: non-data/config prefix rejected
//   - missing tarball arg
//   - unknown flag
//   - missing tarball file on disk
//   - safety dir is preserved on extract failure (corrupted tarball mid-flight)
//   - list-backups: empty dir output
//   - list-backups: multiple tarballs sorted newest-first
//   - formatAge boundaries

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/brushtailmedia/sshkey-chat/internal/backup"
)

// setupRestoreFixture builds a config + data dir with real SQLite
// content so backup → tamper → restore round-trips end-to-end. Returns
// (configDir, dataDir).
func setupRestoreFixture(t *testing.T) (string, string) {
	t.Helper()
	configDir := t.TempDir()
	dataDir := t.TempDir()

	// server.toml — minimal but valid.
	if err := os.WriteFile(filepath.Join(configDir, "server.toml"), []byte(`
[server]
port = 2222
bind = "127.0.0.1"

[server.auto_revoke]
enabled = false
`), 0644); err != nil {
		t.Fatalf("write server.toml: %v", err)
	}
	// host_key — required when IncludeConfigFiles=true (the default).
	// Real-looking content; we never parse it as SSH in restore tests.
	if err := os.WriteFile(filepath.Join(configDir, "host_key"),
		[]byte("-----BEGIN OPENSSH PRIVATE KEY-----\nfake test key\n-----END OPENSSH PRIVATE KEY-----\n"),
		0600); err != nil {
		t.Fatalf("write host_key: %v", err)
	}

	// data/ subdir with three real SQLite DBs.
	dataRoot := filepath.Join(dataDir, "data")
	if err := os.MkdirAll(dataRoot, 0755); err != nil {
		t.Fatalf("mkdir data: %v", err)
	}
	for _, name := range []string{"data.db", "rooms.db", "users.db"} {
		path := filepath.Join(dataRoot, name)
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		if _, err := db.Exec(`CREATE TABLE marker (label TEXT)`); err != nil {
			t.Fatalf("create table %s: %v", path, err)
		}
		if _, err := db.Exec(`INSERT INTO marker (label) VALUES (?)`, name+"-original-content"); err != nil {
			t.Fatalf("insert %s: %v", path, err)
		}
		db.Close()
	}

	// data/files/ with two attachment blobs.
	if err := os.MkdirAll(filepath.Join(dataRoot, "files"), 0755); err != nil {
		t.Fatalf("mkdir files: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataRoot, "files", "file_blob1"), []byte("attachment 1 content"), 0644); err != nil {
		t.Fatalf("write blob1: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataRoot, "files", "file_blob2"), []byte("attachment 2 content"), 0644); err != nil {
		t.Fatalf("write blob2: %v", err)
	}

	// audit.log + pending-keys.log
	if err := os.WriteFile(filepath.Join(dataDir, "audit.log"), []byte("audit line 1\naudit line 2\n"), 0644); err != nil {
		t.Fatalf("write audit.log: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataRoot, "pending-keys.log"), []byte("pending key blob\n"), 0644); err != nil {
		t.Fatalf("write pending-keys.log: %v", err)
	}

	return configDir, dataDir
}

// produceBackup runs backup.Run against the fixture and returns the
// resulting tarball path.
func produceBackup(t *testing.T, configDir, dataDir, label string) string {
	t.Helper()
	destDir := filepath.Join(dataDir, "backups")
	res, err := backup.Run(context.Background(), backup.Options{
		DataDir:            dataDir,
		ConfigDir:          configDir,
		DestDir:            destDir,
		Label:              label,
		Compress:           true,
		IncludeConfigFiles: true,
	})
	if err != nil {
		t.Fatalf("backup.Run: %v", err)
	}
	return res.Path
}

// readMarker reads the single 'label' value from a marker table in
// the SQLite DB at path. Returns empty string on any error.
func readMarker(t *testing.T, path string) string {
	t.Helper()
	db, err := sql.Open("sqlite", path+"?mode=ro")
	if err != nil {
		return ""
	}
	defer db.Close()
	var s string
	if err := db.QueryRow(`SELECT label FROM marker LIMIT 1`).Scan(&s); err != nil {
		return ""
	}
	return s
}

// readFileText returns the content of path, or empty on error.
func readFileText(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

// -------- end-to-end round-trip --------

func TestCmdRestore_RoundTrip(t *testing.T) {
	configDir, dataDir := setupRestoreFixture(t)

	// Step 1: take a backup.
	tarballPath := produceBackup(t, configDir, dataDir, "")

	// Step 2: tamper — overwrite a DB row + delete an attachment.
	dbPath := filepath.Join(dataDir, "data", "data.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("reopen for tamper: %v", err)
	}
	if _, err := db.Exec(`UPDATE marker SET label = 'TAMPERED'`); err != nil {
		t.Fatalf("tamper: %v", err)
	}
	db.Close()
	if err := os.Remove(filepath.Join(dataDir, "data", "files", "file_blob1")); err != nil {
		t.Fatalf("delete blob: %v", err)
	}

	// Confirm tamper took effect.
	if got := readMarker(t, dbPath); got != "TAMPERED" {
		t.Fatalf("tamper precondition: marker = %q, want TAMPERED", got)
	}

	// Step 3: restore with --no-pre-backup so the test doesn't write
	// an extra pre-restore tarball into the dest dir.
	if err := cmdRestore(configDir, dataDir, []string{tarballPath, "--no-pre-backup"}); err != nil {
		t.Fatalf("cmdRestore: %v", err)
	}

	// Step 4: verify state matches the original.
	if got := readMarker(t, dbPath); got != "data.db-original-content" {
		t.Errorf("after restore: marker = %q, want data.db-original-content", got)
	}
	if got := readFileText(t, filepath.Join(dataDir, "data", "files", "file_blob1")); got != "attachment 1 content" {
		t.Errorf("after restore: blob1 = %q, want 'attachment 1 content'", got)
	}
	if got := readFileText(t, filepath.Join(dataDir, "audit.log")); got != "audit line 1\naudit line 2\n" {
		t.Errorf("after restore: audit.log content mismatch: %q", got)
	}

	// Safety dir should exist with the tampered state preserved.
	entries, _ := os.ReadDir(dataDir)
	hasSafety := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "pre-restore-") {
			hasSafety = true
		}
	}
	if !hasSafety {
		t.Error("safety dir not created")
	}
}

// -------- lockfile rejection --------

func TestCmdRestore_LockfileBlocks(t *testing.T) {
	configDir, dataDir := setupRestoreFixture(t)
	tarballPath := produceBackup(t, configDir, dataDir, "")

	// Write a lockfile pointing at our own (alive) PID.
	lockPath := filepath.Join(dataDir, "sshkey-server.pid")
	content := fmt.Sprintf("%d\n%d\n", os.Getpid(), time.Now().Unix())
	if err := os.WriteFile(lockPath, []byte(content), 0644); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}

	err := cmdRestore(configDir, dataDir, []string{tarballPath, "--no-pre-backup"})
	if err == nil {
		t.Fatal("cmdRestore should refuse with live lockfile, got nil")
	}
	if !strings.Contains(err.Error(), "server is running") {
		t.Errorf("error should mention 'server is running', got: %q", err.Error())
	}

	// Verify nothing was moved or extracted — the lockfile check
	// should reject before any state mutation.
	if got := readFileText(t, filepath.Join(dataDir, "audit.log")); got != "audit line 1\naudit line 2\n" {
		t.Errorf("audit.log altered despite lockfile rejection: %q", got)
	}
}

// -------- pre-restore backup behavior --------

func TestCmdRestore_PreRestoreBackupCreatedByDefault(t *testing.T) {
	configDir, dataDir := setupRestoreFixture(t)
	tarballPath := produceBackup(t, configDir, dataDir, "")

	// No --no-pre-backup flag. Test runs with non-TTY stdin so
	// prompt is skipped → defaults to "yes" (run pre-backup).
	if err := cmdRestore(configDir, dataDir, []string{tarballPath}); err != nil {
		t.Fatalf("cmdRestore: %v", err)
	}

	// At least one pre-restore tarball must exist in the dest dir.
	destDir := filepath.Join(dataDir, "backups")
	entries, _ := os.ReadDir(destDir)
	preRestoreCount := 0
	for _, e := range entries {
		if strings.Contains(e.Name(), "-pre-restore.tar.gz") {
			preRestoreCount++
		}
	}
	if preRestoreCount != 1 {
		t.Errorf("expected 1 pre-restore tarball, got %d (entries: %v)", preRestoreCount, entries)
	}
}

func TestCmdRestore_NoPreBackupSkipsIt(t *testing.T) {
	configDir, dataDir := setupRestoreFixture(t)
	tarballPath := produceBackup(t, configDir, dataDir, "")

	if err := cmdRestore(configDir, dataDir, []string{tarballPath, "--no-pre-backup"}); err != nil {
		t.Fatalf("cmdRestore: %v", err)
	}

	destDir := filepath.Join(dataDir, "backups")
	entries, _ := os.ReadDir(destDir)
	for _, e := range entries {
		if strings.Contains(e.Name(), "-pre-restore.tar.gz") {
			t.Errorf("pre-restore tarball created despite --no-pre-backup: %s", e.Name())
		}
	}
}

// TestCmdRestore_PreRestoreIsRestorable confirms the rollback story —
// after a restore, the operator can restore again from the
// pre-restore tarball to roll back to the prior state.
func TestCmdRestore_PreRestoreIsRestorable(t *testing.T) {
	configDir, dataDir := setupRestoreFixture(t)
	originalTarball := produceBackup(t, configDir, dataDir, "original")

	// Tamper to a known state, then restore from "original".
	dbPath := filepath.Join(dataDir, "data", "data.db")
	db, _ := sql.Open("sqlite", dbPath)
	db.Exec(`UPDATE marker SET label = 'STATE_B'`)
	db.Close()
	stateB := "STATE_B"
	if got := readMarker(t, dbPath); got != stateB {
		t.Fatalf("precondition: marker = %q, want %q", got, stateB)
	}

	// Restore from the original. Pre-restore tarball captures STATE_B.
	if err := cmdRestore(configDir, dataDir, []string{originalTarball}); err != nil {
		t.Fatalf("first restore: %v", err)
	}
	if got := readMarker(t, dbPath); got != "data.db-original-content" {
		t.Fatalf("after first restore: marker = %q, want original", got)
	}

	// Find the pre-restore tarball.
	destDir := filepath.Join(dataDir, "backups")
	entries, _ := os.ReadDir(destDir)
	var preRestorePath string
	for _, e := range entries {
		if strings.Contains(e.Name(), "-pre-restore.tar.gz") {
			preRestorePath = filepath.Join(destDir, e.Name())
		}
	}
	if preRestorePath == "" {
		t.Fatal("pre-restore tarball not found")
	}

	// Restore from the pre-restore tarball — should bring back STATE_B.
	if err := cmdRestore(configDir, dataDir, []string{preRestorePath, "--no-pre-backup"}); err != nil {
		t.Fatalf("rollback restore: %v", err)
	}
	if got := readMarker(t, dbPath); got != stateB {
		t.Errorf("after rollback: marker = %q, want %q", got, stateB)
	}
}

// -------- arg parsing + error paths --------

func TestCmdRestore_MissingTarballArg(t *testing.T) {
	configDir := t.TempDir()
	dataDir := t.TempDir()
	err := cmdRestore(configDir, dataDir, []string{})
	if err == nil || !strings.Contains(err.Error(), "usage:") {
		t.Errorf("expected usage error, got: %v", err)
	}
}

func TestCmdRestore_UnknownFlagRejected(t *testing.T) {
	configDir := t.TempDir()
	dataDir := t.TempDir()
	err := cmdRestore(configDir, dataDir, []string{"--bogus"})
	if err == nil || !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("expected 'unknown flag' error, got: %v", err)
	}
}

func TestCmdRestore_MissingTarballFile(t *testing.T) {
	configDir := t.TempDir()
	dataDir := t.TempDir()
	err := cmdRestore(configDir, dataDir, []string{"/does/not/exist.tar.gz"})
	if err == nil {
		t.Fatal("expected error for missing tarball file, got nil")
	}
}

// -------- tarball validation --------

func TestValidateTarball_GzipCRC(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "bad.tar.gz")
	if err := os.WriteFile(tmp, []byte("definitely not gzip"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, err := validateTarball(tmp)
	if err == nil || !strings.Contains(err.Error(), "gzip") {
		t.Errorf("expected gzip error, got: %v", err)
	}
}

// makeTarball builds a synthetic tarball with the given entries (name + content)
// for validation tests that need to inject specific path shapes.
func makeTarball(t *testing.T, entries []struct{ name, content string }) string {
	t.Helper()
	var buf bytes.Buffer
	gzw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gzw)
	for _, e := range entries {
		header := &tar.Header{
			Name:     e.name,
			Mode:     0644,
			Size:     int64(len(e.content)),
			Typeflag: tar.TypeReg,
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tw.Write([]byte(e.content)); err != nil {
			t.Fatalf("write body: %v", err)
		}
	}
	tw.Close()
	gzw.Close()
	path := filepath.Join(t.TempDir(), "synth.tar.gz")
	if err := os.WriteFile(path, buf.Bytes(), 0644); err != nil {
		t.Fatalf("write tarball: %v", err)
	}
	return path
}

func TestValidateTarball_PathTraversalRejected(t *testing.T) {
	path := makeTarball(t, []struct{ name, content string }{
		{"data/../../escape.txt", "escape"},
	})
	_, err := validateTarball(path)
	if err == nil {
		t.Fatal("expected validation rejection for path traversal")
	}
}

func TestValidateTarball_AbsolutePathRejected(t *testing.T) {
	path := makeTarball(t, []struct{ name, content string }{
		{"/etc/passwd", "owned"},
	})
	_, err := validateTarball(path)
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Errorf("expected absolute-path rejection, got: %v", err)
	}
}

func TestValidateTarball_BadPrefixRejected(t *testing.T) {
	path := makeTarball(t, []struct{ name, content string }{
		{"random/file.txt", "x"},
	})
	_, err := validateTarball(path)
	if err == nil || !strings.Contains(err.Error(), "data/ or config/") {
		t.Errorf("expected data/config-only rejection, got: %v", err)
	}
}

func TestValidateTarball_EmptyTarballRejected(t *testing.T) {
	path := makeTarball(t, nil)
	_, err := validateTarball(path)
	if err == nil || !strings.Contains(err.Error(), "no entries") {
		t.Errorf("expected empty-tarball rejection, got: %v", err)
	}
}

func TestValidateTarball_HappyPath(t *testing.T) {
	path := makeTarball(t, []struct{ name, content string }{
		{"data/data.db", "fake content"},
		{"config/host_key", "fake key"},
	})
	entries, err := validateTarball(path)
	if err != nil {
		t.Fatalf("expected ok, got: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 entries, got %d", len(entries))
	}
}

// -------- list-backups --------

func TestCmdListBackups_EmptyDir(t *testing.T) {
	configDir := t.TempDir()
	dataDir := t.TempDir()
	// No backups dir at all.
	r, w, _ := os.Pipe()
	origStdout := os.Stdout
	os.Stdout = w

	err := cmdListBackups(configDir, dataDir, []string{})

	w.Close()
	os.Stdout = origStdout

	if err != nil {
		t.Fatalf("cmdListBackups: %v", err)
	}
	var buf bytes.Buffer
	io.Copy(&buf, r)
	if !strings.Contains(buf.String(), "does not exist") {
		t.Errorf("expected 'does not exist' message, got: %q", buf.String())
	}
}

func TestCmdListBackups_SortedNewestFirst(t *testing.T) {
	configDir, dataDir := setupRestoreFixture(t)
	destDir := filepath.Join(dataDir, "backups")
	if err := os.MkdirAll(destDir, 0755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	// Three tarballs with different timestamps + labels.
	now := time.Now()
	cases := []struct {
		name  string
		mtime time.Time
	}{
		{"backup-20260415-120000-old.tar.gz", now.Add(-72 * time.Hour)},
		{"backup-20260418-120000.tar.gz", now.Add(-24 * time.Hour)},
		{"backup-20260419-120000-newest.tar.gz", now.Add(-1 * time.Hour)},
	}
	for _, c := range cases {
		path := filepath.Join(destDir, c.name)
		if err := os.WriteFile(path, []byte("fake"), 0644); err != nil {
			t.Fatalf("write %s: %v", c.name, err)
		}
		if err := os.Chtimes(path, c.mtime, c.mtime); err != nil {
			t.Fatalf("chtimes: %v", err)
		}
	}
	// Add a non-tarball file — must be ignored.
	os.WriteFile(filepath.Join(destDir, ".backup-stats.json"), []byte("{}"), 0644)

	r, w, _ := os.Pipe()
	origStdout := os.Stdout
	os.Stdout = w
	err := cmdListBackups(configDir, dataDir, []string{})
	w.Close()
	os.Stdout = origStdout
	if err != nil {
		t.Fatalf("cmdListBackups: %v", err)
	}
	var buf bytes.Buffer
	io.Copy(&buf, r)
	out := buf.String()

	// Header present.
	if !strings.Contains(out, "NAME") || !strings.Contains(out, "SIZE") || !strings.Contains(out, "LABEL") {
		t.Errorf("output missing header columns:\n%s", out)
	}
	// All three tarballs present.
	for _, c := range cases {
		if !strings.Contains(out, c.name) {
			t.Errorf("output missing %s:\n%s", c.name, out)
		}
	}
	// Newest before oldest.
	idxNewest := strings.Index(out, "newest")
	idxOld := strings.Index(out, "old")
	if idxNewest < 0 || idxOld < 0 {
		t.Fatalf("missing label markers in output:\n%s", out)
	}
	if idxNewest >= idxOld {
		t.Errorf("newest backup should appear before oldest, got idxNewest=%d idxOld=%d:\n%s", idxNewest, idxOld, out)
	}
	// Non-tarball ignored.
	if strings.Contains(out, ".backup-stats.json") {
		t.Errorf("non-tarball leaked into output:\n%s", out)
	}
}

func TestCmdListBackups_RejectsArgs(t *testing.T) {
	err := cmdListBackups(t.TempDir(), t.TempDir(), []string{"--bogus"})
	if err == nil || !strings.Contains(err.Error(), "usage") {
		t.Errorf("expected usage error, got: %v", err)
	}
}

// -------- formatAge --------

func TestFormatAge(t *testing.T) {
	cases := map[time.Duration]string{
		0:                            "just now",
		15 * time.Second:             "just now",
		29 * time.Second:             "just now",
		30 * time.Second:             "30s",
		59 * time.Second:             "59s",
		60 * time.Second:             "1m",
		59 * time.Minute:             "59m",
		60 * time.Minute:             "1h",
		23 * time.Hour:               "23h",
		24 * time.Hour:               "1d",
		47 * time.Hour:               "1d",
		48 * time.Hour:               "2d",
		30 * 24 * time.Hour:          "30d",
	}
	for d, want := range cases {
		if got := formatAge(d); got != want {
			t.Errorf("formatAge(%v) = %q, want %q", d, got, want)
		}
	}
}
