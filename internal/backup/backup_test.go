package backup

// Phase 19 Step 3 — backup package unit tests.
//
// Coverage matrix:
//   - ValidateLabel: empty accepted, happy-path labels accepted,
//     whitespace / dot / slash / length-33 / unicode rejected
//   - Run: happy path over a seeded fixture (DBs + blobs + aux files)
//   - Run: tarball filename includes timestamp + label
//   - Run: tarball filename omits label when label is empty
//   - Run: tarball contents match expected layout
//   - Run: integrity_check failure aborts with no tarball left behind
//   - Run: missing DataDir → error
//   - Run: missing required host_key (with IncludeConfigFiles) → error
//   - Run: absent optional aux file (audit.log missing) → skipped cleanly
//   - Run: temp-file + staging dir cleaned up on failure
//   - Run: NowFn injection produces deterministic timestamps
//   - isContextDB: prefix matching
//
// Tests use real SQLite files (opened via database/sql + modernc/sqlite)
// so the Online Backup API path is exercised end-to-end, not mocked.
// Deterministic time via NowFn keeps filename assertions stable.

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

// -------- ValidateLabel --------

func TestValidateLabel_Empty(t *testing.T) {
	if err := ValidateLabel(""); err != nil {
		t.Errorf("empty label should be accepted, got: %v", err)
	}
}

func TestValidateLabel_Accepts(t *testing.T) {
	cases := []string{
		"nightly",
		"pre-upgrade",
		"monthly_2026-04",
		"abc",
		"X",
		strings.Repeat("a", 32), // exact length cap
		"2026-04-19",
		"ABC-def_123",
	}
	for _, c := range cases {
		t.Run(c, func(t *testing.T) {
			if err := ValidateLabel(c); err != nil {
				t.Errorf("label %q should be accepted, got: %v", c, err)
			}
		})
	}
}

func TestValidateLabel_Rejects(t *testing.T) {
	cases := map[string]string{
		"has space":                  "space",
		"has.dot":                    "dot",
		"has/slash":                  "slash",
		"../traversal":               "traversal",
		strings.Repeat("a", 33):      "length 33",
		"café":                        "unicode",
		"emoji-🎉":                    "emoji",
		"with\ttab":                  "tab",
		"newline\nbad":               "newline",
	}
	for label, desc := range cases {
		t.Run(desc, func(t *testing.T) {
			err := ValidateLabel(label)
			if err == nil {
				t.Errorf("label %q should be rejected", label)
			}
			if !strings.Contains(err.Error(), "invalid label") {
				t.Errorf("error should mention 'invalid label', got: %q", err.Error())
			}
		})
	}
}

// -------- Run: helpers + fixtures --------

// fixture builds a data/config directory structure mimicking a real
// server. Returns dataDir, configDir, destDir.
type fixture struct {
	t         *testing.T
	dataDir   string
	configDir string
	destDir   string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	fx := &fixture{
		t:         t,
		dataDir:   filepath.Join(root, "data-root"),
		configDir: filepath.Join(root, "config-root"),
		destDir:   filepath.Join(root, "dest"),
	}
	mustMkdirAll(t, filepath.Join(fx.dataDir, "data", "files"))
	mustMkdirAll(t, fx.configDir)
	mustMkdirAll(t, fx.destDir)
	return fx
}

// createSQLiteFile makes a minimal but valid SQLite DB at path with
// one table and one row. Enough that Online Backup + PRAGMA
// integrity_check both succeed.
func createSQLiteFile(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO t (v) VALUES ('hello')`); err != nil {
		t.Fatalf("insert: %v", err)
	}
}

// corruptFile writes garbage bytes into a supposed SQLite file. The
// Online Backup API will still "succeed" on open (since NewBackup
// doesn't validate page structure immediately) but integrity_check
// on the backup copy must detect corruption.
func corruptFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("not a sqlite database at all"), 0644); err != nil {
		t.Fatalf("corrupt %s: %v", path, err)
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatalf("mkdir %s: %v", path, err)
	}
}

func mustWriteFile(t *testing.T, path string, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// (fx *fixture) seedAllArtefacts creates the full set of files Run
// should pick up: 3 core DBs, 2 context DBs, 2 attachment blobs, and
// all 4 aux files (audit.log, pending-keys.log, host_key, server.toml).
func (fx *fixture) seedAllArtefacts() {
	t := fx.t
	// Core DBs
	createSQLiteFile(t, filepath.Join(fx.dataDir, "data", "data.db"))
	createSQLiteFile(t, filepath.Join(fx.dataDir, "data", "rooms.db"))
	createSQLiteFile(t, filepath.Join(fx.dataDir, "data", "users.db"))
	// Context DBs
	createSQLiteFile(t, filepath.Join(fx.dataDir, "data", "room-abc123.db"))
	createSQLiteFile(t, filepath.Join(fx.dataDir, "data", "group-xyz789.db"))
	// Attachment blobs
	mustWriteFile(t, filepath.Join(fx.dataDir, "data", "files", "file_blob1"), "blob1 content", 0644)
	mustWriteFile(t, filepath.Join(fx.dataDir, "data", "files", "file_blob2"), "blob2 content", 0644)
	// Aux files
	mustWriteFile(t, filepath.Join(fx.dataDir, "audit.log"), "audit line 1\n", 0644)
	mustWriteFile(t, filepath.Join(fx.dataDir, "data", "pending-keys.log"), "pending key 1\n", 0644)
	mustWriteFile(t, filepath.Join(fx.configDir, "host_key"), "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n", 0600)
	mustWriteFile(t, filepath.Join(fx.configDir, "server.toml"), "[server]\nport = 2222\n", 0644)
}

// fixedNow returns a NowFn that always reports 2026-04-19 14:30:22 UTC.
// Pins filenames to a known value so tests can assert on them.
func fixedNow() func() time.Time {
	fixed := time.Date(2026, 4, 19, 14, 30, 22, 0, time.UTC)
	return func() time.Time { return fixed }
}

// readTarballEntries opens a gzip+tar file and returns the entry names
// in the order they appear. Convenience for layout assertions.
func readTarballEntries(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open tarball: %v", err)
	}
	defer f.Close()
	gzr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		names = append(names, h.Name)
	}
	return names
}

// -------- Run: happy path --------

func TestRun_HappyPath(t *testing.T) {
	fx := newFixture(t)
	fx.seedAllArtefacts()

	opts := Options{
		DataDir:            fx.dataDir,
		ConfigDir:          fx.configDir,
		DestDir:            fx.destDir,
		Compress:           true,
		IncludeConfigFiles: true,
		NowFn:              fixedNow(),
	}
	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if res.CoreDBs != 3 {
		t.Errorf("CoreDBs = %d, want 3", res.CoreDBs)
	}
	if res.ContextDBs != 2 {
		t.Errorf("ContextDBs = %d, want 2", res.ContextDBs)
	}
	if res.Attachments != 2 {
		t.Errorf("Attachments = %d, want 2", res.Attachments)
	}
	if res.AuxFiles != 4 {
		t.Errorf("AuxFiles = %d (audit + pending + host_key + server.toml), want 4", res.AuxFiles)
	}
	if res.Bytes <= 0 {
		t.Errorf("Bytes = %d, want > 0", res.Bytes)
	}
	if _, err := os.Stat(res.Path); err != nil {
		t.Errorf("tarball missing at %s: %v", res.Path, err)
	}

	expected := []string{
		"data/data.db",
		"data/rooms.db",
		"data/users.db",
		"data/room-abc123.db",
		"data/group-xyz789.db",
		"data/files/file_blob1",
		"data/files/file_blob2",
		"data/audit.log",
		"data/pending-keys.log",
		"config/host_key",
		"config/server.toml",
	}
	got := readTarballEntries(t, res.Path)
	sort.Strings(expected)
	gotSorted := make([]string, len(got))
	copy(gotSorted, got)
	sort.Strings(gotSorted)
	if !sliceEq(expected, gotSorted) {
		t.Errorf("tarball entries differ\nexpected (sorted): %v\ngot (sorted): %v", expected, gotSorted)
	}
}

// -------- Run: filename shape --------

func TestRun_FilenameIncludesLabel(t *testing.T) {
	fx := newFixture(t)
	fx.seedAllArtefacts()

	opts := Options{
		DataDir:            fx.dataDir,
		ConfigDir:          fx.configDir,
		DestDir:            fx.destDir,
		Label:              "pre-upgrade",
		Compress:           true,
		IncludeConfigFiles: true,
		NowFn:              fixedNow(),
	}
	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	wantName := "backup-20260419-143022-pre-upgrade.tar.gz"
	if filepath.Base(res.Path) != wantName {
		t.Errorf("filename = %q, want %q", filepath.Base(res.Path), wantName)
	}
}

func TestRun_FilenameOmitsLabelWhenEmpty(t *testing.T) {
	fx := newFixture(t)
	fx.seedAllArtefacts()

	opts := Options{
		DataDir:            fx.dataDir,
		ConfigDir:          fx.configDir,
		DestDir:            fx.destDir,
		Compress:           true,
		IncludeConfigFiles: true,
		NowFn:              fixedNow(),
	}
	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	wantName := "backup-20260419-143022.tar.gz"
	if filepath.Base(res.Path) != wantName {
		t.Errorf("filename = %q, want %q", filepath.Base(res.Path), wantName)
	}
}

// -------- Run: config files opt-out --------

func TestRun_ExcludeConfigFiles(t *testing.T) {
	fx := newFixture(t)
	fx.seedAllArtefacts()

	opts := Options{
		DataDir:            fx.dataDir,
		DestDir:            fx.destDir,
		Compress:           true,
		IncludeConfigFiles: false,
		NowFn:              fixedNow(),
	}
	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// AuxFiles should now be just audit.log + pending-keys.log (no host_key, no server.toml)
	if res.AuxFiles != 2 {
		t.Errorf("AuxFiles = %d, want 2 (no config files)", res.AuxFiles)
	}
	got := readTarballEntries(t, res.Path)
	for _, entry := range got {
		if strings.HasPrefix(entry, "config/") {
			t.Errorf("tarball should not contain config/ entries when IncludeConfigFiles=false, got: %s", entry)
		}
	}
}

// -------- Run: integrity check failure --------

func TestRun_IntegrityCheckFailureAborts(t *testing.T) {
	fx := newFixture(t)
	fx.seedAllArtefacts()
	// Corrupt data.db so the Online Backup copy will fail integrity.
	corruptFile(t, filepath.Join(fx.dataDir, "data", "data.db"))

	opts := Options{
		DataDir:            fx.dataDir,
		ConfigDir:          fx.configDir,
		DestDir:            fx.destDir,
		Compress:           true,
		IncludeConfigFiles: true,
		NowFn:              fixedNow(),
	}
	_, err := Run(context.Background(), opts)
	if err == nil {
		t.Fatal("Run should fail when source DB is corrupt, got nil")
	}
	// No tarball should be on disk.
	entries, _ := os.ReadDir(fx.destDir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tar.gz") {
			t.Errorf("tarball leaked to disk after failure: %s", e.Name())
		}
		if strings.HasSuffix(e.Name(), ".tar.gz.tmp") {
			t.Errorf("temp tarball leaked: %s", e.Name())
		}
		if strings.HasSuffix(e.Name(), ".work") {
			t.Errorf("staging dir leaked: %s", e.Name())
		}
	}
}

// -------- Run: required config file missing --------

func TestRun_MissingHostKeyIsFatal(t *testing.T) {
	fx := newFixture(t)
	fx.seedAllArtefacts()
	// Remove host_key — IncludeConfigFiles requires it.
	if err := os.Remove(filepath.Join(fx.configDir, "host_key")); err != nil {
		t.Fatalf("remove host_key: %v", err)
	}

	opts := Options{
		DataDir:            fx.dataDir,
		ConfigDir:          fx.configDir,
		DestDir:            fx.destDir,
		Compress:           true,
		IncludeConfigFiles: true,
		NowFn:              fixedNow(),
	}
	_, err := Run(context.Background(), opts)
	if err == nil {
		t.Fatal("Run should fail when required config file missing, got nil")
	}
	if !strings.Contains(err.Error(), "host_key") {
		t.Errorf("error should mention host_key, got: %q", err.Error())
	}
}

// -------- Run: absent optional aux file is skipped --------

func TestRun_MissingOptionalAuxFilesSkippedCleanly(t *testing.T) {
	fx := newFixture(t)
	fx.seedAllArtefacts()
	// Remove both optional files — run should succeed.
	os.Remove(filepath.Join(fx.dataDir, "audit.log"))
	os.Remove(filepath.Join(fx.dataDir, "data", "pending-keys.log"))

	opts := Options{
		DataDir:            fx.dataDir,
		ConfigDir:          fx.configDir,
		DestDir:            fx.destDir,
		Compress:           true,
		IncludeConfigFiles: true,
		NowFn:              fixedNow(),
	}
	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run should succeed with missing optional aux files, got: %v", err)
	}
	// AuxFiles should now be just host_key + server.toml (2).
	if res.AuxFiles != 2 {
		t.Errorf("AuxFiles = %d, want 2 (host_key + server.toml only)", res.AuxFiles)
	}
}

// -------- Run: validation --------

func TestRun_MissingDataDir(t *testing.T) {
	fx := newFixture(t)
	_, err := Run(context.Background(), Options{DestDir: fx.destDir})
	if err == nil {
		t.Fatal("Run with empty DataDir should fail, got nil")
	}
	if !strings.Contains(err.Error(), "DataDir") {
		t.Errorf("error should mention DataDir, got: %q", err.Error())
	}
}

func TestRun_MissingDestDir(t *testing.T) {
	fx := newFixture(t)
	_, err := Run(context.Background(), Options{DataDir: fx.dataDir})
	if err == nil {
		t.Fatal("Run with empty DestDir should fail, got nil")
	}
	if !strings.Contains(err.Error(), "DestDir") {
		t.Errorf("error should mention DestDir, got: %q", err.Error())
	}
}

func TestRun_BadLabelRejected(t *testing.T) {
	fx := newFixture(t)
	fx.seedAllArtefacts()

	opts := Options{
		DataDir:   fx.dataDir,
		ConfigDir: fx.configDir,
		DestDir:   fx.destDir,
		Label:     "bad/label",
		NowFn:     fixedNow(),
	}
	_, err := Run(context.Background(), opts)
	if err == nil {
		t.Fatal("Run with bad label should fail, got nil")
	}
	if !strings.Contains(err.Error(), "invalid label") {
		t.Errorf("error should mention 'invalid label', got: %q", err.Error())
	}
}

// -------- Run: context cancellation --------

func TestRun_ContextCancellation(t *testing.T) {
	fx := newFixture(t)
	fx.seedAllArtefacts()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	opts := Options{
		DataDir:            fx.dataDir,
		ConfigDir:          fx.configDir,
		DestDir:            fx.destDir,
		Compress:           true,
		IncludeConfigFiles: true,
		NowFn:              fixedNow(),
	}
	_, err := Run(ctx, opts)
	if err == nil {
		t.Fatal("Run with cancelled ctx should fail, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error should wrap context.Canceled, got: %v", err)
	}
}

// -------- Run: compressed vs uncompressed --------

func TestRun_Uncompressed(t *testing.T) {
	fx := newFixture(t)
	fx.seedAllArtefacts()

	opts := Options{
		DataDir:            fx.dataDir,
		ConfigDir:          fx.configDir,
		DestDir:            fx.destDir,
		Compress:           false,
		IncludeConfigFiles: true,
		NowFn:              fixedNow(),
	}
	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run uncompressed: %v", err)
	}
	// Extension stays .tar.gz per our naming convention, even when
	// uncompressed — operators expect consistency and gzip is the
	// common case. If the tarball isn't actually gzipped that's a
	// caller responsibility to know about.
	if !strings.HasSuffix(res.Path, ".tar.gz") {
		t.Errorf("path = %q, want .tar.gz suffix", res.Path)
	}
	// Verify we can read it as a raw tar (no gzip layer).
	f, err := os.Open(res.Path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	tr := tar.NewReader(f)
	count := 0
	for {
		_, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		count++
	}
	if count == 0 {
		t.Error("uncompressed tarball read produced zero entries")
	}
}

// -------- Run: round-trip data integrity --------

// TestRun_DBDataSurvivesRoundTrip verifies that data inserted into a
// source DB is readable after extraction from the backup tarball.
// Strongest assertion that the Online Backup API path is actually
// producing real snapshots, not empty files.
func TestRun_DBDataSurvivesRoundTrip(t *testing.T) {
	fx := newFixture(t)

	// Seed data.db with a known row so we can verify later.
	dbPath := filepath.Join(fx.dataDir, "data", "data.db")
	createSQLiteFile(t, dbPath)
	// Add a second row with distinctive content.
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO t (v) VALUES ('round-trip-marker')`); err != nil {
		t.Fatalf("insert: %v", err)
	}
	db.Close()

	// Minimal rooms.db + users.db so Run doesn't complain about
	// missing core DBs (it just skips missing, but we want all three).
	createSQLiteFile(t, filepath.Join(fx.dataDir, "data", "rooms.db"))
	createSQLiteFile(t, filepath.Join(fx.dataDir, "data", "users.db"))

	opts := Options{
		DataDir:  fx.dataDir,
		DestDir:  fx.destDir,
		Compress: true,
		NowFn:    fixedNow(),
	}
	res, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Extract data.db from the tarball to a scratch location.
	extractPath := filepath.Join(t.TempDir(), "extracted-data.db")
	extractSingleFile(t, res.Path, "data/data.db", extractPath)

	// Open the extracted DB and verify our marker row is there.
	db2, err := sql.Open("sqlite", extractPath+"?mode=ro")
	if err != nil {
		t.Fatalf("open extracted: %v", err)
	}
	defer db2.Close()
	var count int
	if err := db2.QueryRow(`SELECT COUNT(*) FROM t WHERE v = 'round-trip-marker'`).Scan(&count); err != nil {
		t.Fatalf("query extracted: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 marker row in extracted DB, got %d", count)
	}
}

// extractSingleFile copies the named entry out of a gzipped tarball
// into outPath. Test helper only.
func extractSingleFile(t *testing.T, tarballPath, entryName, outPath string) {
	t.Helper()
	f, err := os.Open(tarballPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	gzr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip: %v", err)
	}
	defer gzr.Close()
	tr := tar.NewReader(gzr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("tar next: %v", err)
		}
		if h.Name != entryName {
			continue
		}
		out, err := os.Create(outPath)
		if err != nil {
			t.Fatalf("create %s: %v", outPath, err)
		}
		defer out.Close()
		if _, err := io.Copy(out, tr); err != nil {
			t.Fatalf("copy: %v", err)
		}
		return
	}
	t.Fatalf("entry %q not found in %s", entryName, tarballPath)
}

// -------- isContextDB --------

func TestIsContextDB(t *testing.T) {
	cases := map[string]bool{
		"room-abc123.db":    true,
		"group-xyz.db":      true,
		"dm-asdf.db":        true,
		"data.db":           false,
		"rooms.db":          false,
		"users.db":          false,
		"room.db":           false, // no dash — not per-context shape
		"room-abc.txt":      false, // not .db
		"group":             false,
		"sshkey-server.pid": false,
	}
	for name, want := range cases {
		if got := isContextDB(name); got != want {
			t.Errorf("isContextDB(%q) = %v, want %v", name, got, want)
		}
	}
}

// -------- sliceEq helper --------

func sliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
