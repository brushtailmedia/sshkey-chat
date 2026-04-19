package main

// Phase 19 Step 4 — `sshkey-ctl backup` command tests.
//
// Coverage matrix:
//   - Happy path: produces a tarball at the expected location
//   - --label flag: tarball filename includes the label
//   - --out flag: overrides config dest_dir
//   - --label rejected at parse time when malformed (path-traversal etc)
//   - Unknown flag rejected with usage hint
//   - Missing argument to --out / --label rejected
//   - server.toml absent: falls back to defaults (still succeeds)

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
)

// setupBackupFixture builds a config dir with server.toml + a data dir
// with a real store + dataDir layout that backup.Run can walk.
// Returns (configDir, dataDir).
func setupBackupFixture(t *testing.T) (string, string) {
	t.Helper()
	users := map[string]testUser{
		"usr_alice": {
			Key:         "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJPpG4hFrxw7JOAppGdh0JrkNDNGxypfmwJxNFCWXnpG",
			DisplayName: "Alice",
			Rooms:       []string{"general"},
		},
	}
	configDir := setupConfig(t, users, map[string]config.Room{"general": {}})

	// server.toml — minimal but parseable + auto_revoke disabled to
	// suppress the "no thresholds" warning.
	if err := os.WriteFile(filepath.Join(configDir, "server.toml"), []byte(`
[server]
port = 2222
bind = "127.0.0.1"

[server.auto_revoke]
enabled = false
`), 0644); err != nil {
		t.Fatalf("write server.toml: %v", err)
	}
	// Required by config.LoadServerConfig path traversal — write a
	// fake host_key so backup with IncludeConfigFiles=true (the
	// default) doesn't bail on the required-file check.
	if err := os.WriteFile(filepath.Join(configDir, "host_key"), []byte("fake"), 0600); err != nil {
		t.Fatalf("write host_key: %v", err)
	}

	dataDir := setupDataDir(t, map[string]config.Room{"general": {}}, users)
	return configDir, dataDir
}

// findTarball returns the first .tar.gz in dir. Fails the test if none
// or more than one exists.
func findTarball(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	var matches []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tar.gz") {
			matches = append(matches, filepath.Join(dir, e.Name()))
		}
	}
	if len(matches) == 0 {
		t.Fatalf("no .tar.gz in %s; entries: %v", dir, entries)
	}
	if len(matches) > 1 {
		t.Fatalf("multiple .tar.gz in %s: %v", dir, matches)
	}
	return matches[0]
}

// readTarballEntries opens a gzipped tarball and returns entry names.
func readBackupTarballEntries(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()
	gzr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("gzip: %v", err)
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

func TestCmdBackup_HappyPath(t *testing.T) {
	configDir, dataDir := setupBackupFixture(t)

	if err := cmdBackup(configDir, dataDir, []string{}); err != nil {
		t.Fatalf("cmdBackup: %v", err)
	}

	// Default dest_dir is "backups" under dataDir.
	tarballPath := findTarball(t, filepath.Join(dataDir, "backups"))
	entries := readBackupTarballEntries(t, tarballPath)
	// Should at minimum include the three core DBs and host_key.
	wantSubset := map[string]bool{
		"data/data.db":     false,
		"data/rooms.db":    false,
		"data/users.db":    false,
		"config/host_key":  false,
		"config/server.toml": false,
	}
	for _, e := range entries {
		if _, ok := wantSubset[e]; ok {
			wantSubset[e] = true
		}
	}
	for entry, found := range wantSubset {
		if !found {
			t.Errorf("expected entry %q not found in tarball; got entries: %v", entry, entries)
		}
	}
}

func TestCmdBackup_LabelFlag(t *testing.T) {
	configDir, dataDir := setupBackupFixture(t)

	if err := cmdBackup(configDir, dataDir, []string{"--label", "pre-upgrade"}); err != nil {
		t.Fatalf("cmdBackup: %v", err)
	}

	tarballPath := findTarball(t, filepath.Join(dataDir, "backups"))
	if !strings.Contains(filepath.Base(tarballPath), "-pre-upgrade.tar.gz") {
		t.Errorf("tarball name = %q, want suffix '-pre-upgrade.tar.gz'", filepath.Base(tarballPath))
	}
}

func TestCmdBackup_OutFlagOverridesConfig(t *testing.T) {
	configDir, dataDir := setupBackupFixture(t)

	customOut := filepath.Join(t.TempDir(), "custom-out")

	if err := cmdBackup(configDir, dataDir, []string{"--out", customOut}); err != nil {
		t.Fatalf("cmdBackup: %v", err)
	}

	// Tarball lands in --out, not in the config's default location.
	if _, err := os.Stat(filepath.Join(dataDir, "backups")); err == nil {
		// The default backups dir was created mid-flight — but no
		// tarball should be in it. (Actually backup.Run only creates
		// dest_dir, so this should not exist at all.)
		entries, _ := os.ReadDir(filepath.Join(dataDir, "backups"))
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".tar.gz") {
				t.Errorf("tarball appeared in default dir despite --out: %s", e.Name())
			}
		}
	}

	if _, err := findTarballNoFatal(customOut); err != nil {
		t.Fatalf("no tarball in --out dir %s: %v", customOut, err)
	}
}

// findTarballNoFatal is like findTarball but returns an error instead
// of failing the test — for cases where absence is the point of the
// assertion.
func findTarballNoFatal(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tar.gz") {
			return filepath.Join(dir, e.Name()), nil
		}
	}
	return "", os.ErrNotExist
}

func TestCmdBackup_BadLabelRejected(t *testing.T) {
	configDir, dataDir := setupBackupFixture(t)

	err := cmdBackup(configDir, dataDir, []string{"--label", "../../etc"})
	if err == nil {
		t.Fatal("cmdBackup with malicious label should fail, got nil")
	}
	if !strings.Contains(err.Error(), "invalid label") {
		t.Errorf("error should mention 'invalid label', got: %q", err.Error())
	}

	// No tarball should have been written.
	if _, err := os.Stat(filepath.Join(dataDir, "backups")); err == nil {
		entries, _ := os.ReadDir(filepath.Join(dataDir, "backups"))
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".tar.gz") {
				t.Errorf("tarball leaked despite label rejection: %s", e.Name())
			}
		}
	}
}

func TestCmdBackup_UnknownFlagRejected(t *testing.T) {
	configDir, dataDir := setupBackupFixture(t)

	err := cmdBackup(configDir, dataDir, []string{"--bogus"})
	if err == nil {
		t.Fatal("cmdBackup with unknown flag should fail, got nil")
	}
	if !strings.Contains(err.Error(), "unknown flag") {
		t.Errorf("error should mention 'unknown flag', got: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "usage:") {
		t.Errorf("error should include usage hint, got: %q", err.Error())
	}
}

func TestCmdBackup_MissingFlagArgs(t *testing.T) {
	configDir, dataDir := setupBackupFixture(t)

	err := cmdBackup(configDir, dataDir, []string{"--out"})
	if err == nil || !strings.Contains(err.Error(), "--out requires") {
		t.Errorf("--out without arg should fail with clear message, got: %v", err)
	}

	err = cmdBackup(configDir, dataDir, []string{"--label"})
	if err == nil || !strings.Contains(err.Error(), "--label requires") {
		t.Errorf("--label without arg should fail with clear message, got: %v", err)
	}
}

func TestCmdBackup_NoServerToml(t *testing.T) {
	// Operator running backup against a dataDir that doesn't have a
	// configured server.toml — should fall back to defaults and
	// still succeed (recovery scenario).
	configDir := t.TempDir()
	dataDir := setupDataDir(t, map[string]config.Room{"general": {}}, nil)

	// IncludeConfigFiles=true (default) requires host_key + server.toml
	// to exist. Since we have neither, expect a clean error mentioning
	// the missing file.
	err := cmdBackup(configDir, dataDir, []string{})
	if err == nil {
		t.Fatal("cmdBackup with missing config files should fail with default IncludeConfigFiles=true, got nil")
	}
	if !strings.Contains(err.Error(), "required file missing") {
		t.Errorf("error should mention required file missing, got: %q", err.Error())
	}
}

func TestCmdBackup_NoServerTomlConfigFilesOff(t *testing.T) {
	// Same as above but configure include_config_files = false so the
	// missing config dir doesn't block the backup. This is the actual
	// "operator runs backup against a dataDir copy" recovery path.
	configDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(configDir, "server.toml"), []byte(`
[server]
port = 2222
bind = "127.0.0.1"

[server.auto_revoke]
enabled = false

[backup]
include_config_files = false
`), 0644); err != nil {
		t.Fatalf("write server.toml: %v", err)
	}
	dataDir := setupDataDir(t, map[string]config.Room{"general": {}}, nil)

	if err := cmdBackup(configDir, dataDir, []string{}); err != nil {
		t.Fatalf("cmdBackup: %v", err)
	}

	tarballPath := findTarball(t, filepath.Join(dataDir, "backups"))
	entries := readBackupTarballEntries(t, tarballPath)
	for _, e := range entries {
		if strings.HasPrefix(e, "config/") {
			t.Errorf("config/ entry leaked despite include_config_files=false: %s", e)
		}
	}
}
