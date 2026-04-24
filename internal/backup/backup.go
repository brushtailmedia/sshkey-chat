// Package backup implements the Phase 19 server backup + restore
// primitives. The Run entry point produces a single tar+gzip archive
// containing every artefact the Phase 19 scope calls for (SQLite DBs
// via Online Backup API, attachment blobs, audit + pending-keys logs,
// host key, server.toml).
//
// Callers: both the scheduled backup goroutine (scheduler.go in
// internal/server, ships in Phase 19 Step 5) and the manual
// `sshkey-ctl backup` command (ships in Phase 19 Step 4). Backup runs
// safely while the server is live — SQLite's Online Backup API
// handles concurrent writers via MVCC retries, attachment blobs are
// immutable after upload_complete, and audit/pending-keys logs are
// append-only.
//
// Structure:
//
//	backup-<YYYYMMDD-HHMMSS>[-<label>].tar.gz
//	  data/
//	    data.db, rooms.db, users.db     (Online Backup API snapshots)
//	    room-*.db, group-*.db, dm-*.db  (Online Backup API snapshots)
//	    files/<fileID>                  (plain file copy)
//	    pending-keys.log                (plain file copy)
//	    audit.log                       (plain file copy)
//	  config/
//	    host_key                        (plain file copy, mode 0600 preserved)
//	    server.toml                     (plain file copy)
//
// The tarball lands atomically via temp-file + rename: partial writes
// leave no tarball at all, never a corrupted one.
package backup

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Options configures a single Run call. All paths are resolved by the
// caller before being passed in — Run does not apply defaults for
// DataDir / ConfigDir / DestDir (those are the server's config, not
// the backup package's concern).
type Options struct {
	// DataDir is the server's data directory — source of SQLite DBs,
	// attachment blobs under data/files/, the audit log, and the
	// pending-keys.log file.
	DataDir string

	// ConfigDir is the server's config directory — source of host_key
	// and server.toml. Only required when IncludeConfigFiles is true.
	ConfigDir string

	// DestDir is the directory that receives the final tarball. Must
	// be writable. Created if missing (non-recursive parent creation
	// is still required — we don't mkdir -p arbitrary paths).
	DestDir string

	// Label is an optional human-readable tag embedded in the
	// filename. Must pass ValidateLabel — CLI callers should validate
	// at flag-parse time for better error surfacing. Empty means no
	// label in the filename.
	Label string

	// Compress gzip-compresses the tarball. Phase 19 default true.
	Compress bool

	// IncludeConfigFiles bundles host_key + server.toml under
	// config/ in the tarball. Host key is critical for restore-to-
	// new-machine (see Phase 19 decision #2); server.toml is
	// included for full-state recovery. Phase 19 default true.
	IncludeConfigFiles bool

	// NowFn returns the current time for timestamps in filenames.
	// Defaults to time.Now. Injectable for deterministic tests.
	NowFn func() time.Time
}

// Result reports what a Run call produced. All counters are
// post-success — a failed Run returns zero-valued Result.
type Result struct {
	Path        string        // absolute path to the produced tarball
	Bytes       int64         // tarball size on disk
	Duration    time.Duration // wall-clock time from Run entry to rename
	CoreDBs     int           // data.db, rooms.db, users.db — expected 0-3
	ContextDBs  int           // room-*.db + group-*.db + dm-*.db
	Attachments int           // files under data/files/
	AuxFiles    int           // audit.log + pending-keys.log + host_key + server.toml
}

// Run produces a backup tarball per the package-level layout. On
// success the tarball is at Result.Path and every staging artefact
// has been cleaned up. On error the tarball .tmp file has been
// removed and no staging artefacts remain.
//
// The context is honored at a coarse granularity — between per-DB
// snapshot phases. Cancellation mid-DB-backup waits for the current
// Step() call to return before aborting, because SQLite's backup
// API does not expose cancellation.
func Run(ctx context.Context, opts Options) (Result, error) {
	var result Result
	start := time.Now()

	if err := ValidateLabel(opts.Label); err != nil {
		return result, err
	}
	if opts.DataDir == "" {
		return result, fmt.Errorf("Options.DataDir is required")
	}
	if opts.DestDir == "" {
		return result, fmt.Errorf("Options.DestDir is required")
	}
	if opts.IncludeConfigFiles && opts.ConfigDir == "" {
		return result, fmt.Errorf("Options.ConfigDir is required when IncludeConfigFiles is true")
	}

	nowFn := opts.NowFn
	if nowFn == nil {
		nowFn = time.Now
	}

	ts := nowFn().UTC().Format("20060102-150405")
	name := "backup-" + ts
	if opts.Label != "" {
		name += "-" + opts.Label
	}
	name += ".tar.gz"
	finalPath := filepath.Join(opts.DestDir, name)
	tmpPath := finalPath + ".tmp"

	if err := os.MkdirAll(opts.DestDir, 0755); err != nil {
		return result, fmt.Errorf("create dest_dir: %w", err)
	}

	// Staging dir holds scratch files for per-DB Online Backup. One
	// SQLite backup at a time writes here; we stream it into the
	// tarball and delete the scratch file before moving on to the
	// next DB. Staging dir itself is removed on exit.
	stagingDir := filepath.Join(opts.DestDir, "backup-"+ts+".work")
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		return result, fmt.Errorf("create staging dir: %w", err)
	}
	defer os.RemoveAll(stagingDir)

	tmpFile, err := os.Create(tmpPath)
	if err != nil {
		return result, fmt.Errorf("create tarball temp file: %w", err)
	}
	// committed flips to true once rename succeeds. On any earlier
	// return path the deferred cleanup removes tmpPath — partial
	// tarballs never survive.
	committed := false
	defer func() {
		if !committed {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	var writer io.Writer = tmpFile
	var gzw *gzip.Writer
	if opts.Compress {
		gzw = gzip.NewWriter(tmpFile)
		writer = gzw
	}
	tw := tar.NewWriter(writer)

	// -------- core DBs --------
	coreDBs := []string{"data.db", "rooms.db", "users.db"}
	for _, name := range coreDBs {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		src := filepath.Join(opts.DataDir, "data", name)
		if _, err := os.Stat(src); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// Fresh server that hasn't created a particular DB
				// yet — skip. store.Open normally creates all three,
				// but defensive check keeps us safe on first-ever
				// runs.
				continue
			}
			return result, fmt.Errorf("stat %s: %w", src, err)
		}
		if err := backupOneDB(ctx, src, filepath.Join(stagingDir, name), tw, "data/"+name); err != nil {
			return result, err
		}
		result.CoreDBs++
	}

	// -------- per-context DBs via directory walk --------
	dataRoot := filepath.Join(opts.DataDir, "data")
	entries, err := os.ReadDir(dataRoot)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return result, fmt.Errorf("read data dir: %w", err)
		}
		// No data dir — nothing to back up beyond what we've already done.
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !isContextDB(name) {
			continue
		}
		src := filepath.Join(dataRoot, name)
		if err := backupOneDB(ctx, src, filepath.Join(stagingDir, name), tw, "data/"+name); err != nil {
			return result, err
		}
		result.ContextDBs++
	}

	// -------- attachment blobs --------
	filesDir := filepath.Join(dataRoot, "files")
	if blobEntries, err := os.ReadDir(filesDir); err == nil {
		for _, e := range blobEntries {
			if err := ctx.Err(); err != nil {
				return result, err
			}
			if e.IsDir() {
				continue
			}
			src := filepath.Join(filesDir, e.Name())
			if err := streamFile(src, tw, "data/files/"+e.Name()); err != nil {
				return result, fmt.Errorf("attachment %s: %w", e.Name(), err)
			}
			result.Attachments++
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, fmt.Errorf("read files dir: %w", err)
	}

	// -------- aux plain files --------
	// Per Phase 19 "Tarball contents" block. Each entry has a source
	// path, a tarball path, and whether absence is fatal.
	type auxFile struct {
		src       string
		tarPath   string
		required  bool // if true and missing → error
	}
	aux := []auxFile{
		{filepath.Join(opts.DataDir, "audit.log"), "data/audit.log", false},
		{filepath.Join(dataRoot, "pending-keys.log"), "data/pending-keys.log", false},
	}
	if opts.IncludeConfigFiles {
		aux = append(aux,
			auxFile{filepath.Join(opts.ConfigDir, "host_key"), "config/host_key", true},
			auxFile{filepath.Join(opts.ConfigDir, "server.toml"), "config/server.toml", true},
		)
	}
	for _, f := range aux {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if _, err := os.Stat(f.src); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				if f.required {
					return result, fmt.Errorf("required file missing: %s", f.src)
				}
				continue
			}
			return result, fmt.Errorf("stat %s: %w", f.src, err)
		}
		if err := streamFile(f.src, tw, f.tarPath); err != nil {
			return result, fmt.Errorf("aux %s: %w", f.tarPath, err)
		}
		result.AuxFiles++
	}

	// -------- close writers and commit via rename --------
	if err := tw.Close(); err != nil {
		return result, fmt.Errorf("close tar writer: %w", err)
	}
	if gzw != nil {
		if err := gzw.Close(); err != nil {
			return result, fmt.Errorf("close gzip writer: %w", err)
		}
	}
	if err := tmpFile.Close(); err != nil {
		return result, fmt.Errorf("close tarball: %w", err)
	}

	if err := os.Rename(tmpPath, finalPath); err != nil {
		return result, fmt.Errorf("rename to final: %w", err)
	}
	committed = true

	info, err := os.Stat(finalPath)
	if err != nil {
		return result, fmt.Errorf("stat final: %w", err)
	}
	result.Path = finalPath
	result.Bytes = info.Size()
	result.Duration = time.Since(start)
	return result, nil
}

// isContextDB returns true if name matches the per-context DB pattern
// (room-*.db, group-*.db, dm-*.db). Core DBs (data.db, rooms.db,
// users.db) are caught upstream by name; everything else is ignored.
func isContextDB(name string) bool {
	if !strings.HasSuffix(name, ".db") {
		return false
	}
	for _, prefix := range []string{"room-", "group-", "dm-"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}
