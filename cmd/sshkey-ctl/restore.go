package main

// Phase 19 Step 6 — `sshkey-ctl restore` command.
//
// Restores a previously-created backup tarball over the live data
// and config directories. Refuses to run while the server is alive
// (lockfile check). Default behavior is to take a "pre-restore"
// backup of the current state first so the operator has a portable,
// listable rollback point if the new state turns out wrong.
//
// Flow (per Phase 19 plan §"`restore`"):
//   1. Lockfile check — reject if PID alive
//   2. Validate tarball (gzip CRC + tar header walk + path safety)
//   3. Pre-restore backup prompt (default Y; --no-pre-backup skips)
//   4. Free disk space check
//   5. Move current state to <dataDir>/pre-restore-<ts>/ safety dir
//   6. Extract tarball to original positions
//   7. PRAGMA integrity_check on every restored DB
//   8. Operator restarts the server manually
//
// Usage:
//   sshkey-ctl restore <tarball> [--no-pre-backup]

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	_ "modernc.org/sqlite"

	"github.com/brushtailmedia/sshkey-chat/internal/backup"
	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/lockfile"
)

// freeSpaceMultiplier is the heuristic ratio used when estimating
// "free space needed" from "tarball size". The tarball is gzipped
// and contains both compressible content (DBs, plaintext logs) and
// already-encrypted-or-compressed content (attachment blobs). 3x
// is conservative for the typical mix; operators with all-attachment
// backups won't have a concerning ratio either.
const freeSpaceMultiplier = 3

func cmdRestore(configDir, dataDir string, args []string) error {
	var (
		noPreBackup bool
		tarballArg  string
	)

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--no-pre-backup":
			noPreBackup = true
		case "--help", "-h":
			fmt.Println("usage: sshkey-ctl restore <tarball> [--no-pre-backup]")
			return nil
		default:
			if strings.HasPrefix(a, "--") {
				return fmt.Errorf("unknown flag: %s\nusage: sshkey-ctl restore <tarball> [--no-pre-backup]", a)
			}
			if tarballArg != "" {
				return fmt.Errorf("multiple tarball arguments; expected exactly one")
			}
			tarballArg = a
		}
	}
	if tarballArg == "" {
		return fmt.Errorf("usage: sshkey-ctl restore <tarball> [--no-pre-backup]")
	}

	tarballPath, err := filepath.Abs(tarballArg)
	if err != nil {
		return fmt.Errorf("resolve tarball path: %w", err)
	}
	if _, err := os.Stat(tarballPath); err != nil {
		return fmt.Errorf("tarball %s: %w", tarballPath, err)
	}

	// ---- Step 1: Lockfile check ----
	lockPath := filepath.Join(dataDir, "sshkey-server.pid")
	if info, err := lockfile.Read(lockPath); err == nil && info.Alive {
		return fmt.Errorf("server is running (PID %d, started %s); stop it before running restore",
			info.PID, info.StartedAt.UTC().Format(time.RFC3339))
	}

	// ---- Step 2: Validate tarball ----
	fmt.Println("restore: validating tarball...")
	entries, err := validateTarball(tarballPath)
	if err != nil {
		return fmt.Errorf("tarball validation failed: %w", err)
	}
	fmt.Printf("restore: tarball OK (%d entries)\n", len(entries))

	// ---- Step 3: Pre-restore backup prompt ----
	runPreBackup := !noPreBackup
	if runPreBackup && term.IsTerminal(int(os.Stdin.Fd())) {
		runPreBackup = promptYesNo("Create pre-restore backup of current state? [Y/n]: ", true)
	}
	if runPreBackup {
		fmt.Println("restore: creating pre-restore backup of current state...")
		preBackupCfg := loadBackupConfigForCLI(configDir)
		preDestDir := preBackupDestDir(preBackupCfg.DestDir, dataDir)
		res, err := backup.Run(context.Background(), backup.Options{
			DataDir:            dataDir,
			ConfigDir:          configDir,
			DestDir:            preDestDir,
			Label:              "pre-restore",
			Compress:           preBackupCfg.Compress,
			IncludeConfigFiles: preBackupCfg.IncludeConfigFiles,
		})
		if err != nil {
			return fmt.Errorf("pre-restore backup failed: %w (use --no-pre-backup to skip if you accept the risk)", err)
		}
		fmt.Printf("restore: pre-restore backup wrote %s (%s)\n",
			res.Path, formatBytes(res.Bytes))
	} else if noPreBackup {
		fmt.Println("restore: --no-pre-backup specified; skipping pre-restore backup")
	} else {
		fmt.Println("restore: pre-restore backup declined")
	}

	// ---- Step 4: Free disk space check ----
	tarballSize, err := fileSize(tarballPath)
	if err != nil {
		return err
	}
	if err := checkFreeSpace(dataDir, tarballSize); err != nil {
		return err
	}

	// ---- Step 5: Move current state to safety dir ----
	safetyDir := filepath.Join(dataDir, "pre-restore-"+time.Now().UTC().Format("20060102-150405"))
	if err := os.MkdirAll(safetyDir, 0755); err != nil {
		return fmt.Errorf("create safety dir: %w", err)
	}
	fmt.Printf("restore: moving current state to %s\n", safetyDir)
	moved, err := moveToSafety(dataDir, configDir, entries, safetyDir)
	if err != nil {
		return fmt.Errorf("safety move failed: %w (no extraction performed; safety dir at %s holds partial state)", err, safetyDir)
	}
	fmt.Printf("restore: moved %d existing artefacts to safety dir\n", moved)

	// ---- Step 6: Extract tarball ----
	fmt.Println("restore: extracting tarball...")
	extracted, err := extractTarball(tarballPath, dataDir, configDir)
	if err != nil {
		return fmt.Errorf("extraction failed: %w (original state preserved at %s — manually rsync it back if you want to abort the restore)", err, safetyDir)
	}
	fmt.Printf("restore: extracted %d entries\n", extracted)

	// ---- Step 7: Integrity check on every restored DB ----
	fmt.Println("restore: running integrity check on every restored DB...")
	dbCount, err := postRestoreIntegrityCheck(dataDir)
	if err != nil {
		return fmt.Errorf("integrity check failed on a restored DB: %w (original state preserved at %s)", err, safetyDir)
	}
	fmt.Printf("restore: integrity check passed (%d DBs)\n", dbCount)

	fmt.Println("restore: complete. Start the server when ready.")
	fmt.Printf("        Original state preserved at %s — remove it after verifying the restored server works.\n", safetyDir)
	return nil
}

// promptYesNo prints prompt and reads a line from stdin. Empty input
// (just Enter) returns defaultYes. Any answer starting with 'y' or 'Y'
// returns true; 'n' or 'N' returns false; anything else also returns
// defaultYes (don't loop on garbage input — operator can re-run the
// command if they typed wrong).
func promptYesNo(prompt string, defaultYes bool) bool {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return defaultYes
	}
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return defaultYes
	}
	switch strings.ToLower(trimmed)[0] {
	case 'y':
		return true
	case 'n':
		return false
	}
	return defaultYes
}

// validateTarball walks the tarball without extracting and returns
// the list of validated entry names. Rejects:
//   - Unreadable gzip stream (CRC failure)
//   - Tar entries with absolute paths
//   - Tar entries containing ".." segments after Clean
//   - Tar entries not under "data/" or "config/"
//   - Symlinks, hardlinks, devices (only regular files allowed)
func validateTarball(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	var entries []string
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar header: %w", err)
		}
		// tar.TypeRegA was deprecated in Go 1.11 and the stdlib tar
		// reader normalises TypeRegA ('\x00') entries to TypeReg on
		// read, so checking TypeReg alone is sufficient.
		if header.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("entry %q: only regular files allowed (got typeflag %d)", header.Name, header.Typeflag)
		}
		if filepath.IsAbs(header.Name) {
			return nil, fmt.Errorf("entry %q: absolute path not allowed", header.Name)
		}
		clean := filepath.Clean(header.Name)
		if clean != header.Name && clean != "./"+header.Name {
			// Could happen with redundant separators or "./" prefixes;
			// require canonical form.
			return nil, fmt.Errorf("entry %q: non-canonical path", header.Name)
		}
		if strings.HasPrefix(clean, "..") || strings.Contains(clean, string(filepath.Separator)+"..") {
			return nil, fmt.Errorf("entry %q: path-traversal not allowed", header.Name)
		}
		if !strings.HasPrefix(clean, "data/") && !strings.HasPrefix(clean, "config/") {
			return nil, fmt.Errorf("entry %q: must be under data/ or config/", header.Name)
		}
		// Drain the body — we're not extracting, just validating.
		if _, err := io.Copy(io.Discard, tr); err != nil {
			return nil, fmt.Errorf("entry %q body: %w", header.Name, err)
		}
		entries = append(entries, clean)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("tarball contains no entries")
	}
	return entries, nil
}

// moveToSafety relocates each existing artefact (one per tarball
// entry) to the safety dir under a parallel path. Skips entries
// whose source path doesn't exist (the tarball includes optional
// items like audit.log that the live deployment might not have).
//
// Uses os.Rename for atomicity within the same filesystem; cross-
// filesystem renames fail and we fall back to copy + remove. Returns
// the number of files actually moved.
func moveToSafety(dataDir, configDir string, entries []string, safetyDir string) (int, error) {
	moved := 0
	for _, entry := range entries {
		srcPath, ok := tarEntryToSourcePath(entry, dataDir, configDir)
		if !ok {
			continue // unreachable after validation, but defensive
		}
		if _, err := os.Stat(srcPath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue // optional file not present locally
			}
			return moved, fmt.Errorf("stat %s: %w", srcPath, err)
		}
		dstPath := filepath.Join(safetyDir, entry)
		if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
			return moved, fmt.Errorf("mkdir safety subdir: %w", err)
		}
		if err := os.Rename(srcPath, dstPath); err != nil {
			// Rename across filesystems fails on Linux with EXDEV.
			// Fall back to copy + remove to handle that case.
			if linkErr, ok := err.(*os.LinkError); ok && linkErr.Err == syscall.EXDEV {
				if err := copyFile(srcPath, dstPath); err != nil {
					return moved, fmt.Errorf("cross-fs copy %s: %w", srcPath, err)
				}
				if err := os.Remove(srcPath); err != nil {
					return moved, fmt.Errorf("remove after copy %s: %w", srcPath, err)
				}
			} else {
				return moved, fmt.Errorf("rename %s -> %s: %w", srcPath, dstPath, err)
			}
		}
		moved++
	}
	return moved, nil
}

// tarEntryToSourcePath maps a validated tarball entry name (e.g.,
// "data/data.db" or "config/host_key") to its on-disk source path
// under dataDir or configDir. Returns false for entries that don't
// match either prefix (validation should have caught these — defensive).
func tarEntryToSourcePath(entry, dataDir, configDir string) (string, bool) {
	if strings.HasPrefix(entry, "data/") {
		return filepath.Join(dataDir, entry), true
	}
	if strings.HasPrefix(entry, "config/") {
		return filepath.Join(configDir, strings.TrimPrefix(entry, "config/")), true
	}
	return "", false
}

// extractTarball walks the tarball and writes each entry to its
// canonical on-disk location. Preserves file mode from the tar
// header (important for host_key's 0600).
func extractTarball(tarballPath, dataDir, configDir string) (int, error) {
	f, err := os.Open(tarballPath)
	if err != nil {
		return 0, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	gzr, err := gzip.NewReader(f)
	if err != nil {
		return 0, fmt.Errorf("gzip: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	count := 0
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return count, fmt.Errorf("tar header: %w", err)
		}
		clean := filepath.Clean(header.Name)
		dstPath, ok := tarEntryToSourcePath(clean, dataDir, configDir)
		if !ok {
			return count, fmt.Errorf("entry %q: cannot map to dest path", header.Name)
		}
		if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
			return count, fmt.Errorf("mkdir for %s: %w", dstPath, err)
		}
		mode := os.FileMode(header.Mode) & os.ModePerm
		if mode == 0 {
			mode = 0644
		}
		out, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			return count, fmt.Errorf("create %s: %w", dstPath, err)
		}
		if _, err := io.Copy(out, tr); err != nil {
			out.Close()
			return count, fmt.Errorf("copy %s: %w", dstPath, err)
		}
		if err := out.Close(); err != nil {
			return count, fmt.Errorf("close %s: %w", dstPath, err)
		}
		count++
	}
	return count, nil
}

// postRestoreIntegrityCheck runs `PRAGMA integrity_check` on every
// SQLite DB under <dataDir>/data/. Returns the number of DBs checked
// and the first failure (if any).
func postRestoreIntegrityCheck(dataDir string) (int, error) {
	dataRoot := filepath.Join(dataDir, "data")
	entries, err := os.ReadDir(dataRoot)
	if err != nil {
		return 0, fmt.Errorf("read data dir: %w", err)
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".db") {
			continue
		}
		path := filepath.Join(dataRoot, e.Name())
		if err := pragmaIntegrityCheckOne(path); err != nil {
			return count, fmt.Errorf("%s: %w", e.Name(), err)
		}
		count++
	}
	return count, nil
}

// pragmaIntegrityCheckOne opens one DB read-only and runs PRAGMA
// integrity_check. Collects all result rows so a multi-error report
// is preserved in the error message.
func pragmaIntegrityCheckOne(path string) error {
	db, err := sql.Open("sqlite", path+"?mode=ro")
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer db.Close()
	rows, err := db.Query("PRAGMA integrity_check")
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}
	defer rows.Close()
	var results []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(results) == 1 && results[0] == "ok" {
		return nil
	}
	return fmt.Errorf("integrity_check returned: %s", strings.Join(results, "; "))
}

// checkFreeSpace returns an error if the dataDir's filesystem doesn't
// have enough free bytes to absorb a restore. Heuristic: free space
// must be ≥ tarballSize × freeSpaceMultiplier. This covers the
// uncompressed extracted contents plus any growth headroom; safety
// dir is created via rename so it costs ~0 additional space.
func checkFreeSpace(dataDir string, tarballSize int64) error {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dataDir, &stat); err != nil {
		return fmt.Errorf("statfs %s: %w", dataDir, err)
	}
	available := int64(stat.Bavail) * int64(stat.Bsize)
	needed := tarballSize * freeSpaceMultiplier
	if available < needed {
		return fmt.Errorf("insufficient free space at %s: have %s, need ~%s (%dx tarball size)",
			dataDir, formatBytes(available), formatBytes(needed), freeSpaceMultiplier)
	}
	return nil
}

// fileSize returns the size in bytes of a file at path.
func fileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, fmt.Errorf("stat %s: %w", path, err)
	}
	return info.Size(), nil
}

// copyFile is a fallback for cross-filesystem moves. Used by
// moveToSafety when os.Rename returns EXDEV. Copies content + mode.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open src: %w", err)
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return fmt.Errorf("stat src: %w", err)
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
	if err != nil {
		return fmt.Errorf("create dst: %w", err)
	}
	defer out.Close()
	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copy: %w", err)
	}
	return nil
}

// loadBackupConfigForCLI loads the [backup] section from server.toml.
// Falls back to defaults if server.toml is absent (recovery scenarios).
// Mirrors cmdBackup's logic; extracted because cmdRestore needs the
// same parse for the pre-restore backup invocation.
func loadBackupConfigForCLI(configDir string) config.ParsedBackupConfig {
	cfg := config.DefaultServerConfig()
	serverTomlPath := filepath.Join(configDir, "server.toml")
	if _, err := os.Stat(serverTomlPath); err == nil {
		if loaded, err := config.LoadServerConfig(serverTomlPath); err == nil {
			cfg = loaded
		}
	}
	parsed, _, _ := cfg.Backup.ParseAndValidate()
	return parsed
}

// preBackupDestDir mirrors backup_scheduler.go:resolveBackupDestDir
// without importing internal/server (keeps cmd/sshkey-ctl's
// dependency surface narrow).
func preBackupDestDir(configDestDir, dataDir string) string {
	d := configDestDir
	if d == "" {
		d = "backups"
	}
	if !filepath.IsAbs(d) {
		d = filepath.Join(dataDir, d)
	}
	return d
}
