package backup

// Per-DB backup helpers. Isolates the modernc.org/sqlite Online Backup
// API interaction from the rest of the package. The driver's Backup
// type is exposed via conn.Raw + an interface type-assertion because
// the standard database/sql API doesn't expose driver-specific methods.

import (
	"archive/tar"
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"strings"

	"modernc.org/sqlite"
)

// backupPageStep is the number of SQLite pages copied per
// sqlite3_backup_step call. Larger values finish faster but hold
// the source read lock for longer (blocking writers briefly). 100
// pages ≈ 400KB at the 4KB default page size — fast enough for
// large DBs without starving writers. Chosen by the same heuristic
// SQLite's own sqlite3 shell uses.
const backupPageStep = 100

// backupOneDB performs an Online Backup from srcPath to tempPath,
// runs PRAGMA integrity_check on the result, and streams the
// backup file into the tarball at tarPath. Removes tempPath when
// done (success or failure). The staging-dir caller guarantees
// tempPath is under a directory that will be rm-rf'd on exit as
// well, so a crashed process can't leak staging files.
func backupOneDB(ctx context.Context, srcPath, tempPath string, tw *tar.Writer, tarPath string) error {
	// Remove any leftover from a prior run — NewBackup will open
	// this path as a SQLite DB; leftover bytes could confuse it.
	_ = os.Remove(tempPath)

	src, err := sql.Open("sqlite", srcPath+"?_journal_mode=WAL&_busy_timeout=5000&mode=ro")
	if err != nil {
		return fmt.Errorf("open source %s: %w", srcPath, err)
	}
	defer src.Close()

	conn, err := src.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire conn for %s: %w", srcPath, err)
	}
	defer conn.Close()

	if err := runOnlineBackup(conn, tempPath); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("online backup %s: %w", srcPath, err)
	}

	if err := integrityCheck(ctx, tempPath); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("integrity check %s: %w", tarPath, err)
	}

	if err := streamFile(tempPath, tw, tarPath); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("stream %s into tarball: %w", tarPath, err)
	}
	_ = os.Remove(tempPath)
	return nil
}

// runOnlineBackup drives SQLite's Online Backup API from conn
// (source — any sql.Conn backed by the modernc.org/sqlite driver)
// to dstPath (a fresh file path that NewBackup will open as a new
// SQLite DB). Loops over Step(backupPageStep) until Done.
//
// The NewBackup return type is *sqlite.Backup from the concrete
// modernc.org/sqlite driver package. We type-assert against an
// anonymous interface naming that return type so conn.Raw's
// signature (which passes driver.Conn as any) can be narrowed to
// just the NewBackup method we need.
func runOnlineBackup(conn *sql.Conn, dstPath string) error {
	return conn.Raw(func(driverConn any) error {
		backuper, ok := driverConn.(interface {
			NewBackup(string) (*sqlite.Backup, error)
		})
		if !ok {
			return fmt.Errorf("driver conn %T does not implement NewBackup", driverConn)
		}
		bk, err := backuper.NewBackup(dstPath)
		if err != nil {
			return fmt.Errorf("NewBackup: %w", err)
		}
		for {
			more, err := bk.Step(backupPageStep)
			if err != nil {
				_ = bk.Finish()
				return fmt.Errorf("Step: %w", err)
			}
			if !more {
				break
			}
		}
		return bk.Finish()
	})
}

// integrityCheck runs PRAGMA integrity_check against the database
// at path and returns nil iff the single response row is "ok".
// SQLite's integrity_check returns one "ok" row on success or up
// to MAX_ERROR (default 100) rows on failure; we collect all of
// them for the error message so the operator sees the full
// diagnostic rather than just the first complaint.
func integrityCheck(ctx context.Context, path string) error {
	db, err := sql.Open("sqlite", path+"?mode=ro")
	if err != nil {
		return fmt.Errorf("open for integrity check: %w", err)
	}
	defer db.Close()
	rows, err := db.QueryContext(ctx, "PRAGMA integrity_check")
	if err != nil {
		return fmt.Errorf("query integrity_check: %w", err)
	}
	defer rows.Close()
	var results []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return fmt.Errorf("scan integrity_check row: %w", err)
		}
		results = append(results, r)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("rows: %w", err)
	}
	if len(results) == 1 && results[0] == "ok" {
		return nil
	}
	return fmt.Errorf("integrity_check failed: %s", strings.Join(results, "; "))
}

// streamFile copies the file at src into the tarball at tarPath
// with a plain regular-file header. File mode is preserved from
// the source (important for host_key's 0600).
func streamFile(src string, tw *tar.Writer, tarPath string) error {
	info, err := os.Stat(src)
	if err != nil {
		return fmt.Errorf("stat %s: %w", src, err)
	}
	header, err := tar.FileInfoHeader(info, "")
	if err != nil {
		return fmt.Errorf("build header for %s: %w", src, err)
	}
	header.Name = tarPath
	if err := tw.WriteHeader(header); err != nil {
		return fmt.Errorf("write header for %s: %w", tarPath, err)
	}
	f, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer f.Close()
	if _, err := io.Copy(tw, f); err != nil {
		return fmt.Errorf("copy %s: %w", src, err)
	}
	return nil
}
