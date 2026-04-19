package main

// Phase 19 Step 6 — `sshkey-ctl list-backups` command.
//
// Walks the configured `[backup].dest_dir` (resolved against
// dataDir), parses the timestamp + label embedded in each
// backup-*.tar.gz filename, and prints a formatted table sorted
// newest-first. Includes pre-restore backups (label = "pre-restore")
// so the operator can distinguish those from scheduled or manual
// snapshots when picking a tarball to restore from.
//
// Usage:
//   sshkey-ctl list-backups

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"time"
)

// backupFilePattern parses the filename produced by
// internal/backup.Run: backup-<YYYYMMDD-HHMMSS>[-<label>].tar.gz.
// Group 1 = timestamp, Group 2 = label (may be empty).
var backupFilePattern = regexp.MustCompile(`^backup-(\d{8}-\d{6})(?:-([A-Za-z0-9_-]+))?\.tar\.gz$`)

func cmdListBackups(configDir, dataDir string, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("usage: sshkey-ctl list-backups (no flags)")
	}

	cfg := loadBackupConfigForCLI(configDir)
	destDir := preBackupDestDir(cfg.DestDir, dataDir)

	entries, err := os.ReadDir(destDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Printf("No backups (directory does not exist: %s)\n", destDir)
			return nil
		}
		return fmt.Errorf("read %s: %w", destDir, err)
	}

	type backupEntry struct {
		name      string
		size      int64
		mtime     time.Time
		label     string
	}
	var backups []backupEntry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		match := backupFilePattern.FindStringSubmatch(e.Name())
		if match == nil {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		backups = append(backups, backupEntry{
			name:  e.Name(),
			size:  info.Size(),
			mtime: info.ModTime(),
			label: match[2], // empty string when no label was attached
		})
	}

	if len(backups) == 0 {
		fmt.Printf("No backups in %s\n", destDir)
		return nil
	}

	sort.Slice(backups, func(i, j int) bool {
		return backups[i].mtime.After(backups[j].mtime)
	})

	// Compute name column width based on the widest filename so
	// the table stays aligned regardless of label length.
	maxNameLen := len("NAME")
	for _, b := range backups {
		if len(b.name) > maxNameLen {
			maxNameLen = len(b.name)
		}
	}
	nameFmt := fmt.Sprintf("%%-%ds", maxNameLen)

	fmt.Printf(nameFmt+"  %-8s  %-12s  %s\n", "NAME", "SIZE", "AGE", "LABEL")
	now := time.Now()
	for _, b := range backups {
		label := b.label
		if label == "" {
			label = "-"
		}
		fmt.Printf(nameFmt+"  %-8s  %-12s  %s\n",
			b.name, formatBytes(b.size), formatAge(now.Sub(b.mtime)), label)
	}
	return nil
}

// formatAge returns a short human-readable age string. Examples:
//   0s         → "just now"
//   45s        → "45s"
//   3m20s      → "3m"
//   2h15m      → "2h"
//   3d4h       → "3d"
//   45d        → "45d"
//
// Operators want at-a-glance "how old" — single unit precision is
// enough; if they need exact, the timestamp is in the filename.
func formatAge(d time.Duration) string {
	if d < 30*time.Second {
		return "just now"
	}
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	days := int(d.Hours()) / 24
	return fmt.Sprintf("%dd", days)
}

