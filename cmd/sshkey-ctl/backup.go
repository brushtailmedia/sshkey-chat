package main

// Phase 19 Step 4 — `sshkey-ctl backup` command.
//
// Thin wrapper around internal/backup.Run. Loads the [backup] section
// from server.toml (if present) so manual backups inherit the same
// Compress / IncludeConfigFiles / DestDir choices the scheduled
// backup uses; CLI flags override on a per-invocation basis.
//
// Usage:
//   sshkey-ctl backup [--out PATH] [--label TAG]
//
// --out:    write the tarball to this directory instead of the
//           [backup].dest_dir from server.toml. Use for ad-hoc
//           archive locations (e.g. an NFS mount).
// --label:  embed this tag in the filename. Must match
//           [A-Za-z0-9_-]{1,32}.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/backup"
	"github.com/brushtailmedia/sshkey-chat/internal/config"
)

func cmdBackup(configDir, dataDir string, args []string) error {
	var outDir, label string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--out":
			if i+1 >= len(args) {
				return fmt.Errorf("--out requires a path argument")
			}
			outDir = args[i+1]
			i++
		case "--label":
			if i+1 >= len(args) {
				return fmt.Errorf("--label requires a tag argument")
			}
			label = args[i+1]
			i++
		default:
			return fmt.Errorf("unknown flag: %s\nusage: sshkey-ctl backup [--out PATH] [--label TAG]", args[i])
		}
	}

	// Pre-validate the label so the operator gets a clean error
	// before we touch any filesystem state.
	if err := backup.ValidateLabel(label); err != nil {
		return err
	}

	// Load [backup] section from server.toml. Missing file is OK —
	// fall back to defaults so the operator can run a backup against
	// a dataDir that doesn't have a fully-configured server.toml
	// (recovery / inspection scenarios).
	cfg := config.DefaultServerConfig()
	serverTomlPath := filepath.Join(configDir, "server.toml")
	if _, err := os.Stat(serverTomlPath); err == nil {
		loaded, err := config.LoadServerConfig(serverTomlPath)
		if err != nil {
			return fmt.Errorf("load server.toml: %w", err)
		}
		cfg = loaded
	}
	parsed, _, err := cfg.Backup.ParseAndValidate()
	if err != nil {
		return fmt.Errorf("validate [backup]: %w", err)
	}

	// Resolve dest dir: --out flag wins, else config dest_dir
	// (relative paths anchored to dataDir), else default "backups".
	destDir := outDir
	if destDir == "" {
		destDir = parsed.DestDir
		if destDir == "" {
			destDir = "backups"
		}
		if !filepath.IsAbs(destDir) {
			destDir = filepath.Join(dataDir, destDir)
		}
	}

	res, err := backup.Run(context.Background(), backup.Options{
		DataDir:            dataDir,
		ConfigDir:          configDir,
		DestDir:            destDir,
		Label:              label,
		Compress:           parsed.Compress,
		IncludeConfigFiles: parsed.IncludeConfigFiles,
	})
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}

	fmt.Printf("backup: wrote %s (%s) in %s\n",
		res.Path, formatBytes(res.Bytes), res.Duration.Round(time.Millisecond))
	fmt.Printf("        %d core DBs + %d context DBs + %d attachments + %d aux files\n",
		res.CoreDBs, res.ContextDBs, res.Attachments, res.AuxFiles)
	return nil
}
