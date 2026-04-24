package main

// Phase 16 — operational + maintenance commands.
//
//   list-devices --user USER       Show all devices for a user
//   room-stats                      Per-room member counts + last activity
//   check-integrity [--db NAME]    Run PRAGMA integrity_check on DBs
//   prune-devices [--stale-for D]  Revoke devices older than D (default 90d)
//
// list-devices, room-stats, and check-integrity are read-only.
// prune-devices is a write operation that revokes stale devices
// via the existing pending_device_revocations queue.

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/audit"
	"github.com/brushtailmedia/sshkey-chat/internal/store"

	_ "modernc.org/sqlite"
)

// cmdListDevices shows all devices for a user: device ID, creation
// date, last sync time, and revocation status. Phase 16 scope item.
func cmdListDevices(dataDir string, args []string) error {
	var user string
	for i := 0; i < len(args); i++ {
		if args[i] == "--user" && i+1 < len(args) {
			user = args[i+1]
			i++
		}
	}
	if user == "" {
		return fmt.Errorf("usage: list-devices --user USER_ID")
	}

	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	u := st.GetUserByID(user)
	if u == nil {
		return fmt.Errorf("user %q not found", user)
	}

	devices, err := st.GetDevices(user)
	if err != nil {
		return fmt.Errorf("get devices: %w", err)
	}
	if len(devices) == 0 {
		fmt.Printf("User %s (%s) has no registered devices.\n", u.DisplayName, user)
		return nil
	}

	fmt.Printf("Devices for %s (%s): %d total\n", u.DisplayName, user, len(devices))
	for _, d := range devices {
		revoked, _ := st.IsDeviceRevoked(user, d.DeviceID)
		status := ""
		if revoked {
			status = " [REVOKED]"
		}
		lastSync := d.LastSynced
		if lastSync == "" {
			lastSync = "(never synced)"
		}
		fmt.Printf("  %-25s last_sync=%s  created=%s%s\n", d.DeviceID, lastSync, d.CreatedAt, status)
	}
	return nil
}

// cmdRoomStats shows per-room statistics: member count and message
// count. Message counts come from the per-room SQLite databases
// (room-<id>.db), which the store may or may not have open.
//
// Note: message counts require opening each per-room DB, which can
// be slow on servers with many rooms. The command is intended for
// occasional operator use, not automated monitoring.
func cmdRoomStats(dataDir string) error {
	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	rooms, err := st.GetAllRooms()
	if err != nil {
		return fmt.Errorf("get rooms: %w", err)
	}
	if len(rooms) == 0 {
		fmt.Println("No rooms.")
		return nil
	}

	fmt.Printf("%-30s %8s %10s %s\n", "ROOM", "MEMBERS", "MESSAGES", "STATUS")
	fmt.Printf("%-30s %8s %10s %s\n", "────", "───────", "────────", "──────")

	for _, r := range rooms {
		members := st.GetRoomMemberIDsByRoomID(r.ID)

		// Try to count messages in the per-room DB. If the file
		// doesn't exist or the DB is locked, report "?" rather than
		// failing the whole command.
		msgCount := "?"
		roomDBPath := filepath.Join(dataDir, "data", fmt.Sprintf("room-%s.db", r.ID))
		if db, err := sql.Open("sqlite", roomDBPath+"?_busy_timeout=5000"); err == nil {
			var count int
			if db.QueryRow("SELECT COUNT(*) FROM messages").Scan(&count) == nil {
				msgCount = fmt.Sprintf("%d", count)
			}
			db.Close()
		}

		status := ""
		if r.IsDefault {
			status = "[default] "
		}
		if r.Retired {
			status += "[retired]"
		}
		fmt.Printf("%-30s %8d %10s %s\n", r.DisplayName, len(members), msgCount, status)
	}
	return nil
}

// cmdCheckIntegrity runs PRAGMA integrity_check on SQLite databases
// in the data directory. Checks users.db, rooms.db, data.db, and
// optionally every per-room / per-group / per-DM database.
//
// The --db flag limits the check to a specific named DB (e.g.
// "users.db" or "rooms.db"). Without --db, all main DBs are
// checked. Per-context DBs (room-*.db, group-*.db, dm-*.db) are
// checked with --all.
//
// Non-zero exit code if any DB fails the integrity check.
func cmdCheckIntegrity(dataDir string, args []string) error {
	var specificDB string
	checkAll := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--db":
			if i+1 < len(args) {
				specificDB = args[i+1]
				i++
			}
		case "--all":
			checkAll = true
		}
	}

	dataPath := filepath.Join(dataDir, "data")

	// Build the list of DBs to check.
	var dbFiles []string
	if specificDB != "" {
		dbFiles = []string{filepath.Join(dataPath, specificDB)}
	} else {
		// Always check the three main DBs.
		for _, name := range []string{"users.db", "rooms.db", "data.db"} {
			p := filepath.Join(dataPath, name)
			if _, err := os.Stat(p); err == nil {
				dbFiles = append(dbFiles, p)
			}
		}
		if checkAll {
			// Also check every per-context DB.
			entries, err := os.ReadDir(dataPath)
			if err == nil {
				for _, e := range entries {
					name := e.Name()
					if strings.HasSuffix(name, ".db") &&
						(strings.HasPrefix(name, "room-") ||
							strings.HasPrefix(name, "group-") ||
							strings.HasPrefix(name, "dm-")) {
						dbFiles = append(dbFiles, filepath.Join(dataPath, name))
					}
				}
			}
		}
	}

	if len(dbFiles) == 0 {
		fmt.Println("No databases found to check.")
		return nil
	}

	allOK := true
	for _, path := range dbFiles {
		name := filepath.Base(path)
		db, err := sql.Open("sqlite", path+"?_busy_timeout=5000&mode=ro")
		if err != nil {
			fmt.Printf("  %-30s ERROR: %v\n", name, err)
			allOK = false
			continue
		}

		var result string
		if err := db.QueryRow("PRAGMA integrity_check").Scan(&result); err != nil {
			fmt.Printf("  %-30s ERROR: %v\n", name, err)
			allOK = false
		} else if result == "ok" {
			fmt.Printf("  %-30s ok\n", name)
		} else {
			fmt.Printf("  %-30s FAILED: %s\n", name, result)
			allOK = false
		}
		db.Close()
	}

	if !allOK {
		return fmt.Errorf("one or more databases failed integrity check")
	}
	fmt.Println("\nAll databases passed integrity check.")
	return nil
}

// cmdPruneDevices revokes devices that haven't synced in longer than
// the given duration. Default: 90 days. Walks every device across
// every user, checks whether the device is already revoked (skip),
// then checks whether last_synced (or created_at if never synced)
// is older than the cutoff. Matching devices are revoked via the
// same store.RevokeDevice + pending_device_revocations queue that
// `revoke-device` uses, so any active sessions on stale devices
// are also terminated by the running server's processor.
//
// A --dry-run flag previews what would be pruned without actually
// revoking anything.
func cmdPruneDevices(dataDir string, args []string) error {
	staleDuration := 90 * 24 * time.Hour // default 90 days
	dryRun := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--stale-for":
			if i+1 < len(args) {
				d, err := audit.ParseDuration(args[i+1])
				if err != nil {
					return fmt.Errorf("invalid --stale-for: %w", err)
				}
				staleDuration = d
				i++
			}
		case "--dry-run":
			dryRun = true
		}
	}

	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	allDevices, err := st.GetAllDevices()
	if err != nil {
		return fmt.Errorf("get devices: %w", err)
	}
	if len(allDevices) == 0 {
		fmt.Println("No devices registered.")
		return nil
	}

	cutoff := time.Now().Add(-staleDuration)
	revokedBy := fmt.Sprintf("os:%d", os.Getuid())
	pruned := 0
	skippedAlreadyRevoked := 0

	for _, d := range allDevices {
		// Skip devices already revoked.
		revoked, _ := st.IsDeviceRevoked(d.User, d.DeviceID)
		if revoked {
			skippedAlreadyRevoked++
			continue
		}

		// Determine staleness: prefer last_synced if available,
		// fall back to created_at. Both are RFC3339 strings.
		ts := d.LastSynced
		if ts == "" {
			ts = d.CreatedAt
		}
		parsed, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			// Can't parse the timestamp — skip rather than
			// accidentally pruning a device with a broken timestamp.
			continue
		}
		if parsed.After(cutoff) {
			continue // not stale
		}

		if dryRun {
			fmt.Printf("  [dry-run] would prune: user=%s device=%s last_activity=%s\n", d.User, d.DeviceID, ts)
			pruned++
			continue
		}

		// Revoke + enqueue for live session termination.
		if err := st.RevokeDevice(d.User, d.DeviceID, "stale_prune"); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to revoke %s/%s: %v\n", d.User, d.DeviceID, err)
			continue
		}
		if err := st.RecordPendingDeviceRevocation(d.User, d.DeviceID, "stale_prune", revokedBy); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: revoked %s/%s but queue enqueue failed: %v\n", d.User, d.DeviceID, err)
		}
		fmt.Printf("  pruned: user=%s device=%s last_activity=%s\n", d.User, d.DeviceID, ts)
		pruned++
	}

	if dryRun {
		fmt.Printf("\nDry run: %d device(s) would be pruned (stale for >%s). %d already revoked.\n",
			pruned, staleDuration, skippedAlreadyRevoked)
	} else {
		fmt.Printf("\nPruned %d device(s) (stale for >%s). %d already revoked.\n",
			pruned, staleDuration, skippedAlreadyRevoked)
		if pruned > 0 {
			fmt.Println("Active sessions on pruned devices will be kicked within a few seconds.")
		}
	}
	return nil
}
