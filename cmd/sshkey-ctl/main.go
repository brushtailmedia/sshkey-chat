package main

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/lockfile"
	"github.com/brushtailmedia/sshkey-chat/internal/server"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sshkey-ctl: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		return printUsage()
	}

	configDir := "/etc/sshkey-chat"
	dataDir := "/var/sshkey-chat"

	// Check for --config and --data flags
	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		if args[i] == "--config" && i+1 < len(args) {
			configDir = args[i+1]
			args = append(args[:i], args[i+2:]...)
			i--
		} else if args[i] == "--data" && i+1 < len(args) {
			dataDir = args[i+1]
			args = append(args[:i], args[i+2:]...)
			i--
		}
	}

	if len(args) == 0 {
		return printUsage()
	}

	cmd := args[0]
	cmdArgs := args[1:]

	switch cmd {
	case "pending":
		return cmdPending(dataDir)
	case "approve":
		return cmdApprove(configDir, dataDir, cmdArgs)
	case "bootstrap-admin":
		return cmdBootstrapAdmin(dataDir, cmdArgs)
	case "reject":
		return cmdReject(dataDir, cmdArgs)
	case "list-users":
		return cmdListUsers(dataDir)
	case "show-user":
		return cmdShowUser(dataDir, cmdArgs)
	case "show-room":
		return cmdShowRoom(dataDir, cmdArgs)
	case "list-admins":
		return cmdListAdmins(dataDir)
	case "search-users":
		return cmdSearchUsers(dataDir, cmdArgs)
	case "audit-log":
		return cmdAuditLog(dataDir, cmdArgs)
	case "audit-user":
		return cmdAuditUser(dataDir, cmdArgs)
	case "retire-user":
		return cmdRetireUser(dataDir, cmdArgs)
	case "unretire-user":
		return cmdUnretireUser(dataDir, cmdArgs)
	case "list-retired":
		return cmdListRetired(dataDir)
	case "promote":
		return cmdPromote(dataDir, cmdArgs)
	case "demote":
		return cmdDemote(dataDir, cmdArgs)
	case "rename-user":
		return cmdRenameUser(dataDir, cmdArgs)
	case "revoke-device":
		return cmdRevokeDevice(dataDir, cmdArgs)
	case "restore-device":
		return cmdRestoreDevice(dataDir, cmdArgs)
	case "list-devices":
		return cmdListDevices(dataDir, cmdArgs)
	case "prune-devices":
		return cmdPruneDevices(dataDir, cmdArgs)
	case "room-stats":
		return cmdRoomStats(dataDir)
	case "check-integrity":
		return cmdCheckIntegrity(dataDir, cmdArgs)
	case "add-to-room":
		return cmdAddToRoom(configDir, dataDir, cmdArgs)
	case "remove-from-room":
		return cmdRemoveFromRoom(configDir, dataDir, cmdArgs)
	case "add-room":
		return cmdAddRoom(dataDir, cmdArgs)
	case "update-topic":
		return cmdUpdateTopic(dataDir, cmdArgs)
	case "rename-room":
		return cmdRenameRoom(dataDir, cmdArgs)
	case "set-default-room":
		return cmdSetDefaultRoom(dataDir, cmdArgs)
	case "unset-default-room":
		return cmdUnsetDefaultRoom(dataDir, cmdArgs)
	case "list-default-rooms":
		return cmdListDefaultRooms(dataDir)
	case "list-rooms":
		return cmdListRooms(dataDir)
	case "retire-room":
		return cmdRetireRoom(dataDir, cmdArgs)
	case "list-retired-rooms":
		return cmdListRetiredRooms(dataDir)
	case "list-groups":
		return cmdListGroups(dataDir)
	case "block-fingerprint":
		return cmdBlockFingerprint(dataDir, cmdArgs)
	case "list-blocks":
		return cmdListBlocks(dataDir)
	case "unblock-fingerprint":
		return cmdUnblockFingerprint(dataDir, cmdArgs)
	case "status":
		return cmdStatus(configDir, dataDir)
	case "host-key":
		return cmdHostKey(configDir)
	case "purge":
		return cmdPurge(dataDir, cmdArgs)
	case "backup":
		return cmdBackup(configDir, dataDir, cmdArgs)
	case "restore":
		return cmdRestore(configDir, dataDir, cmdArgs)
	case "list-backups":
		return cmdListBackups(configDir, dataDir, cmdArgs)
	case "user":
		return cmdUser(configDir, dataDir, cmdArgs)
	case "quota-report":
		return cmdQuotaReport(dataDir, cmdArgs)
	default:
		return fmt.Errorf("unknown command: %s", cmd)
	}
}

func printUsage() error {
	fmt.Fprintln(os.Stderr, `sshkey-ctl - local admin tool for sshkey-chat

Usage: sshkey-ctl [--config DIR] [--data DIR] <command> [args]

Commands:
  pending                                 View pending key requests
  approve --key "ssh-ed25519 AAAA... name" --rooms ROOMS  Approve (display name from key comment)
  approve --key "ssh-ed25519 AAAA..." --name NAME --rooms ROOMS  Approve (override display name)
  bootstrap-admin DISPLAY_NAME            Generate admin keypair (server-side keygen, encrypted, prompts for passphrase)
  reject --fingerprint FP                 Reject/clear a pending key
  list-users                              List all users
  show-user <id|display_name>             Full user details (key, rooms, devices)
  show-room <display_name|id>             Full room details (members, topic, status)
  list-admins                             Quick view of all admin users
  search-users --name <query>             Fuzzy search by display name
  search-users --fingerprint <fp>         Find user by SSH key fingerprint
  audit-log [--since DURATION] [--limit N]  Read recent audit log entries (newest first)
  audit-user USER [--since DURATION] [--limit N]  Audit entries for a specific user
  retire-user NAME [--reason REASON] [--yes]  Retire an account (permanent, for lost keys or compromise)
  unretire-user NAME                      Reverse a mistaken retirement (does NOT restore memberships)
  promote USER_ID                         Grant admin status (live broadcast to all clients)
  demote USER_ID                          Revoke admin status (live broadcast to all clients)
  rename-user NAME NEW_DISPLAY_NAME       Force a display name change (moderation tool)
  list-retired                            List retired accounts
  add-room --name NAME --topic TOPIC       Create a room
  update-topic --room NAME --topic TEXT   Change a room's topic (live broadcast)
  rename-room --room NAME --new-name NEW  Rename a room (live broadcast)
  set-default-room NAME                   Flag a room as default (auto-join + backfill existing users)
  unset-default-room NAME                 Clear default flag (existing members stay)
  list-default-rooms                      Show flagged default rooms
  list-rooms                              List all rooms
  add-to-room --user USER --room ROOM     Add user to a room
  remove-from-room --user USER --room ROOM  Remove user from a room
  retire-room --room NAME_OR_ID [--reason REASON]
                                          Retire a room (permanent, mirrors
                                          retire-user). The display name is
                                          suffixed so the original can be
                                          reused. Connected members receive
                                          a room_retired event within a few
                                          seconds via the polling bridge.
  list-retired-rooms                      List all retired rooms
  list-groups                             List all group DMs (and their members)
  revoke-device --user USER --device DEV [--reason R]  Revoke a device
  restore-device --user USER --device DEV Restore a revoked device
  list-devices --user USER                Show all devices for a user
  prune-devices [--stale-for DURATION] [--dry-run]  Revoke stale devices (default 90d)
  room-stats                              Per-room member counts + message counts
  check-integrity [--db NAME] [--all]     Run PRAGMA integrity_check on databases
  block-fingerprint <fp> [--reason TEXT]  Block a fingerprint from connecting
  list-blocks                             Show all blocked fingerprints
  unblock-fingerprint <fp>                Remove a fingerprint from the block list
  status                                  Show server overview (users, rooms, data)
  host-key                                Print server host key fingerprint
  purge --older-than DURATION [--dry-run]  Purge old messages and vacuum DBs
  backup [--out PATH] [--label TAG]       Take a snapshot tarball (Phase 19;
                                          uses [backup].dest_dir from server.toml
                                          unless --out is specified)
  restore <tarball> [--no-pre-backup]     Restore from a backup tarball (server
                                          must be stopped). Default behavior is
                                          to create a pre-restore backup of the
                                          current state first; --no-pre-backup
                                          skips that.
  list-backups                            Show available backups in [backup].dest_dir
                                          (newest first)
  user quota-exempt <user_id> --on|--off  Toggle daily upload quota exempt flag
                                          (out-of-phase 2026-04-19; --on requires
                                          [server.quotas.user] allow_exempt_users
                                          = true in server.toml — default false)
  quota-report [--days N] [--top M]       Top users by upload volume in the
                                          recent window (default: 7 days, top 10)`)
	return nil
}

func cmdPending(dataDir string) error {
	logPath := filepath.Join(dataDir, "data", "pending-keys.log")
	data, err := os.ReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("No pending keys.")
			return nil
		}
		return err
	}
	if len(data) == 0 {
		fmt.Println("No pending keys.")
		return nil
	}
	fmt.Print(string(data))
	return nil
}

func cmdApprove(configDir, dataDir string, args []string) error {
	var displayName, key, rooms string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--name":
			if i+1 < len(args) {
				displayName = args[i+1]
				i++
			}
		case "--key":
			if i+1 < len(args) {
				key = args[i+1]
				i++
			}
		case "--rooms":
			if i+1 < len(args) {
				rooms = args[i+1]
				i++
			}
		}
	}

	if key == "" {
		return fmt.Errorf("usage: approve --key \"ssh-ed25519 AAAA... name\" --rooms ROOMS\n" +
			"   or: approve --key \"ssh-ed25519 AAAA...\" --name NAME --rooms ROOMS")
	}

	// Parse the key
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		return fmt.Errorf("invalid key: %v", err)
	}

	// Extract display name from key comment if --name not provided
	parts := strings.SplitN(strings.TrimSpace(key), " ", 3)
	if len(parts) < 2 {
		return fmt.Errorf("malformed key: expected at least \"type base64\"")
	}
	if len(parts) == 3 && displayName == "" {
		displayName = strings.TrimSpace(parts[2])
	}
	if displayName == "" {
		return fmt.Errorf("display name required: provide --name NAME or embed it in the key comment")
	}

	// Strip comment from key for storage
	keyLine := parts[0] + " " + parts[1]

	// Enforce Ed25519 key type
	if parsed.Type() != "ssh-ed25519" {
		return fmt.Errorf("only Ed25519 keys are supported, got %s", parsed.Type())
	}

	// Validate display name (trim, length, printable characters)
	displayName, err = config.ValidateDisplayName(displayName)
	if err != nil {
		return err
	}

	// Open store
	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	// Check for duplicate SSH key (same key already assigned to another user)
	if existingID := st.GetUserByKey(keyLine); existingID != "" {
		existing := st.GetUserByID(existingID)
		return fmt.Errorf("this SSH key is already assigned to user %s (%s). Each key can only belong to one account.", existing.DisplayName, existingID)
	}

	// Check display name not already in use
	allUsers := st.GetAllUsersIncludingRetired()
	for _, u := range allUsers {
		if strings.EqualFold(u.DisplayName, displayName) {
			return fmt.Errorf("display name %q is already in use by %s", displayName, u.ID)
		}
		if strings.EqualFold(u.ID, displayName) {
			return fmt.Errorf("display name %q conflicts with an existing username", displayName)
		}
	}

	// Generate nanoid username (internal ID, never shown to users)
	// Guard against astronomically unlikely collision.
	username := store.GenerateID("usr_")
	if st.GetUserByID(username) != nil {
		username = store.GenerateID("usr_")
		if st.GetUserByID(username) != nil {
			return fmt.Errorf("nanoid collision (extremely unlikely) — please retry")
		}
	}

	// Insert user into users.db
	if err := st.InsertUser(username, keyLine, displayName); err != nil {
		return fmt.Errorf("insert user: %w", err)
	}

	// Add room memberships to rooms.db
	if rooms != "" {
		for _, r := range strings.Split(rooms, ",") {
			r = strings.TrimSpace(r)
			if r == "" {
				continue
			}
			roomRecord, _ := st.GetRoomByDisplayName(r)
			if roomRecord == nil {
				fmt.Fprintf(os.Stderr, "Warning: room %q does not exist in rooms.db\n", r)
				continue
			}
			st.AddRoomMember(roomRecord.ID, username, 0)
		}
	}

	// Phase 16 default rooms: auto-add the new user to every flagged
	// room. AddRoomMember is idempotent so this is a no-op for any
	// rooms the operator already passed via --rooms (rare but
	// possible). The number added is reported in the success output
	// so operators can verify the auto-join fired.
	defaultRoomsAdded := addUserToDefaultRooms(st, username)

	fmt.Printf("Approved %s\n", displayName)
	fmt.Printf("  Username:    %s\n", username)
	fmt.Printf("  Fingerprint: %s\n", ssh.FingerprintSHA256(parsed))
	if rooms != "" {
		fmt.Printf("  Rooms:       %s\n", rooms)
	}
	if defaultRoomsAdded > 0 {
		fmt.Printf("  Default rooms auto-joined: %d\n", defaultRoomsAdded)
	}
	// The printed message below used to say "the server will detect the
	// change and apply it automatically" — a Phase 9 artifact from when
	// users lived in users.toml and the file watcher picked up changes
	// on reload. After the users.db migration (Phase 9), the file
	// watcher no longer covers user data. But for approve this is fine:
	// a newly-approved user has zero active sessions, so there's nothing
	// to notify. Next time they SSH in, the server reads their key from
	// users.db and authenticates them. No broadcast needed.
	fmt.Println("\nThe user can now connect.")
	return nil
}

func cmdReject(dataDir string, args []string) error {
	var fingerprint string
	for i := 0; i < len(args); i++ {
		if args[i] == "--fingerprint" && i+1 < len(args) {
			fingerprint = args[i+1]
			i++
		}
	}
	if fingerprint == "" {
		return fmt.Errorf("usage: reject --fingerprint FP")
	}

	// Remove from pending-keys.log
	logPath := filepath.Join(dataDir, "data", "pending-keys.log")
	data, err := os.ReadFile(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("no pending keys log found")
		}
		return err
	}

	var kept []string
	removed := false
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		if strings.Contains(line, "fingerprint="+fingerprint) {
			removed = true
		} else {
			kept = append(kept, line)
		}
	}

	if !removed {
		return fmt.Errorf("fingerprint %s not found in pending keys", fingerprint)
	}

	// Atomic write: temp file + rename
	content := strings.Join(kept, "\n") + "\n"
	tmpPath := logPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(content), 0640); err != nil {
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := os.Rename(tmpPath, logPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("rename: %w", err)
	}

	fmt.Printf("Rejected pending key %s\n", fingerprint)
	return nil
}

func cmdListUsers(dataDir string) error {
	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	users := st.GetAllUsersIncludingRetired()
	for _, u := range users {
		status := ""
		if u.Retired {
			status = "  (retired)"
		}
		fmt.Printf("%-20s display_name=%q%s\n", u.ID, u.DisplayName, status)
	}
	return nil
}

// Phase 16 Gap 3: cmdRemoveUser was deleted. It was a pre-Phase-9
// holdover from when users lived in users.toml and the only way to
// "get rid of" an account was to delete the TOML entry. Phase 12
// added retirement (tombstone + cascade) which is the correct
// invariant-preserving path, and Phase 14 locked in the "user rows
// are permanent" invariant that the groups admin model depends on
// (every group_members / room_members / message authorship /
// reaction / delivery receipt row FKs back to users.id). Hard-deleting
// a user row breaks every one of those invariants.
//
// Use cases that previously called for remove-user, and what to use
// instead:
//
//   - "Undo a mistaken approve" → use `reject` (pre-approval) or
//     `retire-user --reason admin_mistake` (post-approval). Both
//     safer, both preserve audit trail.
//   - "Stop a retired user showing up" → retirement cascade already
//     removes them from all member lists. Historical messages still
//     show their `[retired]` marker (correct behavior).
//   - "GDPR right-to-erasure" → would need a dedicated `purge-user`
//     with full cascade delete of messages/reactions/receipts/DMs.
//     Not Phase 16 scope; separate design discussion if/when real
//     compliance is required.
//   - "Clean up test accounts during development" → drop the data
//     dir entirely.
//
// The store.DeleteUser helper is still kept for bootstrap-admin's
// cleanup-on-error path (insert user → SetAdmin fails → delete the
// orphan row). It's not exposed via the CLI anymore.

func cmdRetireUser(dataDir string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: retire-user NAME [--reason REASON] [--yes]")
	}
	args, force := hasForceFlag(args)
	name := args[0]
	reason := "admin"
	for i := 1; i < len(args); i++ {
		if args[i] == "--reason" && i+1 < len(args) {
			reason = args[i+1]
			i++
		}
	}

	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	u := st.GetUserByID(name)
	if u == nil {
		return fmt.Errorf("user %q not found", name)
	}
	if u.Retired {
		return fmt.Errorf("user %q is already retired (at %s, reason: %s)", name, u.RetiredAt, u.RetiredReason)
	}

	// Phase 16: destructive-action confirmation. Retirement is
	// permanent — the user is removed from all rooms/groups/DMs and
	// their display name is suffixed so a new user can take it.
	if !force {
		rooms := st.GetUserRoomIDs(name)
		summary := fmt.Sprintf("About to retire user %q (%s). This will:\n"+
			"  - Remove from %d room(s)\n"+
			"  - Exit all group DMs\n"+
			"  - Set DM cutoffs on all 1:1 conversations\n"+
			"  - Terminate active sessions\n"+
			"  - Suffix the display name so it can be reused\n\n",
			u.DisplayName, name, len(rooms))
		if err := confirmAction(summary); err != nil {
			return err
		}
	}

	// Phase 16 Gap 1: flip the retired flag immediately so retirement
	// takes effect at the data layer regardless of whether the
	// running server processes the queue row, then enqueue a
	// pending_user_retirements row so the running server can fire
	// the downstream cascade (per-room leave events with reason
	// "user_retired", group exits with last-admin succession,
	// per-user DM cutoffs, user_retired broadcast to connected
	// clients, and active session termination for the retired user).
	//
	// If the server is down when this runs, the retirement is still
	// effective in users.db. The queue row sits there until the
	// server next starts; on startup it runs one immediate consume
	// pass before entering the ticker loop, so the cascade happens
	// as soon as the server comes back online.
	if err := st.SetUserRetired(name, reason); err != nil {
		return fmt.Errorf("retire user: %w", err)
	}
	retiredBy := fmt.Sprintf("os:%d", os.Getuid())
	if err := st.RecordPendingUserRetirement(name, retiredBy, reason); err != nil {
		// The flag flip already succeeded — log the queue failure
		// loudly but don't roll back the retirement. The operator
		// can manually re-enqueue if needed, or the user just gets
		// the cascade on the next server restart (which is the
		// fallback path the queue exists to optimize, not the
		// primary path).
		return fmt.Errorf("retire-user: flag set but queue enqueue failed (retirement is still effective in users.db, but live broadcasts to connected sessions will be skipped until the server next restarts): %w", err)
	}

	fmt.Printf("User %q retired (reason: %s).\n", name, reason)
	fmt.Println("Retirement is queued — the running server will fire leave events,")
	fmt.Println("group exits, DM cutoffs, and active session termination shortly.")
	fmt.Println("(If the server is offline, the cascade runs on its next startup.)")
	return nil
}

// cmdUnretireUser is the Phase 16 Gap 1 escape hatch for mistaken
// retirements. It reverses retire-user by flipping users.retired
// back to 0, clearing retired_at / retired_reason, stripping the
// retirement display-name suffix, and broadcasting user_unretired
// so connected clients flush the [retired] marker.
//
// It does NOT restore room/group/DM memberships. The retirement
// cascade removed the user from every shared context, and unretire
// is intentionally minimal — operators must manually re-add via
// add-to-room, in-group /add, etc. See the Phase 16 plan section
// "What unretire-user does NOT do" for the full design rationale.
func cmdUnretireUser(dataDir string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: unretire-user USER_ID\n\n" +
			"Reverses a mistaken retirement. Flips the retired flag\n" +
			"back to 0 and broadcasts user_unretired to connected\n" +
			"clients so they flush the [retired] marker. Does NOT\n" +
			"restore room/group/DM memberships — those were cleared\n" +
			"on retirement and must be re-established manually via\n" +
			"add-to-room or in-group /add.")
	}
	name := args[0]

	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	u := st.GetUserByID(name)
	if u == nil {
		return fmt.Errorf("user %q not found", name)
	}
	if !u.Retired {
		return fmt.Errorf("user %q is not currently retired — nothing to unretire", name)
	}

	// Phase 16 Gap 1: flip the retired flag immediately so the
	// unretirement takes effect at the data layer regardless of
	// whether the running server processes the queue row, then
	// enqueue a row so the running server can broadcast
	// user_unretired to connected clients.
	if err := st.SetUserUnretired(name); err != nil {
		return fmt.Errorf("unretire user: %w", err)
	}
	unretiredBy := fmt.Sprintf("os:%d", os.Getuid())
	if err := st.RecordPendingUserUnretirement(name, unretiredBy); err != nil {
		return fmt.Errorf("unretire-user: flag cleared but queue enqueue failed (unretirement is still effective in users.db, but live broadcasts to connected sessions will be skipped until the server next restarts): %w", err)
	}

	// Re-fetch the user to get the post-unretirement display name
	// (with the retirement suffix stripped) so the operator sees the
	// restored name in the success output.
	uAfter := st.GetUserByID(name)
	displayName := name
	if uAfter != nil {
		displayName = uAfter.DisplayName
	}

	fmt.Printf("User %q unretired (display name: %q).\n", name, displayName)
	fmt.Println("Connected clients will flush the [retired] marker shortly.")
	fmt.Println()
	fmt.Println("Note: room/group/DM memberships were NOT restored. To restore them:")
	fmt.Printf("  - Re-add to rooms: sshkey-ctl add-to-room --user %s --room <name>\n", name)
	fmt.Println("  - Re-add to group DMs: ask a remaining group admin to /add the user")
	fmt.Println("  - 1:1 DMs: resume automatically when the user reconnects (subject to per-user left_at cutoff)")
	return nil
}

func cmdListRetired(dataDir string) error {
	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	retired := st.GetAllRetiredUsers()
	if len(retired) == 0 {
		fmt.Println("No retired accounts.")
		return nil
	}
	for _, u := range retired {
		fmt.Printf("%-20s retired_at=%s  reason=%s  display_name=%q\n",
			u.ID, u.RetiredAt, u.RetiredReason, u.DisplayName)
	}
	return nil
}

func cmdPromote(dataDir string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: promote USER_ID")
	}
	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	u := st.GetUserByID(args[0])
	if u == nil {
		return fmt.Errorf("user %q not found", args[0])
	}
	if u.Admin {
		return fmt.Errorf("user %q is already an admin", args[0])
	}
	if err := st.SetAdmin(args[0], true); err != nil {
		return fmt.Errorf("promote: %w", err)
	}

	// Phase 16 Gap 1: enqueue a state change so the running server
	// broadcasts a fresh profile event to all connected clients.
	// Critical for the support story — users find admins via the
	// admin badge in the members list, and that badge needs to
	// propagate live so newly-promoted admins appear immediately
	// rather than on next reconnect.
	changedBy := fmt.Sprintf("os:%d", os.Getuid())
	if err := st.RecordPendingAdminStateChange(args[0], store.AdminStateChangePromote, changedBy); err != nil {
		return fmt.Errorf("promote: flag set but queue enqueue failed (admin status is still effective in users.db, but live broadcasts to connected sessions will be skipped until the server next restarts): %w", err)
	}

	fmt.Printf("Promoted %s (%s) to admin.\n", u.DisplayName, args[0])
	fmt.Println("Connected clients will see the admin badge on their next render.")
	return nil
}

func cmdDemote(dataDir string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: demote USER_ID")
	}
	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	u := st.GetUserByID(args[0])
	if u == nil {
		return fmt.Errorf("user %q not found", args[0])
	}
	if !u.Admin {
		return fmt.Errorf("user %q is not an admin", args[0])
	}
	if err := st.SetAdmin(args[0], false); err != nil {
		return fmt.Errorf("demote: %w", err)
	}

	// Phase 16 Gap 1: enqueue a state change. Same broadcast
	// mechanism as promote — connected clients flush the admin
	// badge from the demoted user immediately.
	changedBy := fmt.Sprintf("os:%d", os.Getuid())
	if err := st.RecordPendingAdminStateChange(args[0], store.AdminStateChangeDemote, changedBy); err != nil {
		return fmt.Errorf("demote: flag set but queue enqueue failed (admin status is still effective in users.db, but live broadcasts to connected sessions will be skipped until the server next restarts): %w", err)
	}

	fmt.Printf("Demoted %s (%s) from admin.\n", u.DisplayName, args[0])
	fmt.Println("Connected clients will flush the admin badge on their next render.")
	return nil
}

// cmdRenameUser is a Phase 16 Gap 1 moderation tool: it forces a
// display name change server-side, bypassing the client-initiated
// /settings flow. Use cases:
//   - Impersonation (user chose "admin" or a name confusingly
//     similar to an existing user)
//   - Offensive names (ToS violations requiring immediate
//     intervention)
//   - Squatting (user holding a name they're not actively using)
//
// The new display name is validated for format and uniqueness, then
// written via SetUserDisplayName. A pending_admin_state_changes row
// is enqueued so connected clients receive a fresh Profile event
// and update their sidebar labels, info panels, message headers,
// members overlay, and mention resolution immediately.
//
// Note: the operator-imposed name is NOT locked — if the user
// later runs /settings to change their display name again, it
// overwrites the admin-imposed name. Operators needing a hard lock
// should retire-user instead.
func cmdRenameUser(dataDir string, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: rename-user USER_ID NEW_DISPLAY_NAME\n\n" +
			"Forces a display name change server-side (moderation tool).\n" +
			"The new name is validated for format and uniqueness.\n" +
			"Connected clients receive a live profile update.")
	}
	userID := args[0]
	newName := args[1]

	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	u := st.GetUserByID(userID)
	if u == nil {
		return fmt.Errorf("user %q not found", userID)
	}

	// Validate display name format (length, printable chars, etc.).
	validated, err := config.ValidateDisplayName(newName)
	if err != nil {
		return fmt.Errorf("invalid display name %q: %w", newName, err)
	}

	// No-op if the new name matches the current name. We treat this
	// as an error (not a silent no-op) so the operator notices they
	// fat-fingered the same name.
	if strings.EqualFold(validated, u.DisplayName) {
		return fmt.Errorf("user %q already has display name %q — no change to make", userID, validated)
	}

	// Uniqueness check across all users (active and retired). Same
	// logic as cmdApprove and cmdBootstrapAdmin.
	allUsers := st.GetAllUsersIncludingRetired()
	for _, other := range allUsers {
		if other.ID == userID {
			continue
		}
		if strings.EqualFold(other.DisplayName, validated) {
			return fmt.Errorf("display name %q is already in use by %s", validated, other.ID)
		}
		if strings.EqualFold(other.ID, validated) {
			return fmt.Errorf("display name %q conflicts with an existing user ID", validated)
		}
	}

	if err := st.SetUserDisplayName(userID, validated); err != nil {
		return fmt.Errorf("rename: %w", err)
	}

	// Enqueue the broadcast.
	changedBy := fmt.Sprintf("os:%d", os.Getuid())
	if err := st.RecordPendingAdminStateChange(userID, store.AdminStateChangeRename, changedBy); err != nil {
		return fmt.Errorf("rename-user: name updated but queue enqueue failed (rename is still effective in users.db, but live broadcasts to connected sessions will be skipped until the server next restarts): %w", err)
	}

	fmt.Printf("Renamed %s: %q → %q.\n", userID, u.DisplayName, validated)
	fmt.Println("Connected clients will see the new display name on their next render.")
	return nil
}

func cmdAddToRoom(configDir, dataDir string, args []string) error {
	var user, room string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--user":
			if i+1 < len(args) {
				user = args[i+1]
				i++
			}
		case "--room":
			if i+1 < len(args) {
				room = args[i+1]
				i++
			}
		}
	}
	if user == "" || room == "" {
		return fmt.Errorf("usage: add-to-room --user USER --room ROOM")
	}

	// Validate user exists
	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	u := st.GetUserByID(user)
	if u == nil {
		return fmt.Errorf("user %q not found", user)
	}
	if u.Retired {
		return fmt.Errorf("user %q is retired and cannot be added to rooms", user)
	}

	// Validate room exists in rooms.db
	roomRecord, _ := st.GetRoomByDisplayName(room)
	if roomRecord == nil {
		return fmt.Errorf("room %q does not exist", room)
	}

	// Check not already a member
	if st.IsRoomMemberByID(roomRecord.ID, user) {
		return fmt.Errorf("user %q is already in room %q", user, room)
	}

	if err := st.AddRoomMember(roomRecord.ID, user, 0); err != nil {
		return fmt.Errorf("add member: %w", err)
	}

	// Phase 20: clear any prior leave-history rows for this (user, room).
	// Rejoining is the affirmative undo of a prior leave — without this,
	// stale rows would re-surface on the user's next catchup handshake.
	// Best-effort: a cleanup failure is also defended against at the
	// catchup-query level (GetUserLeftRoomsCatchup filters against
	// room_members via the caller).
	if err := st.DeleteUserLeftRoomRows(user, roomRecord.ID); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to clear prior leave history for %s in %s: %v\n", user, room, err)
	}

	// Phase 20: record a "join" room_event in the per-room audit trail.
	// Other members see "alice added bob to the room" inline on their
	// next sync (CLI adds don't have a live broadcast wire-up yet; that's
	// a separate future item). Best-effort: audit failure doesn't block
	// the add.
	initiatedBy := fmt.Sprintf("os:%d", os.Getuid())
	if err := st.RecordRoomEvent(
		roomRecord.ID, "join", user, initiatedBy, "", "", false, time.Now().Unix(),
	); err != nil {
		fmt.Fprintf(os.Stderr, "warning: failed to record room join event for %s in %s: %v\n", user, room, err)
	}

	fmt.Printf("Added %s (%s) to room %q.\n", u.DisplayName, user, room)
	return nil
}

func cmdRemoveFromRoom(configDir, dataDir string, args []string) error {
	var user, room string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--user":
			if i+1 < len(args) {
				user = args[i+1]
				i++
			}
		case "--room":
			if i+1 < len(args) {
				room = args[i+1]
				i++
			}
		}
	}
	if user == "" || room == "" {
		return fmt.Errorf("usage: remove-from-room --user USER --room ROOM")
	}

	// Validate user exists
	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	u := st.GetUserByID(user)
	if u == nil {
		return fmt.Errorf("user %q not found", user)
	}

	roomRecord, _ := st.GetRoomByDisplayName(room)
	if roomRecord == nil {
		return fmt.Errorf("room %q does not exist", room)
	}

	if !st.IsRoomMemberByID(roomRecord.ID, user) {
		return fmt.Errorf("user %q is not in room %q", user, room)
	}

	// Phase 20 (Option D): enqueue a row in pending_remove_from_room
	// — a pure queue table matching the shape of the other five
	// Phase 16 pending_* queues. The server's
	// runRemoveFromRoomProcessor drains the queue and calls
	// performRoomLeave, which:
	//   - removes the user from room_members
	//   - writes the authoritative history row to user_left_rooms
	//   - records a room_event audit row (leave) in the per-room DB
	//   - broadcasts room_event{leave, reason='removed'} to remaining
	//     members so client UIs render "alice was removed by an admin"
	//   - echoes room_left to the kicked user's connected sessions
	//   - marks the room for epoch rotation (forward secrecy)
	initiatedBy := fmt.Sprintf("os:%d", os.Getuid())
	if err := st.RecordPendingRemoveFromRoom(user, roomRecord.ID, "removed", initiatedBy); err != nil {
		return fmt.Errorf("enqueue remove-from-room: %w", err)
	}

	fmt.Printf("Removal of %s (%s) from room %q queued.\n", u.DisplayName, user, room)
	fmt.Println("The server will run the leave cascade and broadcast within a few seconds.")
	return nil
}

func cmdAddRoom(dataDir string, args []string) error {
	var name, topic string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--name":
			if i+1 < len(args) {
				name = args[i+1]
				i++
			}
		case "--topic":
			if i+1 < len(args) {
				topic = args[i+1]
				i++
			}
		}
	}
	if name == "" {
		return fmt.Errorf("usage: add-room --name NAME [--topic TOPIC]")
	}

	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	// Check name not taken
	existing, _ := st.GetRoomByDisplayName(name)
	if existing != nil {
		return fmt.Errorf("room %q already exists", name)
	}

	id := store.GenerateRoomID()
	_, err = st.RoomsDB().Exec(
		`INSERT INTO rooms (id, display_name, topic) VALUES (?, ?, ?)`,
		id, name, topic)
	if err != nil {
		return fmt.Errorf("create room: %w", err)
	}

	fmt.Printf("Created room %q (id: %s)\n", name, id)
	return nil
}

// cmdUpdateTopic is the Phase 16 Gap 1 implementation of room topic
// updates. Closes Phase 18's deferred write path: Phase 18 shipped
// the display-only side (rooms render their topic in the messages
// header and info panel), and this command finally lets operators
// CHANGE topics post-creation with live propagation to connected
// members.
//
// The room is identified by display name (the same way `add-room`
// and `retire-room` accept it). Errors on missing or retired rooms.
func cmdUpdateTopic(dataDir string, args []string) error {
	var roomName, topic string
	topicSet := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--room":
			if i+1 < len(args) {
				roomName = args[i+1]
				i++
			}
		case "--topic":
			if i+1 < len(args) {
				topic = args[i+1]
				topicSet = true
				i++
			}
		}
	}
	if roomName == "" || !topicSet {
		return fmt.Errorf("usage: update-topic --room NAME --topic TEXT")
	}

	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	room, _ := st.GetRoomByDisplayName(roomName)
	if room == nil {
		return fmt.Errorf("room %q not found", roomName)
	}
	if room.Retired {
		return fmt.Errorf("room %q is retired — cannot update topic", roomName)
	}
	if room.Topic == topic {
		return fmt.Errorf("room %q already has topic %q — no change to make", roomName, topic)
	}

	if err := st.SetRoomTopic(room.ID, topic); err != nil {
		return fmt.Errorf("update topic: %w", err)
	}

	// Phase 16 Gap 1: enqueue a room update so connected members
	// see the new topic on their next render.
	changedBy := fmt.Sprintf("os:%d", os.Getuid())
	if err := st.RecordPendingRoomUpdate(room.ID, store.RoomUpdateActionUpdateTopic, changedBy, topic); err != nil {
		return fmt.Errorf("update-topic: topic written but queue enqueue failed (topic is still effective in rooms.db, but live broadcasts to connected members will be skipped until the server next restarts): %w", err)
	}

	fmt.Printf("Updated topic for room %q.\n", roomName)
	fmt.Println("Connected members will see the new topic on their next render.")
	return nil
}

// cmdRenameRoom is the Phase 16 Gap 1 implementation of room renaming.
// The room is identified by its CURRENT display name, and the new
// name must pass the case-insensitive uniqueness check enforced by
// the existing idx_rooms_display_name_lower index.
//
// Errors on missing room, retired room, duplicate new name, or
// no-change rename (same name as current).
func cmdRenameRoom(dataDir string, args []string) error {
	var roomName, newName string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--room":
			if i+1 < len(args) {
				roomName = args[i+1]
				i++
			}
		case "--new-name":
			if i+1 < len(args) {
				newName = args[i+1]
				i++
			}
		}
	}
	if roomName == "" || newName == "" {
		return fmt.Errorf("usage: rename-room --room CURRENT_NAME --new-name NEW_NAME")
	}

	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	room, _ := st.GetRoomByDisplayName(roomName)
	if room == nil {
		return fmt.Errorf("room %q not found", roomName)
	}
	if room.Retired {
		return fmt.Errorf("room %q is retired — cannot rename", roomName)
	}
	if strings.EqualFold(room.DisplayName, newName) {
		return fmt.Errorf("room %q already has display name %q — no change to make", roomName, newName)
	}

	// Uniqueness check (also enforced at the schema layer, but
	// pre-checking gives a clearer error message).
	existing, _ := st.GetRoomByDisplayName(newName)
	if existing != nil && existing.ID != room.ID {
		return fmt.Errorf("display name %q is already in use by room %s", newName, existing.ID)
	}

	if err := st.SetRoomDisplayName(room.ID, newName); err != nil {
		return fmt.Errorf("rename room: %w", err)
	}

	changedBy := fmt.Sprintf("os:%d", os.Getuid())
	if err := st.RecordPendingRoomUpdate(room.ID, store.RoomUpdateActionRenameRoom, changedBy, newName); err != nil {
		return fmt.Errorf("rename-room: name written but queue enqueue failed (rename is still effective in rooms.db, but live broadcasts to connected members will be skipped until the server next restarts): %w", err)
	}

	fmt.Printf("Renamed room %q → %q.\n", roomName, newName)
	fmt.Println("Connected members will see the new name on their next render.")
	return nil
}

func cmdListRooms(dataDir string) error {
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

	for _, r := range rooms {
		members := st.GetRoomMemberIDsByRoomID(r.ID)
		// Phase 16 default rooms: append a [default] marker for
		// flagged rooms. Operators see at a glance which rooms
		// every new user auto-joins. Retired rooms always have
		// is_default=0 (cleared in SetRoomRetired) so the two
		// markers never appear together.
		status := ""
		if r.IsDefault {
			status = " [default]"
		}
		if r.Retired {
			status += " (retired)"
		}
		fmt.Printf("%-30s members=%d  topic=%q%s\n", r.DisplayName, len(members), r.Topic, status)
	}
	return nil
}

// cmdRetireRoom retires a room by marking it as retired in rooms.db
// and queueing a broadcast notification for the running server. Mirrors
// cmdRetireUser's shape (Phase 9) but adds the queue insert that
// Phase 15 will retrofit onto cmdRetireUser.
//
// Security model: sshkey-ctl is designed to run locally on the server
// box only — the chat protocol does not accept admin commands over the
// wire. See decision_no_remote_admin_commands.md memory note. This
// function opens the local rooms.db + data.db directly and never
// connects to the running server. The "live notification" half is
// handled by a polling goroutine in the running server that watches
// pending_room_retirements.
//
// Two DB writes, best-effort (non-transactional, they're in different
// DB files):
//
//  1. SetRoomRetired on rooms.db — the authoritative state change.
//     Suffixes the display name, sets retired_at/retired_by, flips
//     retired = 1. Errors if the room doesn't exist or is already
//     retired.
//  2. RecordPendingRoomRetirement on data.db — queues the broadcast.
//     Best-effort: if this fails, we warn and exit 0 anyway. The
//     retirement is already recorded (step 1 succeeded), so connected
//     clients will discover it lazily via IsRoomRetired checks on
//     writes and via the retired_rooms catchup on next reconnect.
//     Admin can re-run the command to retry the queue insert.
func cmdRetireRoom(dataDir string, args []string) error {
	args, force := hasForceFlag(args)
	var roomArg, reason string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--room":
			if i+1 < len(args) {
				roomArg = args[i+1]
				i++
			}
		case "--reason":
			if i+1 < len(args) {
				reason = args[i+1]
				i++
			}
		}
	}
	if roomArg == "" {
		return fmt.Errorf("usage: retire-room --room NAME_OR_ID [--reason REASON]")
	}

	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	// Resolve the room argument. Accept either a nanoid ("room_xxx")
	// or a display name (Q7). Prefix check first — if it looks like a
	// nanoid, try that path; otherwise fall back to display-name lookup.
	var roomID string
	var room *store.RoomRecord
	if strings.HasPrefix(roomArg, "room_") {
		room, _ = st.GetRoomByID(roomArg)
		if room != nil {
			roomID = room.ID
		}
	}
	if room == nil {
		room, _ = st.GetRoomByDisplayName(roomArg)
		if room != nil {
			roomID = room.ID
		}
	}
	if room == nil {
		return fmt.Errorf("room %q not found", roomArg)
	}

	if room.Retired {
		return fmt.Errorf("room %q is already retired (at %s, by %s, now %q)",
			roomArg, room.RetiredAt, room.RetiredBy, room.DisplayName)
	}

	// Phase 16: destructive-action confirmation. Room retirement
	// renames the display name (suffixed to free the original name
	// for reuse) and connected members receive a room_retired event.
	// A retired room cannot be unretired — the operator must create
	// a new room with the same display name if they want to undo.
	if !force {
		members := st.GetRoomMemberIDsByRoomID(roomID)
		summary := fmt.Sprintf("About to retire room %q (%s). This will:\n"+
			"  - Suffix the display name so it can be reused\n"+
			"  - Set the room to read-only (writes rejected)\n"+
			"  - Broadcast room_retired to %d connected member(s)\n"+
			"  - Clear the default-room flag (if set)\n"+
			"  - This action is NOT reversible — no unretire-room command exists.\n\n",
			room.DisplayName, roomID, len(members))
		if err := confirmAction(summary); err != nil {
			return err
		}
	}

	// We need the caller's user ID for the retired_by column. The CLI
	// runs with shell-level auth (whoever has filesystem access), not
	// with a specific user identity, so we use a sentinel value. This
	// parallels cmdRetireUser's `reason = "admin"` default — it
	// documents intent rather than identifying a specific person.
	const retiredBy = "cli-admin"
	if reason == "" {
		reason = "admin"
	}

	// Step 1: mark the room retired in rooms.db (authoritative).
	if err := st.SetRoomRetired(roomID, retiredBy, reason); err != nil {
		return fmt.Errorf("retire room: %w", err)
	}

	// Re-fetch to get the post-retirement suffixed display name so we
	// can print it in the confirmation.
	updated, _ := st.GetRoomByID(roomID)
	newName := roomID
	if updated != nil {
		newName = updated.DisplayName
	}

	// Step 2: queue a broadcast notification for the running server.
	// Best-effort — log a warning on failure but exit successfully,
	// since the retirement itself took effect in step 1.
	if err := st.RecordPendingRoomRetirement(roomID, retiredBy, reason); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: room retired but broadcast queue insert failed: %v\n", err)
		fmt.Fprintln(os.Stderr, "Connected clients will detect the retirement lazily via write rejections or reconnect catchup.")
		fmt.Fprintln(os.Stderr, "You can re-run retire-room to retry the queue insert.")
		// Still print the success line — the retirement is recorded.
	}

	fmt.Printf("Room retired: %s (now: %s). Connected clients will be notified within a few seconds.\n",
		roomID, newName)
	return nil
}

// cmdListRetiredRooms prints every retired room from rooms.db. Mirrors
// cmdListRetired (which lists retired users). Useful after retire-room
// to confirm the suffixed display name, or to audit previous retirements.
func cmdListRetiredRooms(dataDir string) error {
	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	rooms, err := st.GetAllRooms()
	if err != nil {
		return fmt.Errorf("get rooms: %w", err)
	}

	found := 0
	for _, r := range rooms {
		if !r.Retired {
			continue
		}
		members := st.GetRoomMemberIDsByRoomID(r.ID)
		fmt.Printf("%-30s id=%s  retired_at=%s  retired_by=%s  members=%d\n",
			r.DisplayName, r.ID, r.RetiredAt, r.RetiredBy, len(members))
		found++
	}
	if found == 0 {
		fmt.Println("No retired rooms.")
	}
	return nil
}

// cmdListGroups dumps every group DM and its current members. Group
// IDs are nanoid-style and not human-friendly, so this is the primary
// way to find a specific group when debugging or inspecting state.
// Phase 14 removed the CLI's remove-from-group escape hatch — all
// group moderation now lives in-group via admin protocol verbs.
func cmdListGroups(dataDir string) error {
	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	rows, err := st.DataDB().Query(
		`SELECT id, COALESCE(name, '') FROM group_conversations ORDER BY id`,
	)
	if err != nil {
		return fmt.Errorf("query groups: %w", err)
	}
	defer rows.Close()

	type groupRow struct {
		id   string
		name string
	}
	var groups []groupRow
	for rows.Next() {
		var g groupRow
		if err := rows.Scan(&g.id, &g.name); err != nil {
			return fmt.Errorf("scan: %w", err)
		}
		groups = append(groups, g)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("rows: %w", err)
	}

	if len(groups) == 0 {
		fmt.Println("No groups.")
		return nil
	}

	for _, g := range groups {
		members, _ := st.GetGroupMembers(g.id)
		name := g.name
		if name == "" {
			name = "(unnamed)"
		}
		fmt.Printf("%-25s name=%q members=%d %v\n", g.id, name, len(members), members)
	}
	return nil
}

func cmdRevokeDevice(dataDir string, args []string) error {
	var user, device, reason string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--user":
			if i+1 < len(args) {
				user = args[i+1]
				i++
			}
		case "--device":
			if i+1 < len(args) {
				device = args[i+1]
				i++
			}
		case "--reason":
			if i+1 < len(args) {
				reason = args[i+1]
				i++
			}
		}
	}
	if user == "" || device == "" {
		return fmt.Errorf("usage: revoke-device --user USER --device DEVICE [--reason REASON]")
	}
	if !strings.HasPrefix(device, "dev_") {
		return fmt.Errorf("invalid device ID %q (expected dev_ prefix)", device)
	}
	if reason == "" {
		reason = "admin_action"
	}

	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	if err := st.RevokeDevice(user, device, reason); err != nil {
		return fmt.Errorf("revoke device: %w", err)
	}

	// Phase 16 Gap 1: enqueue a row so the running server can
	// terminate any active SSH session for this device. The
	// data-layer revocation above is sufficient to block FUTURE
	// authentication attempts (the revoked_devices entry will
	// reject the next connect), but it doesn't kick the device
	// off its currently-open channel — that's what the queue
	// processor does.
	revokedBy := fmt.Sprintf("os:%d", os.Getuid())
	if err := st.RecordPendingDeviceRevocation(user, device, reason, revokedBy); err != nil {
		return fmt.Errorf("revoke-device: data-layer revocation succeeded but queue enqueue failed (the device is blocked from future logins, but if it has an active session right now that session will only close on its own — restart the server to force-kick it): %w", err)
	}

	fmt.Printf("Device %s for user %s revoked.\n", device, user)
	fmt.Println("If the device has an active session, it will be kicked within a few seconds.")
	return nil
}

func cmdRestoreDevice(dataDir string, args []string) error {
	var user, device string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--user":
			if i+1 < len(args) {
				user = args[i+1]
				i++
			}
		case "--device":
			if i+1 < len(args) {
				device = args[i+1]
				i++
			}
		}
	}
	if user == "" || device == "" {
		return fmt.Errorf("usage: restore-device --user USER --device DEVICE")
	}
	if !strings.HasPrefix(device, "dev_") {
		return fmt.Errorf("invalid device ID %q (expected dev_ prefix)", device)
	}

	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	if err := st.RestoreDevice(user, device); err != nil {
		return fmt.Errorf("restore device: %w", err)
	}
	fmt.Printf("Device %s for user %s restored.\n", device, user)
	return nil
}

func cmdStatus(configDir, dataDir string) error {
	// Process state (Phase 19 Step 2: read the server lockfile).
	// Reported first so operators running `status` against a failed
	// server see the most important signal up top.
	lockPath := filepath.Join(dataDir, "sshkey-server.pid")
	processLine := "not running"
	if info, err := lockfile.Read(lockPath); err == nil {
		if info.Alive {
			processLine = fmt.Sprintf("running (PID %d) since %s",
				info.PID, info.StartedAt.UTC().Format(time.RFC3339))
		} else {
			// Stale lockfile — process is dead but file remains.
			// Usually means an ungraceful crash; flag it so the
			// operator can investigate before the next start cleans it.
			processLine = fmt.Sprintf("not running (stale lockfile — PID %d exited)", info.PID)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		// Lockfile exists but is unreadable — worth surfacing.
		processLine = fmt.Sprintf("unknown (lockfile unreadable: %v)", err)
	}

	// Users + Rooms from store
	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	active := len(st.GetAllUsers())
	retired := len(st.GetAllRetiredUsers())

	rooms, err := st.GetAllRooms()
	if err != nil {
		return fmt.Errorf("get rooms: %w", err)
	}

	// Pending keys
	pendingCount := 0
	logPath := filepath.Join(dataDir, "data", "pending-keys.log")
	if data, err := os.ReadFile(logPath); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.TrimSpace(line) != "" {
				pendingCount++
			}
		}
	}

	// Data size
	dataPath := filepath.Join(dataDir, "data")
	var totalSize int64
	var dbCount int
	if entries, err := os.ReadDir(dataPath); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".db") {
				dbCount++
				if entryInfo, err := e.Info(); err == nil {
					totalSize += entryInfo.Size()
				}
			}
		}
	}

	// Backup scheduler stats (Phase 19 Step 5). Reads the sidecar
	// JSON the scheduler writes after each attempt. Absent file →
	// all zeros (scheduler hasn't run yet, or [backup].enabled=false).
	bkFails, bkSuccesses, bkLastSuccess, bkLastFailure, bkLastErr := server.ReadBackupStatsForCLI(dataDir)

	fmt.Println("sshkey-chat server status")
	fmt.Println("─────────────────────────")
	fmt.Printf("Process:      %s\n", processLine)
	fmt.Printf("Users:        %d active, %d retired\n", active, retired)
	fmt.Printf("Rooms:        %d\n", len(rooms))
	fmt.Printf("Pending keys: %d\n", pendingCount)
	fmt.Printf("Databases:    %d files, %s\n", dbCount, formatBytes(totalSize))
	fmt.Printf("Backups:      %d successes, %d failures\n", bkSuccesses, bkFails)
	if !bkLastSuccess.IsZero() {
		fmt.Printf("              last success: %s\n", bkLastSuccess.UTC().Format(time.RFC3339))
	}
	if !bkLastFailure.IsZero() {
		fmt.Printf("              last failure: %s\n", bkLastFailure.UTC().Format(time.RFC3339))
		if bkLastErr != "" {
			fmt.Printf("              last error:   %s\n", bkLastErr)
		}
	}
	fmt.Printf("Config:       %s\n", configDir)
	fmt.Printf("Data:         %s\n", dataDir)
	return nil
}

func formatBytes(b int64) string {
	switch {
	case b >= 1<<30:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(1<<30))
	case b >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(1<<20))
	case b >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(1<<10))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

func cmdHostKey(configDir string) error {
	keyPath := filepath.Join(configDir, "host_key")
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("no host key found at %s: %w", keyPath, err)
	}

	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return fmt.Errorf("failed to parse host key: %w", err)
	}

	fmt.Printf("Host key fingerprint: %s\n", ssh.FingerprintSHA256(signer.PublicKey()))
	fmt.Printf("Key type: %s\n", signer.PublicKey().Type())
	fmt.Printf("Path: %s\n", keyPath)
	return nil
}

func cmdPurge(dataDir string, args []string) error {
	var olderThan string
	var dryRun bool
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--older-than":
			if i+1 < len(args) {
				olderThan = args[i+1]
				i++
			}
		case "--dry-run":
			dryRun = true
		}
	}
	if olderThan == "" {
		return fmt.Errorf("usage: purge --older-than DURATION [--dry-run]\n  DURATION: e.g., 5y, 1y, 180d")
	}

	days, err := parseDurationDays(olderThan)
	if err != nil {
		return err
	}

	cutoff := time.Now().Unix() - int64(days*86400)

	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	// Find all room and conversation DBs
	dataPath := filepath.Join(dataDir, "data")
	entries, err := os.ReadDir(dataPath)
	if err != nil {
		return fmt.Errorf("read data dir: %w", err)
	}

	totalDeleted := 0
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".db") || name == "users.db" {
			continue
		}

		var db *sql.DB
		if strings.HasPrefix(name, "room-") {
			roomName := strings.TrimPrefix(strings.TrimSuffix(name, ".db"), "room-")
			db, err = st.RoomDB(roomName)
		} else if strings.HasPrefix(name, "group-") {
			groupID := strings.TrimPrefix(strings.TrimSuffix(name, ".db"), "group-")
			db, err = st.GroupDB(groupID)
		} else if strings.HasPrefix(name, "dm-") {
			dmID := strings.TrimPrefix(strings.TrimSuffix(name, ".db"), "dm-")
			db, err = st.DMDB(dmID)
		} else {
			continue
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "  skip %s: %v\n", name, err)
			continue
		}

		var count int
		db.QueryRow("SELECT COUNT(*) FROM messages WHERE ts < ?", cutoff).Scan(&count)

		if count == 0 {
			continue
		}

		if dryRun {
			fmt.Printf("  %s: would delete %d messages\n", name, count)
		} else {
			// Collect file IDs from messages being purged. For each,
			// remove the bytes on disk + file_hashes row + file_contexts
			// binding (Phase 17 Step 4.f — the binding cascade keeps the
			// "file exists iff bound" invariant intact after bulk purge).
			fileRows, _ := db.Query("SELECT file_ids FROM messages WHERE ts < ? AND file_ids != ''", cutoff)
			if fileRows != nil {
				for fileRows.Next() {
					var fids string
					fileRows.Scan(&fids)
					if fids != "" {
						for _, fid := range strings.Split(strings.Trim(fids, "[]\""), ",") {
							fid = strings.Trim(fid, " \"")
							if fid != "" {
								os.Remove(filepath.Join(dataDir, "data", "files", fid))
								st.DataDB().Exec("DELETE FROM file_hashes WHERE file_id = ?", fid)
								st.DataDB().Exec("DELETE FROM file_contexts WHERE file_id = ?", fid)
							}
						}
					}
				}
				fileRows.Close()
			}
			db.Exec("DELETE FROM messages WHERE ts < ?", cutoff)
			db.Exec("DELETE FROM reactions WHERE ts < ?", cutoff)
			db.Exec("VACUUM")
			fmt.Printf("  %s: deleted %d messages, vacuumed\n", name, count)
		}
		totalDeleted += count
	}

	// Epoch keys are tiny (~100 bytes each) and needed to decrypt
	// historical messages. Leave them even when messages are purged.

	if dryRun {
		fmt.Printf("\nDry run: would delete %d messages total (older than %s)\n", totalDeleted, olderThan)
	} else {
		fmt.Printf("\nPurged %d messages total (older than %s)\n", totalDeleted, olderThan)
	}
	return nil
}

func parseDurationDays(s string) (int, error) {
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid duration: %s", s)
	}
	unit := s[len(s)-1]
	numStr := s[:len(s)-1]
	var num int
	_, err := fmt.Sscanf(numStr, "%d", &num)
	if err != nil {
		return 0, fmt.Errorf("invalid duration: %s", s)
	}
	switch unit {
	case 'd':
		return num, nil
	case 'm':
		return num * 30, nil
	case 'y':
		return num * 365, nil
	default:
		return 0, fmt.Errorf("unknown duration unit %q (use d, m, or y)", string(unit))
	}
}
