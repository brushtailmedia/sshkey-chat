package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
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
	case "reject":
		return cmdReject(dataDir, cmdArgs)
	case "list-users":
		return cmdListUsers(dataDir)
	case "remove-user":
		return cmdRemoveUser(dataDir, cmdArgs)
	case "retire-user":
		return cmdRetireUser(dataDir, cmdArgs)
	case "list-retired":
		return cmdListRetired(dataDir)
	case "promote":
		return cmdPromote(dataDir, cmdArgs)
	case "demote":
		return cmdDemote(dataDir, cmdArgs)
	case "revoke-device":
		return cmdRevokeDevice(dataDir, cmdArgs)
	case "restore-device":
		return cmdRestoreDevice(dataDir, cmdArgs)
	case "add-to-room":
		return cmdAddToRoom(configDir, dataDir, cmdArgs)
	case "remove-from-room":
		return cmdRemoveFromRoom(configDir, dataDir, cmdArgs)
	case "add-room":
		return cmdAddRoom(dataDir, cmdArgs)
	case "list-rooms":
		return cmdListRooms(dataDir)
	case "retire-room":
		return cmdRetireRoom(dataDir, cmdArgs)
	case "list-retired-rooms":
		return cmdListRetiredRooms(dataDir)
	case "list-groups":
		return cmdListGroups(dataDir)
	case "status":
		return cmdStatus(configDir, dataDir)
	case "host-key":
		return cmdHostKey(configDir)
	case "purge":
		return cmdPurge(dataDir, cmdArgs)
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
  reject --fingerprint FP                 Reject/clear a pending key
  list-users                              List all users
  remove-user NAME                        Remove a user
  retire-user NAME [--reason REASON]      Retire an account (permanent, for lost keys or compromise)
  list-retired                            List retired accounts
  add-room --name NAME --topic TOPIC       Create a room
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
  revoke-device --user USER --device DEV  Revoke a device
  restore-device --user USER --device DEV Restore a revoked device
  status                                  Show server overview (users, rooms, data)
  host-key                                Print server host key fingerprint
  purge --older-than DURATION [--dry-run]  Purge old messages and vacuum DBs`)
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
			if i+1 < len(args) { displayName = args[i+1]; i++ }
		case "--key":
			if i+1 < len(args) { key = args[i+1]; i++ }
		case "--rooms":
			if i+1 < len(args) { rooms = args[i+1]; i++ }
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

	fmt.Printf("Approved %s\n", displayName)
	fmt.Printf("  Username:    %s\n", username)
	fmt.Printf("  Fingerprint: %s\n", ssh.FingerprintSHA256(parsed))
	if rooms != "" {
		fmt.Printf("  Rooms:       %s\n", rooms)
	}
	fmt.Println("\nThe server will detect the change and apply it automatically.")
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

func cmdRemoveUser(dataDir string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: remove-user NAME")
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

	if u.Retired {
		fmt.Fprintf(os.Stderr, "Warning: %q is a retired account. Removing it will lose the retirement record.\n", name)
		fmt.Fprintf(os.Stderr, "Use retire-user instead if you want to preserve the record.\n")
	}

	if err := st.DeleteUser(name); err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	st.RemoveAllRoomMembers(name)

	fmt.Printf("Removed %s (%s).\n", u.DisplayName, name)
	return nil
}

func cmdRetireUser(dataDir string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: retire-user NAME [--reason REASON]")
	}
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

	if err := st.SetUserRetired(name, reason); err != nil {
		return fmt.Errorf("retire user: %w", err)
	}

	fmt.Printf("User %q retired (reason: %s).\n", name, reason)
	fmt.Println("The running server (if any) will detect the change via config watch")
	fmt.Println("and fire leave events + epoch rotations automatically.")
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
	fmt.Printf("Promoted %s (%s) to admin.\n", u.DisplayName, args[0])
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
	fmt.Printf("Demoted %s (%s) from admin.\n", u.DisplayName, args[0])
	return nil
}

func cmdAddToRoom(configDir, dataDir string, args []string) error {
	var user, room string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--user":
			if i+1 < len(args) { user = args[i+1]; i++ }
		case "--room":
			if i+1 < len(args) { room = args[i+1]; i++ }
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

	fmt.Printf("Added %s (%s) to room %q.\n", u.DisplayName, user, room)
	return nil
}

func cmdRemoveFromRoom(configDir, dataDir string, args []string) error {
	var user, room string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--user":
			if i+1 < len(args) { user = args[i+1]; i++ }
		case "--room":
			if i+1 < len(args) { room = args[i+1]; i++ }
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

	if err := st.RemoveRoomMember(roomRecord.ID, user); err != nil {
		return fmt.Errorf("remove member: %w", err)
	}

	fmt.Printf("Removed %s (%s) from room %q.\n", u.DisplayName, user, room)
	return nil
}

func cmdAddRoom(dataDir string, args []string) error {
	var name, topic string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--name":
			if i+1 < len(args) { name = args[i+1]; i++ }
		case "--topic":
			if i+1 < len(args) { topic = args[i+1]; i++ }
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
		status := ""
		if r.Retired {
			status = " (retired)"
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
	var user, device string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--user":
			if i+1 < len(args) { user = args[i+1]; i++ }
		case "--device":
			if i+1 < len(args) { device = args[i+1]; i++ }
		}
	}
	if user == "" || device == "" {
		return fmt.Errorf("usage: revoke-device --user USER --device DEVICE")
	}
	if !strings.HasPrefix(device, "dev_") {
		return fmt.Errorf("invalid device ID %q (expected dev_ prefix)", device)
	}

	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	if err := st.RevokeDevice(user, device, "admin_action"); err != nil {
		return fmt.Errorf("revoke device: %w", err)
	}
	fmt.Printf("Device %s for user %s revoked.\n", device, user)
	return nil
}

func cmdRestoreDevice(dataDir string, args []string) error {
	var user, device string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--user":
			if i+1 < len(args) { user = args[i+1]; i++ }
		case "--device":
			if i+1 < len(args) { device = args[i+1]; i++ }
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
				if info, err := e.Info(); err == nil {
					totalSize += info.Size()
				}
			}
		}
	}

	fmt.Println("sshkey-chat server status")
	fmt.Println("─────────────────────────")
	fmt.Printf("Users:        %d active, %d retired\n", active, retired)
	fmt.Printf("Rooms:        %d\n", len(rooms))
	fmt.Printf("Pending keys: %d\n", pendingCount)
	fmt.Printf("Databases:    %d files, %s\n", dbCount, formatBytes(totalSize))
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
			if i+1 < len(args) { olderThan = args[i+1]; i++ }
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
			// Collect file IDs from messages being purged
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
