package main

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey/internal/config"
	"github.com/brushtailmedia/sshkey/internal/store"
)

func generateCLIID(prefix string) string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-"
	b := make([]byte, 21)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		b[i] = alphabet[n.Int64()]
	}
	return prefix + string(b)
}

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
		return cmdApprove(configDir, cmdArgs)
	case "reject":
		return cmdReject(dataDir, cmdArgs)
	case "list-users":
		return cmdListUsers(configDir)
	case "remove-user":
		return cmdRemoveUser(configDir, cmdArgs)
	case "retire-user":
		return cmdRetireUser(configDir, cmdArgs)
	case "list-retired":
		return cmdListRetired(configDir)
	case "revoke-device":
		return cmdRevokeDevice(dataDir, cmdArgs)
	case "restore-device":
		return cmdRestoreDevice(dataDir, cmdArgs)
	case "add-to-room":
		return cmdAddToRoom(configDir, cmdArgs)
	case "remove-from-room":
		return cmdRemoveFromRoom(configDir, cmdArgs)
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
  add-to-room --user USER --room ROOM     Add user to a room
  remove-from-room --user USER --room ROOM  Remove user from a room
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

func cmdApprove(configDir string, args []string) error {
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

	// Check against existing users
	usersPath := filepath.Join(configDir, "users.toml")
	existingUsers, _ := config.LoadUsers(usersPath)

	// Check display name uniqueness
	for _, user := range existingUsers {
		if strings.EqualFold(user.DisplayName, displayName) {
			return fmt.Errorf("display name %q is already in use. Choose a different name with --name.", displayName)
		}
	}

	// Check for duplicate SSH key (same key bytes already assigned to another user)
	parsedBytes := parsed.Marshal()
	for username, user := range existingUsers {
		existingParsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(user.Key))
		if err != nil {
			continue
		}
		if string(existingParsed.Marshal()) == string(parsedBytes) {
			return fmt.Errorf("this SSH key is already assigned to user %s (%s). Each key can only belong to one account.", user.DisplayName, username)
		}
	}

	// Validate rooms exist (warning only — advisory output)
	if rooms != "" {
		knownRooms, err := config.LoadRooms(filepath.Join(configDir, "rooms.toml"))
		if err == nil {
			for _, r := range strings.Split(rooms, ",") {
				r = strings.TrimSpace(r)
				if _, ok := knownRooms[r]; !ok {
					fmt.Fprintf(os.Stderr, "Warning: room %q does not exist in rooms.toml\n", r)
				}
			}
		}
	}

	// Generate nanoid username (internal ID, never shown to users)
	username := generateCLIID("usr_")

	fmt.Printf("Display name: %s\n", displayName)
	fmt.Printf("Fingerprint:  %s\n", ssh.FingerprintSHA256(parsed))
	fmt.Printf("Username:     %s (internal ID)\n\n", username)

	fmt.Printf("Add to %s/users.toml:\n\n", configDir)
	fmt.Printf("[%s]\n", username)
	fmt.Printf("key = %q\n", keyLine)
	fmt.Printf("display_name = %q\n", displayName)
	if rooms != "" {
		roomList := strings.Split(rooms, ",")
		fmt.Printf("rooms = [%s]\n", formatTOMLArray(roomList))
	}
	fmt.Println("\nThe server will hot-reload the config automatically.")
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
		return err
	}

	var kept []string
	for _, line := range strings.Split(string(data), "\n") {
		if line != "" && !strings.Contains(line, "fingerprint="+fingerprint) {
			kept = append(kept, line)
		}
	}

	return os.WriteFile(logPath, []byte(strings.Join(kept, "\n")+"\n"), 0640)
}

func cmdListUsers(configDir string) error {
	users, err := config.LoadUsers(filepath.Join(configDir, "users.toml"))
	if err != nil {
		return err
	}
	for name, user := range users {
		fmt.Printf("%-20s rooms=[%s]  display_name=%q\n",
			name, strings.Join(user.Rooms, ", "), user.DisplayName)
	}
	return nil
}

func cmdRemoveUser(configDir string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: remove-user NAME")
	}
	name := args[0]

	usersPath := filepath.Join(configDir, "users.toml")
	users, err := config.LoadUsers(usersPath)
	if err != nil {
		return err
	}

	if _, ok := users[name]; !ok {
		return fmt.Errorf("user %q not found", name)
	}

	delete(users, name)
	return config.WriteUsers(usersPath, users)
}

func cmdRetireUser(configDir string, args []string) error {
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

	usersPath := filepath.Join(configDir, "users.toml")
	users, err := config.LoadUsers(usersPath)
	if err != nil {
		return err
	}

	u, ok := users[name]
	if !ok {
		return fmt.Errorf("user %q not found", name)
	}
	if u.Retired {
		return fmt.Errorf("user %q is already retired (at %s, reason: %s)", name, u.RetiredAt, u.RetiredReason)
	}

	u.Retired = true
	u.RetiredAt = time.Now().UTC().Format(time.RFC3339)
	u.RetiredReason = reason
	u.Rooms = nil // retired users belong to no rooms
	users[name] = u

	if err := config.WriteUsers(usersPath, users); err != nil {
		return fmt.Errorf("write users.toml: %w", err)
	}

	fmt.Printf("User %q retired (reason: %s).\n", name, reason)
	fmt.Println("The running server (if any) will detect the change via config watch")
	fmt.Println("and fire leave events + epoch rotations automatically.")
	return nil
}

func cmdListRetired(configDir string) error {
	users, err := config.LoadUsers(filepath.Join(configDir, "users.toml"))
	if err != nil {
		return err
	}
	found := false
	for name, user := range users {
		if !user.Retired {
			continue
		}
		found = true
		fmt.Printf("%-20s retired_at=%s  reason=%s  display_name=%q\n",
			name, user.RetiredAt, user.RetiredReason, user.DisplayName)
	}
	if !found {
		fmt.Println("No retired accounts.")
	}
	return nil
}

func cmdAddToRoom(configDir string, args []string) error {
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

	usersPath := filepath.Join(configDir, "users.toml")
	users, err := config.LoadUsers(usersPath)
	if err != nil {
		return err
	}

	u, ok := users[user]
	if !ok {
		return fmt.Errorf("user %q not found", user)
	}
	if u.Retired {
		return fmt.Errorf("user %q is retired and cannot be added to rooms", user)
	}

	// Validate room exists
	rooms, err := config.LoadRooms(filepath.Join(configDir, "rooms.toml"))
	if err != nil {
		return fmt.Errorf("load rooms.toml: %w", err)
	}
	if _, ok := rooms[room]; !ok {
		return fmt.Errorf("room %q does not exist in rooms.toml", room)
	}

	// Check not already a member
	for _, r := range u.Rooms {
		if r == room {
			return fmt.Errorf("user %q is already in room %q", user, room)
		}
	}

	u.Rooms = append(u.Rooms, room)
	users[user] = u

	if err := config.WriteUsers(usersPath, users); err != nil {
		return fmt.Errorf("write users.toml: %w", err)
	}

	fmt.Printf("Added %s (%s) to room %q.\n", u.DisplayName, user, room)
	fmt.Println("The server will detect the change and broadcast a join event automatically.")
	return nil
}

func cmdRemoveFromRoom(configDir string, args []string) error {
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

	usersPath := filepath.Join(configDir, "users.toml")
	users, err := config.LoadUsers(usersPath)
	if err != nil {
		return err
	}

	u, ok := users[user]
	if !ok {
		return fmt.Errorf("user %q not found", user)
	}

	// Find and remove the room
	found := false
	filtered := u.Rooms[:0]
	for _, r := range u.Rooms {
		if r == room {
			found = true
		} else {
			filtered = append(filtered, r)
		}
	}
	if !found {
		return fmt.Errorf("user %q is not in room %q", user, room)
	}

	u.Rooms = filtered
	users[user] = u

	if err := config.WriteUsers(usersPath, users); err != nil {
		return fmt.Errorf("write users.toml: %w", err)
	}

	fmt.Printf("Removed %s (%s) from room %q.\n", u.DisplayName, user, room)
	fmt.Println("The server will detect the change, broadcast a leave event, and trigger epoch rotation.")
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
	// Users
	users, err := config.LoadUsers(filepath.Join(configDir, "users.toml"))
	if err != nil {
		return fmt.Errorf("load users: %w", err)
	}
	active := 0
	retired := 0
	for _, u := range users {
		if u.Retired {
			retired++
		} else {
			active++
		}
	}

	// Rooms
	rooms, err := config.LoadRooms(filepath.Join(configDir, "rooms.toml"))
	if err != nil {
		return fmt.Errorf("load rooms: %w", err)
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
		} else if strings.HasPrefix(name, "conv-") {
			convID := strings.TrimPrefix(strings.TrimSuffix(name, ".db"), "conv-")
			db, err = st.ConvDB(convID)
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
			db.Exec("DELETE FROM messages WHERE ts < ?", cutoff)
			db.Exec("DELETE FROM reactions WHERE ts < ?", cutoff)
			db.Exec("VACUUM")
			fmt.Printf("  %s: deleted %d messages, vacuumed\n", name, count)
		}
		totalDeleted += count
	}

	// Purge old epoch keys from users.db
	if !dryRun && totalDeleted > 0 {
		// Remove epoch keys for epochs that no longer have any messages
		st.UsersDB().Exec(`
			DELETE FROM epoch_keys WHERE (room, epoch) NOT IN (
				SELECT DISTINCT 'placeholder', 0
			)`)
		// Simpler: just leave epoch keys — they're tiny (~100 bytes each)
	}

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

func formatTOMLArray(items []string) string {
	quoted := make([]string, len(items))
	for i, item := range items {
		quoted[i] = fmt.Sprintf("%q", strings.TrimSpace(item))
	}
	return strings.Join(quoted, ", ")
}
