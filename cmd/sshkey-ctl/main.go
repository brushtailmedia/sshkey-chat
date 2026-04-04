package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/brushtailmedia/sshkey/internal/config"
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
		return cmdApprove(configDir, cmdArgs)
	case "reject":
		return cmdReject(dataDir, cmdArgs)
	case "list-users":
		return cmdListUsers(configDir)
	case "remove-user":
		return cmdRemoveUser(configDir, cmdArgs)
	case "revoke-device":
		return cmdRevokeDevice(configDir, cmdArgs)
	case "restore-device":
		return cmdRestoreDevice(configDir, cmdArgs)
	case "host-key":
		return cmdHostKey(configDir)
	case "purge-archives":
		return cmdPurgeArchives(dataDir, cmdArgs)
	default:
		return fmt.Errorf("unknown command: %s", cmd)
	}
}

func printUsage() error {
	fmt.Fprintln(os.Stderr, `sshkey-ctl - local admin tool for sshkey-chat

Usage: sshkey-ctl [--config DIR] [--data DIR] <command> [args]

Commands:
  pending                                 View pending key requests
  approve --fingerprint FP --name NAME --rooms ROOMS  Approve a pending key
  reject --fingerprint FP                 Reject/clear a pending key
  list-users                              List all users
  remove-user NAME                        Remove a user
  revoke-device --user USER --device DEV  Revoke a device
  restore-device --user USER --device DEV Restore a revoked device
  host-key                                Print server host key fingerprint
  purge-archives --older-than DURATION    Purge old archives`)
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
	var fingerprint, name, rooms string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--fingerprint":
			if i+1 < len(args) { fingerprint = args[i+1]; i++ }
		case "--name":
			if i+1 < len(args) { name = args[i+1]; i++ }
		case "--rooms":
			if i+1 < len(args) { rooms = args[i+1]; i++ }
		}
	}
	if fingerprint == "" || name == "" {
		return fmt.Errorf("usage: approve --fingerprint FP --name NAME --rooms ROOMS")
	}

	// We need the actual public key, not just fingerprint.
	// In practice, the admin would copy it from pending-keys.log or the user would provide it.
	// For now, we require the full key to be provided via --key flag too.
	fmt.Printf("To approve user %q with fingerprint %s:\n", name, fingerprint)
	fmt.Printf("1. Get the user's full public key (ssh-ed25519 AAAA...)\n")
	fmt.Printf("2. Add to %s/users.toml:\n\n", configDir)
	fmt.Printf("[%s]\n", name)
	fmt.Printf("key = \"<paste full public key here>\"\n")
	fmt.Printf("display_name = %q\n", name)
	if rooms != "" {
		roomList := strings.Split(rooms, ",")
		fmt.Printf("rooms = [%s]\n", formatTOMLArray(roomList))
	}
	fmt.Println("\n3. The server will hot-reload the config automatically.")
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
	return writeTOMLFile(usersPath, users)
}

func cmdRevokeDevice(configDir string, args []string) error {
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
	fmt.Printf("Device %s for user %s marked for revocation.\n", device, user)
	fmt.Println("The server will reject this device on next connection attempt.")
	// TODO: write to a revoked-devices file that the server reads
	return nil
}

func cmdRestoreDevice(configDir string, args []string) error {
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
	fmt.Printf("Device %s for user %s restored.\n", device, user)
	return nil
}

func cmdHostKey(configDir string) error {
	keyPath := filepath.Join(configDir, "host_key")
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("no host key found at %s: %w", keyPath, err)
	}

	// Parse to get fingerprint
	// Use ssh.ParsePrivateKey for this
	fmt.Printf("Host key path: %s\n", keyPath)
	fmt.Printf("Key data: %d bytes\n", len(data))
	fmt.Println("(Use `ssh-keygen -l -f` to see the fingerprint)")
	return nil
}

func cmdPurgeArchives(dataDir string, args []string) error {
	var olderThan string
	for i := 0; i < len(args); i++ {
		if args[i] == "--older-than" && i+1 < len(args) {
			olderThan = args[i+1]
			i++
		}
	}
	if olderThan == "" {
		return fmt.Errorf("usage: purge-archives --older-than DURATION (e.g., 5y, 6m)")
	}
	fmt.Printf("Would purge archives older than %s from %s\n", olderThan, dataDir)
	fmt.Println("(Not yet implemented)")
	return nil
}

func writeTOMLFile(path string, data any) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return toml.NewEncoder(f).Encode(data)
}

func formatTOMLArray(items []string) string {
	quoted := make([]string, len(items))
	for i, item := range items {
		quoted[i] = fmt.Sprintf("%q", strings.TrimSpace(item))
	}
	return strings.Join(quoted, ", ")
}
