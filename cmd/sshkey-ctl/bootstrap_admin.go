package main

// Phase 16 Gap 4 — bootstrap-admin command.
//
// Provisions a new admin account with a server-generated keypair.
// Replaces the `users.toml` first-boot seeding path that Phase 9 left
// behind. Works on fresh DBs (the first-admin bootstrap case) AND on
// existing DBs (disaster recovery, pre-provisioning, service accounts)
// — not first-admin-specific.
//
// Why server-side keygen for admins (asymmetric with the approve flow
// which expects users to bring their own keys):
//
//   - Admin set is small (typically 1-5 people) and operationally aware
//   - Bootstrap-from-nothing is a real operational need (fresh server,
//     disaster recovery, headless deployments where there's no user
//     yet to SSH in and trigger pending)
//   - Server-generated keys are an acceptable trade-off for this narrow
//     population. Regular users always go through `approve` to preserve
//     the "user controls their own key material from generation"
//     property.
//
// Order of operations is DB-first, then file writes:
//   1. Validate display name not in use
//   2. Validate output file path not in use
//   3. Prompt for passphrase (interactive, hidden, with strength check)
//   4. Generate Ed25519 keypair in process memory
//   5. Insert user row + flip admin flag (single transaction)
//   6. Write audit log entry
//   7. Marshal encrypted private key + write files to CWD
//
// "User row without key files" is a recoverable state (operator deletes
// the row and re-runs). "Key files without user row" looks like an
// intrusion artifact in the audit log, so DB-first is the deliberate
// choice.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/term"

	"github.com/brushtailmedia/sshkey-chat/internal/audit"
	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/keygen"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// passphraseRetries is the number of times we'll re-prompt for a
// passphrase if the operator's choice fails the strength check or
// confirmation mismatch. Three attempts is enough for a typo-or-two
// recovery without becoming a brute-force surface.
const passphraseRetries = 3

func cmdBootstrapAdmin(configDir, dataDir string, args []string) error {
	var outDir string
	var positional []string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--out":
			if i+1 >= len(args) {
				return fmt.Errorf("usage: bootstrap-admin DISPLAY_NAME [--out DIR]")
			}
			outDir = args[i+1]
			i++
		case "--help", "-h":
			return fmt.Errorf("usage: bootstrap-admin DISPLAY_NAME [--out DIR]")
		default:
			if strings.HasPrefix(args[i], "--") {
				return fmt.Errorf("usage: bootstrap-admin DISPLAY_NAME [--out DIR]")
			}
			positional = append(positional, args[i])
		}
	}
	if len(positional) == 0 {
		return fmt.Errorf("usage: bootstrap-admin DISPLAY_NAME [--out DIR]\n\n" +
			"Generates a new admin keypair, writes the encrypted private\n" +
			"key to ./<name>_ed25519 (or --out DIR), and inserts\n" +
			"a user row with admin=true into users.db")
	}
	if len(positional) > 1 {
		return fmt.Errorf("usage: bootstrap-admin DISPLAY_NAME [--out DIR]")
	}
	if err := checkBootstrapPreconditions(configDir, dataDir); err != nil {
		return err
	}

	rawDisplayName := positional[0]
	displayName, err := config.ValidateDisplayName(rawDisplayName)
	if err != nil {
		return fmt.Errorf("display name %q invalid: %w", rawDisplayName, err)
	}

	// Open the store FIRST so we can fail fast on display name
	// collision, before bothering the operator with a passphrase prompt.
	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	// Display name + output file collision checks happen up-front so
	// the operator doesn't waste time on a passphrase that will be
	// rejected. The core function repeats the display-name check for
	// race safety, but we want the early failure here.
	if err := checkDisplayNameAvailable(st, displayName); err != nil {
		return err
	}

	if outDir == "" {
		outDir, err = os.Getwd()
		if err != nil {
			return fmt.Errorf("cannot determine current directory: %w", err)
		}
	}
	if err := checkOutputDirWritable(outDir); err != nil {
		return err
	}
	if err := checkOutputFilesAvailable(outDir, displayName); err != nil {
		return err
	}

	// Prompt for passphrase + confirmation. Loop on validation failure
	// up to passphraseRetries.
	passphrase, err := promptPassphrase(displayName)
	if err != nil {
		return err
	}

	// Hand off to the testable core. It does the same checks again
	// (race-safe) and performs the actual keygen + DB writes + audit
	// + file writes.
	result, err := bootstrapAdminCore(st, dataDir, displayName, passphrase, outDir)
	if err != nil {
		return err
	}

	// Success output. Include everything the operator needs to
	// transport the key and clean up the staging files.
	fmt.Printf("Generated admin key for %s.\n", displayName)
	fmt.Printf("  User ID:     %s\n", result.UserID)
	fmt.Printf("  Fingerprint: %s\n", result.Fingerprint)
	fmt.Printf("  Private key: %s (encrypted)\n", result.PrivateKeyPath)
	fmt.Printf("  Public key:  %s\n", result.PublicKeyPath)
	fmt.Println()
	fmt.Printf("Transport %s to %s's client machine, then remove it from this server:\n", result.PrivateKeyPath, displayName)
	fmt.Printf("  scp %s %s@<their-machine>:~/.ssh/\n", result.PrivateKeyPath, displayName)
	fmt.Printf("  shred -u %s\n", result.PrivateKeyPath)
	fmt.Println()
	fmt.Printf("%s can now connect with their new key.\n", displayName)
	return nil
}

// bootstrapAdminResult captures the outputs of a successful
// bootstrap-admin run: the new user ID, fingerprint, and on-disk paths
// of the encrypted key files. Returned to the caller for printing
// success output and consumed by tests for assertions.
type bootstrapAdminResult struct {
	UserID         string
	Fingerprint    string
	PrivateKeyPath string
	PublicKeyPath  string
}

// bootstrapAdminCore is the testable side of the command — it takes a
// pre-validated passphrase and an explicit output directory, and
// performs the keygen + DB writes + audit log entry + file writes
// without any interactive prompting. cmdBootstrapAdmin handles the
// terminal prompt and CWD discovery; this function handles everything
// else and is invoked directly by tests.
//
// Order of operations is DB-first, then file writes (see the package
// doc comment for rationale).
func bootstrapAdminCore(st *store.Store, dataDir, displayName, passphrase, outDir string) (*bootstrapAdminResult, error) {
	// Re-check display name + file collisions inside the core — the
	// caller checked them up-front but we want race safety for any
	// other process that might have created a colliding row or file
	// between the prompt and now.
	if err := checkOutputDirWritable(outDir); err != nil {
		return nil, err
	}
	if err := checkDisplayNameAvailable(st, displayName); err != nil {
		return nil, err
	}
	if err := checkOutputFilesAvailable(outDir, displayName); err != nil {
		return nil, err
	}

	// Generate Ed25519 keypair. This is the only entropy source — the
	// passphrase is used to encrypt the private key for storage, not
	// as seed material.
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate keypair: %w", err)
	}

	// Marshal the private key with passphrase encryption. Uses
	// MarshalPrivateKeyWithPassphrase so the unencrypted private key
	// never touches disk — only the encrypted PEM block does.
	pemBlock, err := ssh.MarshalPrivateKeyWithPassphrase(privKey, "", []byte(passphrase))
	if err != nil {
		return nil, fmt.Errorf("marshal encrypted private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(pemBlock)

	// Build the public key in the SSH authorized_keys format we store
	// in users.db. Fingerprint is computed once and reused for output
	// and audit entry.
	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	keyForStorage := pubLine + " " + displayName
	fingerprint := ssh.FingerprintSHA256(sshPub)

	// Generate the user ID via the same scheme as cmdApprove.
	userID := store.GenerateID("usr_")
	if st.GetUserByID(userID) != nil {
		userID = store.GenerateID("usr_")
		if st.GetUserByID(userID) != nil {
			return nil, fmt.Errorf("nanoid collision (extremely unlikely) — please retry")
		}
	}

	// DB writes: insert user row, then flip admin flag.
	if err := st.InsertUser(userID, keyForStorage, displayName); err != nil {
		return nil, fmt.Errorf("insert user row: %w", err)
	}
	if err := st.SetAdmin(userID, true); err != nil {
		_ = st.DeleteUser(userID)
		return nil, fmt.Errorf("set admin flag: %w (user row removed)", err)
	}

	// Phase 16 default rooms: auto-add the new admin to every
	// flagged room. Same hook as cmdApprove uses for regular users.
	// Errors are logged inside addUserToDefaultRooms but don't fail
	// the bootstrap — the user row is committed and an operator can
	// manually add the admin to any room that failed.
	addUserToDefaultRooms(st, userID)

	// Audit log entry.
	auditLog := audit.New(dataDir)
	auditLog.LogOS("bootstrap-admin",
		fmt.Sprintf("user_id=%s display_name=%q fingerprint=%s", userID, displayName, fingerprint))

	// File writes happen AFTER the DB commit.
	outBase := filepath.Join(outDir, displayName+"_ed25519")
	pubBase := outBase + ".pub"
	if err := os.WriteFile(outBase, privPEM, 0600); err != nil {
		return nil, fmt.Errorf("write private key to %s: %w\n\nThe user row was created in users.db but the key file write failed.\nRetire the orphan with: sshkey-ctl retire-user %s --reason admin_mistake\nThen retry bootstrap-admin from a writable directory", outBase, err, userID)
	}
	if err := os.WriteFile(pubBase, []byte(pubLine+"\n"), 0644); err != nil {
		return nil, fmt.Errorf("write public key to %s: %w (private key was written to %s, you can keep it)", pubBase, err, outBase)
	}

	return &bootstrapAdminResult{
		UserID:         userID,
		Fingerprint:    fingerprint,
		PrivateKeyPath: outBase,
		PublicKeyPath:  pubBase,
	}, nil
}

// checkDisplayNameAvailable returns an error if the requested display
// name (or its case-insensitive equivalent) is already taken by any
// user in users.db, including retired users. Mirrors the collision
// check in cmdApprove so the error messages stay consistent.
func checkDisplayNameAvailable(st *store.Store, displayName string) error {
	allUsers := st.GetAllUsersIncludingRetired()
	for _, u := range allUsers {
		if strings.EqualFold(u.DisplayName, displayName) {
			return fmt.Errorf("user %q already exists (id %s) — pick a different display name", displayName, u.ID)
		}
		if strings.EqualFold(u.ID, displayName) {
			return fmt.Errorf("display name %q conflicts with an existing user ID", displayName)
		}
	}
	return nil
}

// checkOutputFilesAvailable returns an error if either the private or
// public key file already exists in the target directory. Refuses to
// overwrite — the operator must explicitly remove the previous file
// or run from a different directory. No --force flag.
func checkOutputFilesAvailable(outDir, displayName string) error {
	priv := filepath.Join(outDir, displayName+"_ed25519")
	pub := priv + ".pub"
	if _, err := os.Stat(priv); err == nil {
		return fmt.Errorf("file %s already exists — remove it or run from a different directory", priv)
	}
	if _, err := os.Stat(pub); err == nil {
		return fmt.Errorf("file %s already exists — remove it or run from a different directory", pub)
	}
	return nil
}

func checkOutputDirWritable(outDir string) error {
	info, err := os.Stat(outDir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("output directory %s does not exist (for Docker mounts: run `mkdir -p ./docker/keys && sudo chown 2222:2222 ./docker/keys && sudo chmod 700 ./docker/keys`)", outDir)
		}
		return fmt.Errorf("stat output directory %s: %w", outDir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("output path %s is not a directory", outDir)
	}

	probe := filepath.Join(outDir, ".bootstrap-admin-write-probe")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("cannot write to output directory %s: %w (for Docker mounts: run `mkdir -p ./docker/keys && sudo chown 2222:2222 ./docker/keys && sudo chmod 700 ./docker/keys`)", outDir, err)
	}
	_ = f.Close()
	_ = os.Remove(probe)
	return nil
}

func checkBootstrapPreconditions(configDir, dataDir string) error {
	serverPath := filepath.Join(configDir, "server.toml")
	if st, err := os.Stat(serverPath); err != nil || st.IsDir() {
		return fmt.Errorf("bootstrap-admin prerequisites missing: %s not found. Run `sshkey-ctl init --config %s --data %s` first", serverPath, configDir, dataDir)
	}

	dataSubdir := filepath.Join(dataDir, "data")
	info, err := os.Stat(dataSubdir)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("bootstrap-admin prerequisites missing: %s not initialized. Run `sshkey-ctl init --config %s --data %s` first", dataSubdir, configDir, dataDir)
	}

	for _, name := range []string{"data.db", "users.db", "rooms.db"} {
		p := filepath.Join(dataSubdir, name)
		if st, err := os.Stat(p); err != nil || st.IsDir() {
			return fmt.Errorf("bootstrap-admin prerequisites missing: %s not initialized. Run `sshkey-ctl init --config %s --data %s` first", p, configDir, dataDir)
		}
	}
	return nil
}

// promptPassphrase reads a passphrase from the terminal twice (entry
// + confirmation), validates strength via the keygen package, and
// retries up to passphraseRetries times on any failure. The display
// name is passed as zxcvbn context so a passphrase that contains the
// admin's own name gets penalized.
func promptPassphrase(displayName string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", fmt.Errorf("bootstrap-admin requires an interactive terminal for the passphrase prompt — stdin is not a tty")
	}

	for attempt := 1; attempt <= passphraseRetries; attempt++ {
		fmt.Print("Enter passphrase (will not echo): ")
		first, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", fmt.Errorf("read passphrase: %w", err)
		}

		fmt.Print("Confirm passphrase: ")
		second, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", fmt.Errorf("read confirmation: %w", err)
		}

		if string(first) != string(second) {
			fmt.Fprintln(os.Stderr, "Passphrases do not match — try again.")
			if attempt == passphraseRetries {
				return "", fmt.Errorf("passphrase confirmation failed after %d attempts", passphraseRetries)
			}
			continue
		}

		// Show a strength bar for every attempt regardless of accept/
		// reject so the operator sees how close they were on a block
		// and how strong on an accept. No colors — bootstrap-admin
		// runs in arbitrary terminals. See keygen.StrengthBar for the
		// segment mapping.
		bar, label := keygen.StrengthBar(string(first), []string{displayName})
		fmt.Fprintf(os.Stderr, "Strength: %s  %s\n", bar, label)

		// Validate strength with display-name context so zxcvbn
		// penalizes "passphrase is my own name with digits" patterns.
		if err := keygen.ValidateAdminPassphraseWithContext(string(first), []string{displayName}); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			if attempt == passphraseRetries {
				return "", fmt.Errorf("passphrase too weak after %d attempts — exiting", passphraseRetries)
			}
			continue
		}

		return string(first), nil
	}

	// Unreachable in practice — the loop always returns or continues.
	return "", fmt.Errorf("passphrase prompt exhausted retries")
}
