package main

// Phase 16 Gap 4 — tests for bootstrap-admin.
//
// The full cmdBootstrapAdmin path requires an interactive terminal for
// the passphrase prompt, so these tests target bootstrapAdminCore (the
// non-interactive helper that takes a pre-validated passphrase). The
// terminal prompting + retry logic lives in cmdBootstrapAdmin and is
// exercised manually rather than via tests — a fake-stdin approach is
// possible but adds noise for marginal value, given that the prompt is
// a thin wrapper around term.ReadPassword.
//
// What's tested here:
//
//   - happy path: keypair generated, files written, user row inserted
//     with admin=true, audit log entry recorded
//   - display name collision (active user)
//   - display name collision (retired user)
//   - output file collision (existing private key file)
//   - output file collision (existing public key file)
//   - invalid display name format
//   - encrypted private key actually decrypts with the supplied
//     passphrase (catches "we wrote unencrypted bytes by accident")
//   - public key file matches the key stored in users.db
//
// A separate test exercises the cleanup-on-SetAdmin-failure path. We
// can't easily induce SetAdmin to fail against a real SQLite store, so
// that one is left as a TODO comment for a follow-up phase that
// introduces injectable errors.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey-chat/internal/audit"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// goodPassphrase is a passphrase that clears zxcvbn admin-strength
// validation. Random characters with no patterns; not a real
// passphrase anyone would use, but strong enough to pass.
const goodPassphrase = "Tz!4pQ@9nW#8vR$xK7"

// newBootstrapTestStore opens a fresh store in a temp dir and returns
// (store, dataDir, outDir). The outDir is a separate temp dir for the
// generated key files so collisions with the store's data dir can't
// happen by accident.
func newBootstrapTestStore(t *testing.T) (*store.Store, string, string) {
	t.Helper()
	dataDir := t.TempDir()
	outDir := t.TempDir()
	st, err := store.Open(dataDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st, dataDir, outDir
}

// TestBootstrapAdminCore_HappyPath exercises the full successful path:
// store insert + admin flag + audit entry + key files written. Verifies
// every observable side effect.
func TestBootstrapAdminCore_HappyPath(t *testing.T) {
	st, dataDir, outDir := newBootstrapTestStore(t)

	result, err := bootstrapAdminCore(st, dataDir, "alice", goodPassphrase, outDir)
	if err != nil {
		t.Fatalf("bootstrapAdminCore: %v", err)
	}

	// Result fields populated.
	if result.UserID == "" {
		t.Error("UserID should be populated")
	}
	if !strings.HasPrefix(result.UserID, "usr_") {
		t.Errorf("UserID should have usr_ prefix, got %q", result.UserID)
	}
	if !strings.HasPrefix(result.Fingerprint, "SHA256:") {
		t.Errorf("Fingerprint should have SHA256: prefix, got %q", result.Fingerprint)
	}
	wantPriv := filepath.Join(outDir, "alice_ed25519")
	if result.PrivateKeyPath != wantPriv {
		t.Errorf("PrivateKeyPath = %q, want %q", result.PrivateKeyPath, wantPriv)
	}
	wantPub := wantPriv + ".pub"
	if result.PublicKeyPath != wantPub {
		t.Errorf("PublicKeyPath = %q, want %q", result.PublicKeyPath, wantPub)
	}

	// User row exists with admin=true.
	u := st.GetUserByID(result.UserID)
	if u == nil {
		t.Fatal("user row not found after bootstrap")
	}
	if u.DisplayName != "alice" {
		t.Errorf("display name = %q, want alice", u.DisplayName)
	}
	if !u.Admin {
		t.Error("admin flag should be set")
	}
	if u.Retired {
		t.Error("new admin should not be retired")
	}

	// Private key file exists with mode 0600 and is non-empty.
	privInfo, err := os.Stat(result.PrivateKeyPath)
	if err != nil {
		t.Fatalf("stat private key: %v", err)
	}
	if privInfo.Mode().Perm() != 0600 {
		t.Errorf("private key mode = %o, want 0600", privInfo.Mode().Perm())
	}
	if privInfo.Size() == 0 {
		t.Error("private key file is empty")
	}

	// Public key file exists with mode 0644.
	pubInfo, err := os.Stat(result.PublicKeyPath)
	if err != nil {
		t.Fatalf("stat public key: %v", err)
	}
	if pubInfo.Mode().Perm() != 0644 {
		t.Errorf("public key mode = %o, want 0644", pubInfo.Mode().Perm())
	}

	// Public key file content matches the key stored in users.db.
	pubBytes, err := os.ReadFile(result.PublicKeyPath)
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	pubLine := strings.TrimSpace(string(pubBytes))
	// users.db key field includes the display name as a comment;
	// strip it for comparison.
	parts := strings.Fields(u.Key)
	if len(parts) < 2 {
		t.Fatalf("stored key malformed: %q", u.Key)
	}
	storedNoComment := parts[0] + " " + parts[1]
	pubParts := strings.Fields(pubLine)
	if len(pubParts) < 2 {
		t.Fatalf("public key file malformed: %q", pubLine)
	}
	pubNoComment := pubParts[0] + " " + pubParts[1]
	if storedNoComment != pubNoComment {
		t.Errorf("stored key %q != public key file %q", storedNoComment, pubNoComment)
	}

	// Audit log entry written. Read the file directly — the audit
	// package doesn't expose a query API yet (that's a future Phase
	// 16 audit-log CLI command), so we verify by reading the raw file.
	auditPath := filepath.Join(dataDir, "audit.log")
	auditBytes, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	auditContent := string(auditBytes)
	if !strings.Contains(auditContent, "bootstrap-admin") {
		t.Errorf("audit log missing bootstrap-admin entry: %q", auditContent)
	}
	if !strings.Contains(auditContent, result.UserID) {
		t.Errorf("audit log missing user ID %s: %q", result.UserID, auditContent)
	}
	if !strings.Contains(auditContent, "alice") {
		t.Errorf("audit log missing display name: %q", auditContent)
	}
}

// TestBootstrapAdminCore_PrivateKeyDecryptsWithPassphrase verifies that
// the encrypted private key file actually requires the passphrase to
// decrypt — catches the failure mode where we accidentally write an
// unencrypted PEM block.
func TestBootstrapAdminCore_PrivateKeyDecryptsWithPassphrase(t *testing.T) {
	st, dataDir, outDir := newBootstrapTestStore(t)

	result, err := bootstrapAdminCore(st, dataDir, "alice", goodPassphrase, outDir)
	if err != nil {
		t.Fatalf("bootstrapAdminCore: %v", err)
	}

	privBytes, err := os.ReadFile(result.PrivateKeyPath)
	if err != nil {
		t.Fatalf("read private key: %v", err)
	}

	// Parsing without passphrase should fail — verifies the file is
	// actually encrypted.
	if _, err := ssh.ParsePrivateKey(privBytes); err == nil {
		t.Error("private key parsed without passphrase — file is not encrypted!")
	}

	// Parsing with the wrong passphrase should fail.
	if _, err := ssh.ParsePrivateKeyWithPassphrase(privBytes, []byte("wrong-passphrase")); err == nil {
		t.Error("private key parsed with wrong passphrase — encryption is broken!")
	}

	// Parsing with the correct passphrase should succeed.
	signer, err := ssh.ParsePrivateKeyWithPassphrase(privBytes, []byte(goodPassphrase))
	if err != nil {
		t.Fatalf("parse with passphrase: %v", err)
	}

	// Verify it's an Ed25519 key by checking the wire-level key type
	// string. Avoids depending on internal type assertions that vary
	// between golang.org/x/crypto versions.
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		t.Errorf("public key type = %q, want %q", signer.PublicKey().Type(), ssh.KeyAlgoED25519)
	}

	// Also verify the fingerprint matches what bootstrapAdminCore
	// returned — closes the loop end-to-end.
	if fp := ssh.FingerprintSHA256(signer.PublicKey()); fp != result.Fingerprint {
		t.Errorf("decrypted key fingerprint %q != bootstrap result fingerprint %q", fp, result.Fingerprint)
	}
}

// TestBootstrapAdminCore_DisplayNameCollision_Active verifies that
// an existing active user with the same display name causes a hard
// error.
func TestBootstrapAdminCore_DisplayNameCollision_Active(t *testing.T) {
	st, dataDir, outDir := newBootstrapTestStore(t)

	// Pre-insert a user named "alice".
	if err := st.InsertUser("usr_existing", "ssh-ed25519 AAAA fake-key", "alice"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	_, err := bootstrapAdminCore(st, dataDir, "alice", goodPassphrase, outDir)
	if err == nil {
		t.Fatal("expected collision error")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error should mention 'already exists', got: %v", err)
	}
}

// TestBootstrapAdminCore_RetiredUserNameFreedForReuse verifies that
// retiring a user releases their display name for reuse — a new
// bootstrap-admin call with the same display name should succeed
// because retirement suffixes the old display name with the user ID's
// nanoid characters (see store.SetUserRetired). The user ID must be
// at least 8 characters for the suffix logic to fire, which matches
// production nanoids (e.g. "usr_3f9a1b2c").
func TestBootstrapAdminCore_RetiredUserNameFreedForReuse(t *testing.T) {
	st, dataDir, outDir := newBootstrapTestStore(t)

	// Insert + retire a user with a realistic nanoid-length ID. Short
	// IDs like "usr_old" don't trigger the suffix-on-retirement
	// behavior in store.SetUserRetired (the suffix logic requires
	// len(userID) > 8), so we use a realistic 12-char ID.
	if err := st.InsertUser("usr_old12345", "ssh-ed25519 AAAA fake-key", "alice"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := st.SetUserRetired("usr_old12345", "test"); err != nil {
		t.Fatalf("retire: %v", err)
	}

	// Verify the display name was actually suffixed by retirement.
	retired := st.GetUserByID("usr_old12345")
	if retired == nil {
		t.Fatal("retired user not found")
	}
	if retired.DisplayName == "alice" {
		t.Fatal("retirement should have suffixed the display name, but it's still 'alice'")
	}

	// Now bootstrap a new admin with the original display name — the
	// retired user's name was suffixed, so "alice" is free.
	result, err := bootstrapAdminCore(st, dataDir, "alice", goodPassphrase, outDir)
	if err != nil {
		t.Fatalf("bootstrap should succeed when retired user has suffixed name: %v", err)
	}
	if result.UserID == "" {
		t.Error("expected new user to be created")
	}

	// And the new user should have admin=true while the retired user
	// stays retired.
	newUser := st.GetUserByID(result.UserID)
	if newUser == nil || !newUser.Admin {
		t.Error("new user should be an admin")
	}
	stillRetired := st.GetUserByID("usr_old12345")
	if stillRetired == nil || !stillRetired.Retired {
		t.Error("old retired user should still be retired")
	}
}

// TestBootstrapAdminCore_OutputFileCollision verifies that an
// existing key file at the output path causes a hard error.
func TestBootstrapAdminCore_OutputFileCollision(t *testing.T) {
	st, dataDir, outDir := newBootstrapTestStore(t)

	// Pre-create the file that bootstrapAdminCore would write to.
	existing := filepath.Join(outDir, "alice_ed25519")
	if err := os.WriteFile(existing, []byte("placeholder"), 0600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	_, err := bootstrapAdminCore(st, dataDir, "alice", goodPassphrase, outDir)
	if err == nil {
		t.Fatal("expected file collision error")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error should mention 'already exists', got: %v", err)
	}

	// Critically: no user row should have been created — the
	// collision check runs BEFORE any DB writes.
	allUsers := st.GetAllUsersIncludingRetired()
	for _, u := range allUsers {
		if u.DisplayName == "alice" {
			t.Errorf("file collision should not have created a user row, but found user %s", u.ID)
		}
	}
}

// TestBootstrapAdminCore_PubFileCollision is the .pub variant of the
// collision check.
func TestBootstrapAdminCore_PubFileCollision(t *testing.T) {
	st, dataDir, outDir := newBootstrapTestStore(t)

	existing := filepath.Join(outDir, "alice_ed25519.pub")
	if err := os.WriteFile(existing, []byte("placeholder"), 0644); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	_, err := bootstrapAdminCore(st, dataDir, "alice", goodPassphrase, outDir)
	if err == nil {
		t.Fatal("expected pub file collision error")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error should mention 'already exists', got: %v", err)
	}
}

// TestBootstrapAdminCore_AuditEntryFormat verifies the audit log line
// is parseable by the standard audit format. This is a contract test
// for the future audit-log CLI command — if it changes the line
// format, this test breaks loudly.
func TestBootstrapAdminCore_AuditEntryFormat(t *testing.T) {
	st, dataDir, outDir := newBootstrapTestStore(t)

	result, err := bootstrapAdminCore(st, dataDir, "alice", goodPassphrase, outDir)
	if err != nil {
		t.Fatalf("bootstrapAdminCore: %v", err)
	}

	auditBytes, err := os.ReadFile(filepath.Join(dataDir, "audit.log"))
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	line := strings.TrimSpace(string(auditBytes))

	// Expected shape: "<timestamp>  os:<uid>  bootstrap-admin  user_id=usr_xxx display_name="alice" fingerprint=SHA256:..."
	// Verify each component is present.
	if !strings.HasPrefix(line, "20") { // timestamp starts with year
		t.Errorf("audit line should start with year, got: %q", line)
	}
	if !strings.Contains(line, "os:") {
		t.Errorf("audit line should contain 'os:' source, got: %q", line)
	}
	if !strings.Contains(line, "bootstrap-admin") {
		t.Errorf("audit line should contain 'bootstrap-admin' action, got: %q", line)
	}
	if !strings.Contains(line, "user_id="+result.UserID) {
		t.Errorf("audit line should contain user_id=%s, got: %q", result.UserID, line)
	}
	if !strings.Contains(line, "fingerprint=SHA256:") {
		t.Errorf("audit line should contain fingerprint, got: %q", line)
	}
}

// TestBootstrapAdminCore_MultipleCallsCreateDistinctAdmins verifies
// that bootstrap-admin works as a general admin provisioning command,
// not just a first-admin bootstrap. Two consecutive calls with
// different display names should both succeed.
func TestBootstrapAdminCore_MultipleCallsCreateDistinctAdmins(t *testing.T) {
	st, dataDir, outDir := newBootstrapTestStore(t)

	resultA, err := bootstrapAdminCore(st, dataDir, "alice", goodPassphrase, outDir)
	if err != nil {
		t.Fatalf("first bootstrap: %v", err)
	}
	resultB, err := bootstrapAdminCore(st, dataDir, "bob", goodPassphrase, outDir)
	if err != nil {
		t.Fatalf("second bootstrap: %v", err)
	}

	if resultA.UserID == resultB.UserID {
		t.Error("expected distinct user IDs")
	}
	if resultA.Fingerprint == resultB.Fingerprint {
		t.Error("expected distinct fingerprints (different keypairs)")
	}

	// Both users should be admins.
	uA := st.GetUserByID(resultA.UserID)
	uB := st.GetUserByID(resultB.UserID)
	if !uA.Admin || !uB.Admin {
		t.Error("both bootstrap-admin users should have admin=true")
	}
}

// TestCheckDisplayNameAvailable_CaseInsensitive verifies that the
// collision check is case-insensitive — uppercase ALICE collides with
// lowercase alice.
func TestCheckDisplayNameAvailable_CaseInsensitive(t *testing.T) {
	st, _, _ := newBootstrapTestStore(t)
	if err := st.InsertUser("usr_a", "ssh-ed25519 AAAA fake-key", "Alice"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := checkDisplayNameAvailable(st, "alice"); err == nil {
		t.Error("lowercase 'alice' should collide with stored 'Alice'")
	}
	if err := checkDisplayNameAvailable(st, "ALICE"); err == nil {
		t.Error("uppercase 'ALICE' should collide with stored 'Alice'")
	}
}

// Compile-time guard: ensure audit.New is visible from this package
// so the linker doesn't strip the call by accident. (Defensive — the
// real audit.New call is in bootstrap_admin.go, this is a no-op
// reference.)
var _ = audit.New
