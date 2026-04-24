package main

// Phase 16 — tests for block-fingerprint / list-blocks / unblock-fingerprint.

import (
	"os"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

func TestBlockFingerprint_HappyPath(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	fp := "SHA256:testfingerprint123"

	if err := cmdBlockFingerprint(dataDir, []string{fp, "--reason", "spam"}); err != nil {
		t.Fatalf("block: %v", err)
	}

	st, _ := store.Open(dataDir)
	defer st.Close()
	if !st.IsFingerprintBlocked(fp) {
		t.Error("fingerprint should be blocked")
	}
}

func TestBlockFingerprint_RequiresSHA256Prefix(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	err := cmdBlockFingerprint(dataDir, []string{"bare-fingerprint"})
	if err == nil {
		t.Fatal("should reject fingerprint without SHA256: prefix")
	}
	if !strings.Contains(err.Error(), "SHA256:") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestBlockFingerprint_AlreadyBlockedRejected(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	fp := "SHA256:testfingerprint123"

	cmdBlockFingerprint(dataDir, []string{fp})
	err := cmdBlockFingerprint(dataDir, []string{fp})
	if err == nil {
		t.Fatal("should reject double block")
	}
	if !strings.Contains(err.Error(), "already blocked") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestBlockFingerprint_MissingArgs(t *testing.T) {
	err := cmdBlockFingerprint(t.TempDir(), nil)
	if err == nil {
		t.Fatal("should error without args")
	}
}

func TestListBlocks_Empty(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	out := captureStdout(t, func() {
		cmdListBlocks(dataDir)
	})
	if !strings.Contains(out, "No blocked") {
		t.Errorf("should say no blocks, got: %q", out)
	}
}

func TestListBlocks_AfterBlock(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	fp := "SHA256:testfingerprint123"
	cmdBlockFingerprint(dataDir, []string{fp, "--reason", "spam"})

	out := captureStdout(t, func() {
		cmdListBlocks(dataDir)
	})
	if !strings.Contains(out, fp) {
		t.Errorf("should list the fingerprint, got: %q", out)
	}
	if !strings.Contains(out, "spam") {
		t.Errorf("should show reason, got: %q", out)
	}
}

func TestUnblockFingerprint_HappyPath(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	fp := "SHA256:testfingerprint123"
	cmdBlockFingerprint(dataDir, []string{fp})

	if err := cmdUnblockFingerprint(dataDir, []string{fp}); err != nil {
		t.Fatalf("unblock: %v", err)
	}

	st, _ := store.Open(dataDir)
	defer st.Close()
	if st.IsFingerprintBlocked(fp) {
		t.Error("fingerprint should be unblocked")
	}
}

func TestUnblockFingerprint_NotBlocked(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	err := cmdUnblockFingerprint(dataDir, []string{"SHA256:not-blocked"})
	if err == nil {
		t.Fatal("should error for unblocking a non-blocked fingerprint")
	}
	if !strings.Contains(err.Error(), "not in the block list") {
		t.Errorf("wrong error: %v", err)
	}
}

func TestUnblockFingerprint_MissingArgs(t *testing.T) {
	err := cmdUnblockFingerprint(t.TempDir(), nil)
	if err == nil {
		t.Fatal("should error without args")
	}
}

func TestUnblockFingerprint_RequiresSHA256Prefix(t *testing.T) {
	err := cmdUnblockFingerprint(t.TempDir(), []string{"bare"})
	if err == nil {
		t.Fatal("should reject fingerprint without SHA256: prefix")
	}
}

// TestBlockFingerprint_AuditEntryWritten verifies an audit log entry
// is created for both block and unblock operations.
func TestBlockFingerprint_AuditEntryWritten(t *testing.T) {
	dataDir := setupDataDir(t, nil)
	fp := "SHA256:auditfp123"

	cmdBlockFingerprint(dataDir, []string{fp, "--reason", "test"})
	cmdUnblockFingerprint(dataDir, []string{fp})

	auditPath := dataDir + "/audit.log"
	data, err := readFileIfExists(auditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "block-fingerprint") {
		t.Errorf("audit should have block entry, got: %q", content)
	}
	if !strings.Contains(content, "unblock-fingerprint") {
		t.Errorf("audit should have unblock entry, got: %q", content)
	}
}

func readFileIfExists(path string) ([]byte, error) {
	return os.ReadFile(path)
}
