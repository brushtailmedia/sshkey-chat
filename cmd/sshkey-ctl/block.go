package main

// Phase 16 — fingerprint block list commands.
//
//   block-fingerprint <fp> [--reason TEXT]  Add fingerprint to block list
//   list-blocks                             Show all blocked fingerprints
//   unblock-fingerprint <fp>                Remove fingerprint from block list
//
// Pre-approval defense against fingerprint spam. Blocked fingerprints
// are checked during the SSH handshake BEFORE writing to pending_keys,
// so they never appear in the pending queue and can't accumulate spam.
//
// Different from reject (which clears a single pending key) and from
// revoke-device (which applies to already-approved users). This is a
// preemptive blocklist for keys that haven't been approved yet.

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/audit"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

func cmdBlockFingerprint(dataDir string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: block-fingerprint <fingerprint> [--reason TEXT]\n\n" +
			"Adds an SSH key fingerprint (SHA256:...) to the block list.\n" +
			"Blocked keys are rejected at the SSH handshake layer before\n" +
			"they can enter the pending-keys queue")
	}
	fingerprint := args[0]
	reason := ""
	for i := 1; i < len(args); i++ {
		if args[i] == "--reason" && i+1 < len(args) {
			reason = args[i+1]
			i++
		}
	}

	// Normalize: ensure SHA256: prefix.
	if !strings.HasPrefix(fingerprint, "SHA256:") {
		return fmt.Errorf("fingerprint should start with SHA256: (got %q)", fingerprint)
	}

	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	// Warn if this fingerprint belongs to an already-approved user.
	// The operator probably meant to retire-user instead.
	allUsers := st.GetAllUsersIncludingRetired()
	for _, u := range allUsers {
		userFP := st.GetUserFingerprint(u.ID)
		if userFP == fingerprint {
			fmt.Fprintf(os.Stderr, "Warning: fingerprint %s belongs to approved user %s (%s).\n", fingerprint, u.DisplayName, u.ID)
			fmt.Fprintf(os.Stderr, "Did you mean: sshkey-ctl retire-user %s ?\n", u.ID)
			fmt.Fprintf(os.Stderr, "Blocking an active user's fingerprint will prevent re-authentication but does NOT run the retirement cascade.\n\n")
		}
	}

	if st.IsFingerprintBlocked(fingerprint) {
		return fmt.Errorf("fingerprint %s is already blocked", fingerprint)
	}

	blockedBy := fmt.Sprintf("os:%d", os.Getuid())
	if err := st.BlockFingerprint(fingerprint, reason, blockedBy); err != nil {
		return fmt.Errorf("block fingerprint: %w", err)
	}

	auditLog := audit.New(dataDir)
	auditLog.LogOS("block-fingerprint", "fingerprint="+fingerprint+" reason="+reason)

	fmt.Printf("Blocked fingerprint %s.\n", fingerprint)
	if reason != "" {
		fmt.Printf("Reason: %s\n", reason)
	}
	fmt.Println("This key will be rejected at the SSH handshake layer going forward.")
	return nil
}

func cmdListBlocks(dataDir string) error {
	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	blocks, err := st.GetBlockedFingerprints()
	if err != nil {
		return fmt.Errorf("list blocks: %w", err)
	}
	if len(blocks) == 0 {
		fmt.Println("No blocked fingerprints.")
		return nil
	}

	fmt.Printf("Blocked fingerprints (%d):\n", len(blocks))
	for _, b := range blocks {
		ts := time.Unix(b.BlockedAt, 0).UTC().Format(time.RFC3339)
		r := b.Reason
		if r == "" {
			r = "(no reason)"
		}
		fmt.Printf("  %s  blocked_at=%s  by=%s  reason=%s\n", b.Fingerprint, ts, b.BlockedBy, r)
	}
	return nil
}

func cmdUnblockFingerprint(dataDir string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: unblock-fingerprint <fingerprint>")
	}
	fingerprint := args[0]

	if !strings.HasPrefix(fingerprint, "SHA256:") {
		return fmt.Errorf("fingerprint should start with SHA256: (got %q)", fingerprint)
	}

	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	if !st.IsFingerprintBlocked(fingerprint) {
		return fmt.Errorf("fingerprint %s is not in the block list", fingerprint)
	}

	if err := st.UnblockFingerprint(fingerprint); err != nil {
		return fmt.Errorf("unblock: %w", err)
	}

	auditLog := audit.New(dataDir)
	auditLog.LogOS("unblock-fingerprint", "fingerprint="+fingerprint)

	fmt.Printf("Unblocked fingerprint %s.\n", fingerprint)
	return nil
}
