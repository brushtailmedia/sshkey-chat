package main

// Phase 16 — audit-log and audit-user CLI commands.
//
// Phase 16 added many state-changing commands that write audit
// entries via internal/audit (bootstrap-admin, retire-user,
// unretire-user, promote, demote, rename-user, update-topic,
// rename-room, revoke-device, etc.). These two commands are the
// reader side: a way for operators to actually look at the audit
// trail without `tail -f /var/sshkey-chat/audit.log` directly.
//
//   audit-log [--since <duration>] [--limit <n>]
//   audit-user <user>
//
// Both produce the same column-aligned output as the on-disk file
// format. We don't reformat — the writer's column widths are
// already terminal-friendly. Newest entries first.

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/audit"
)

// defaultAuditLogLimit is the number of entries shown when the
// operator doesn't pass --limit. 50 is enough to see "what happened
// in the last few minutes" without flooding a terminal.
const defaultAuditLogLimit = 50

// cmdAuditLog reads the audit log and prints recent entries. Backs
// the `audit-log` CLI command.
//
// Flags:
//   --since DURATION   show only entries at or after now-DURATION
//                      (e.g. "24h", "7d", "30m"). Default: no
//                      time filter.
//   --limit N          cap output to the most recent N entries.
//                      Default: 50. Pass 0 for unlimited.
//
// Output format matches the on-disk audit.log line format exactly,
// so operators see the same thing whether they run audit-log or
// `tail audit.log` directly.
func cmdAuditLog(dataDir string, args []string) error {
	limit := defaultAuditLogLimit
	var sinceDur time.Duration
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--since":
			if i+1 >= len(args) {
				return fmt.Errorf("--since requires a duration argument (e.g. 24h, 7d)")
			}
			d, err := audit.ParseDuration(args[i+1])
			if err != nil {
				return fmt.Errorf("invalid --since: %w", err)
			}
			sinceDur = d
			i++
		case "--limit":
			if i+1 >= len(args) {
				return fmt.Errorf("--limit requires an integer argument")
			}
			var n int
			if _, err := fmt.Sscanf(args[i+1], "%d", &n); err != nil {
				return fmt.Errorf("invalid --limit: %w", err)
			}
			if n < 0 {
				return fmt.Errorf("--limit must be non-negative")
			}
			limit = n
			i++
		default:
			return fmt.Errorf("unknown flag %q (usage: audit-log [--since DURATION] [--limit N])", args[i])
		}
	}

	opts := audit.ReadOptions{Limit: limit}
	if sinceDur > 0 {
		opts.Since = time.Now().Add(-sinceDur)
	}

	path := filepath.Join(dataDir, "audit.log")
	entries, err := audit.Read(path, opts)
	if err != nil {
		return fmt.Errorf("read audit log: %w", err)
	}

	if len(entries) == 0 {
		fmt.Println("(no audit entries)")
		return nil
	}

	for _, e := range entries {
		fmt.Println(e.Raw)
	}
	return nil
}

// cmdAuditUser reads the audit log and prints entries that mention
// the given user — either as the actor (Source field) or as the
// target (anywhere in the Details field). Backs the `audit-user`
// CLI command.
//
// Use case: investigating "who approved this account and when," or
// "every action taken on usr_alice in the last week."
//
// The same --since and --limit flags as audit-log are accepted in
// any order before or after the user argument. Match is
// case-sensitive substring on user IDs (which are case-sensitive
// nanoids in ssh-chat, so this is the right semantics).
func cmdAuditUser(dataDir string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: audit-user USER_ID [--since DURATION] [--limit N]")
	}

	user := args[0]
	limit := defaultAuditLogLimit
	var sinceDur time.Duration
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--since":
			if i+1 >= len(args) {
				return fmt.Errorf("--since requires a duration argument")
			}
			d, err := audit.ParseDuration(args[i+1])
			if err != nil {
				return fmt.Errorf("invalid --since: %w", err)
			}
			sinceDur = d
			i++
		case "--limit":
			if i+1 >= len(args) {
				return fmt.Errorf("--limit requires an integer argument")
			}
			var n int
			if _, err := fmt.Sscanf(args[i+1], "%d", &n); err != nil {
				return fmt.Errorf("invalid --limit: %w", err)
			}
			if n < 0 {
				return fmt.Errorf("--limit must be non-negative")
			}
			limit = n
			i++
		default:
			return fmt.Errorf("unknown flag %q (usage: audit-user USER [--since DURATION] [--limit N])", args[i])
		}
	}

	opts := audit.ReadOptions{
		User:  user,
		Limit: limit,
	}
	if sinceDur > 0 {
		opts.Since = time.Now().Add(-sinceDur)
	}

	path := filepath.Join(dataDir, "audit.log")
	entries, err := audit.Read(path, opts)
	if err != nil {
		return fmt.Errorf("read audit log: %w", err)
	}

	if len(entries) == 0 {
		fmt.Printf("(no audit entries for user %q)\n", user)
		return nil
	}

	for _, e := range entries {
		fmt.Println(e.Raw)
	}
	return nil
}
