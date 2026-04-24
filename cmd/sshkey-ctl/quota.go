package main

// Per-user upload quota CLI commands. Out-of-phase work 2026-04-19,
// originally designed as Phase 25.
//
// Usage:
//   sshkey-ctl user quota-exempt <user_id> --on
//   sshkey-ctl user quota-exempt <user_id> --off
//   sshkey-ctl quota-report [--days 7] [--top 10]

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// cmdUser dispatches `sshkey-ctl user <subcommand> ...`. Currently
// only `quota-exempt` is implemented; the namespace is reserved for
// future user-management subcommands that don't merit top-level slots.
func cmdUser(configDir, dataDir string, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("usage: sshkey-ctl user <subcommand> [args]\n\nSubcommands:\n  quota-exempt <user_id> --on|--off    toggle daily upload quota exempt flag")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "quota-exempt":
		return cmdUserQuotaExempt(configDir, dataDir, rest)
	default:
		return fmt.Errorf("unknown user subcommand: %s\nsee `sshkey-ctl user` for the list", sub)
	}
}

// cmdUserQuotaExempt toggles users.quota_exempt for a given user_id.
// Quota-exempt users skip both upload_start and upload_complete quota
// checks AND don't accumulate in daily_upload_quotas — i.e. invisible
// to the daily-cap machinery entirely. Use sparingly.
//
// Gated by `[server.quotas.user] allow_exempt_users` in server.toml
// (default false). When the gate is off:
//   - --on is rejected with a pointer to the config knob.
//   - --off is allowed unconditionally so operators can clean up
//     existing exempt flags after flipping the gate.
//
// The runtime check (server-side `isQuotaExempt`) consults the same
// gate, so even an exempt flag set when the gate was on is ignored
// once the gate flips off — flag and gate are both required.
func cmdUserQuotaExempt(configDir, dataDir string, args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: sshkey-ctl user quota-exempt <user_id> --on|--off")
	}
	userID := args[0]
	var on bool
	switch args[1] {
	case "--on":
		on = true
	case "--off":
		on = false
	default:
		return fmt.Errorf("flag must be --on or --off, got %q", args[1])
	}

	// Consult the gate before opening the store. Loading server.toml
	// here means a misconfigured config aborts the CLI cleanly with
	// a recognizable error instead of silently bypassing the gate.
	if on {
		cfg, err := config.LoadServerConfig(filepath.Join(configDir, "server.toml"))
		if err != nil {
			return fmt.Errorf("load server.toml to check exempt-user gate: %w", err)
		}
		if !cfg.Server.Quotas.User.AllowExemptUsers {
			return fmt.Errorf(
				"refusing to mark %s exempt: [server.quotas.user] allow_exempt_users = false in server.toml.\n"+
					"Set allow_exempt_users = true and reload the server, then re-run this command.\n"+
					"(Default false is the admin-managed posture — exempting a user bypasses the daily upload cap entirely.)",
				userID,
			)
		}
	}

	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	if err := st.SetUserQuotaExempt(userID, on); err != nil {
		return fmt.Errorf("set quota exempt: %w", err)
	}
	state := "off"
	if on {
		state = "on"
	}
	fmt.Printf("user quota-exempt: %s → %s\n", userID, state)
	return nil
}

// cmdQuotaReport prints the top-N users by recent upload volume.
// Useful for investigating after an admin_notify quota_sustained or
// quota_block event. No-op-but-explicit when quotas are disabled.
//
// Usage:
//   sshkey-ctl quota-report                    # last 7 days, top 10
//   sshkey-ctl quota-report --days 30          # last 30 days
//   sshkey-ctl quota-report --top 5            # top 5 only
//   sshkey-ctl quota-report --days 14 --top 20 # both
func cmdQuotaReport(dataDir string, args []string) error {
	days := 7
	top := 10
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--days":
			if i+1 >= len(args) {
				return fmt.Errorf("--days requires a number")
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < 1 {
				return fmt.Errorf("--days must be a positive integer, got %q", args[i+1])
			}
			days = n
			i++
		case "--top":
			if i+1 >= len(args) {
				return fmt.Errorf("--top requires a number")
			}
			n, err := strconv.Atoi(args[i+1])
			if err != nil || n < 1 {
				return fmt.Errorf("--top must be a positive integer, got %q", args[i+1])
			}
			top = n
			i++
		default:
			return fmt.Errorf("unknown flag: %s\nusage: sshkey-ctl quota-report [--days N] [--top M]", args[i])
		}
	}

	st, err := store.Open(dataDir)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	// Aggregate by user across the windowed range. Two-pass: walk
	// every user, sum their last-N-days bytes, sort descending, print
	// top-M. At small scales (say <1000 users) this is fine; if
	// operator scale grows, swap for a single GROUP BY query.
	users := st.GetAllUsers()
	type aggregated struct {
		userID      string
		displayName string
		totalBytes  int64
		days        int
	}
	var rows []aggregated
	for _, u := range users {
		recent, err := st.GetRecentUploadDays(u.ID, days)
		if err != nil {
			fmt.Printf("warn: GetRecentUploadDays(%s) failed: %v\n", u.ID, err)
			continue
		}
		var total int64
		for _, r := range recent {
			total += r.BytesTotal
		}
		if total == 0 {
			continue // no uploads in window — skip
		}
		rows = append(rows, aggregated{
			userID:      u.ID,
			displayName: u.DisplayName,
			totalBytes:  total,
			days:        len(recent),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		return rows[i].totalBytes > rows[j].totalBytes
	})
	if top < len(rows) {
		rows = rows[:top]
	}

	if len(rows) == 0 {
		fmt.Printf("No upload activity in the last %d day(s).\n", days)
		return nil
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02")
	fmt.Printf("Top %d users by upload volume since %s (last %d day(s)):\n", len(rows), cutoff, days)
	fmt.Printf("%-25s  %-30s  %-12s  %s\n", "USER_ID", "DISPLAY_NAME", "TOTAL", "DAYS_ACTIVE")
	for _, r := range rows {
		fmt.Printf("%-25s  %-30s  %-12s  %d\n",
			r.userID, r.displayName, formatBytes(r.totalBytes), r.days)
	}
	return nil
}
