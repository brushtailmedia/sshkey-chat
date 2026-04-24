package main

// Phase 16 — destructive-action confirmation prompt.
//
// Every CLI command that makes an irreversible change prints a
// summary of what it's about to do and requires "yes" typed at the
// prompt (not just y / Enter — force the operator to type the full
// word). The --yes (or --force) flag bypasses the prompt for
// scripting.
//
// This file provides the shared hasForceFlag parser and
// confirmAction prompt used by retire-room, retire-user,
// revoke-device, purge, unretire-user, and prune-devices. The
// callers pass their args through hasForceFlag first to check for
// --yes / --force, then call confirmAction if the flag wasn't set.
//
// Note: prune-devices has its own --dry-run which is complementary
// — --dry-run previews without acting, --yes acts without prompting.
// They can be combined: --dry-run --yes is a no-op (dry-run wins).

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"
)

// hasForceFlag scans args for --yes or --force and returns true if
// found. Also removes the flag from the slice so the caller's
// flag parser doesn't see it as an unknown flag. Returns the
// cleaned args and whether the force flag was present.
func hasForceFlag(args []string) ([]string, bool) {
	var cleaned []string
	force := false
	for _, a := range args {
		if a == "--yes" || a == "--force" {
			force = true
		} else {
			cleaned = append(cleaned, a)
		}
	}
	return cleaned, force
}

// confirmAction prints a summary message and waits for the operator
// to type "yes" at the prompt. Returns nil if confirmed, or an
// error if the operator types anything else.
//
// When stdin is not a terminal (pipe, test harness, cron job), the
// prompt is SKIPPED and the command proceeds as if --yes were
// passed. This allows existing tests to keep working without
// modification and lets operators pipe commands through automation.
// The operator-facing protection is specifically for the interactive
// terminal case — scripts and automation should use --yes explicitly.
//
// The summary should describe what the command is about to do,
// ending with a newline. Example:
//
//	"About to retire room 'general'. This cannot be undone.\n"
func confirmAction(summary string) error {
	// Skip prompt when stdin is not a terminal (tests, pipes, cron).
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil
	}

	fmt.Print(summary)
	fmt.Print("Type 'yes' to confirm: ")

	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("confirmation failed (could not read stdin): %w", err)
	}
	input = strings.TrimSpace(input)
	if input != "yes" {
		return fmt.Errorf("aborted (you typed %q, expected 'yes')", input)
	}
	return nil
}
