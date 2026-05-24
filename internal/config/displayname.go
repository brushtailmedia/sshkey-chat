package config

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ValidateDisplayName checks a display name for length, whitespace, and
// character validity. Returns nil if valid, an error describing the problem
// otherwise. Used by the server (set_profile), sshkey-ctl (approve), and
// referenced by the terminal client's wizard.
func ValidateDisplayName(name string) (string, error) {
	name = strings.TrimSpace(name)

	if name == "" {
		return "", fmt.Errorf("display name cannot be empty")
	}
	if len(name) < 2 {
		return "", fmt.Errorf("display name must be at least 2 characters")
	}
	if len(name) > 32 {
		return "", fmt.Errorf("display name must be 32 characters or fewer")
	}

	for _, r := range name {
		if !unicode.IsPrint(r) {
			return "", fmt.Errorf("display name contains non-printable character (U+%04X)", r)
		}
		if isRejectChar(r) {
			return "", fmt.Errorf("display name contains invalid character (U+%04X)", r)
		}
		if r == '+' {
			// DP9: '+' is banned in display names system-wide — reserved as the
			// future invite-code delimiter, kept out of the name policy so the
			// parser can own it explicitly. Intended pre-v1 break.
			return "", fmt.Errorf("display name may not contain '+'")
		}
	}

	return name, nil
}

// SanitizeRequestedNameHint turns an untrusted SSH-supplied username
// (conn.User()) into a safe display-name *hint* for pending_keys, or "" if the
// input is unusable. This is transport-safety only — DP1 reject-not-coerce,
// DP2 64-byte raw cap, DP3 reject-on-'+' — NOT the display-name policy: a hint
// promoted to a real display name (approve prefill) MUST still pass
// ValidateDisplayName + the uniqueness scan. Whole-string reject, never a
// coerced/stripped substring (a transformed attacker string is a liability).
func SanitizeRequestedNameHint(raw string) string {
	// DP2: cap the RAW input first, before trim/iteration, as a DoS guard.
	if len(raw) == 0 || len(raw) > 64 {
		return ""
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !utf8.ValidString(raw) {
		return ""
	}
	for _, r := range raw {
		if r == '+' {
			// DP3/DP9: reject the whole hint on any '+'.
			return ""
		}
		// unicode.IsPrint is false for C0/C1 controls incl. ESC, \n, \r, \t
		// (kills terminal-escape / admin_notify shape injection); isRejectChar
		// covers zero-width / bidi-override / invisible formatters. Shared with
		// ValidateDisplayName so the two validators can't drift.
		if !unicode.IsPrint(r) || isRejectChar(r) {
			return ""
		}
	}
	return raw
}

// isRejectChar returns true for zero-width, bidirectional override, and other
// invisible Unicode characters that IsPrint lets through.
func isRejectChar(r rune) bool {
	switch {
	// Zero-width characters
	case r == '\u200B': // zero-width space
		return true
	case r == '\u200C': // zero-width non-joiner
		return true
	case r == '\u200D': // zero-width joiner
		return true
	case r == '\u200E': // left-to-right mark
		return true
	case r == '\u200F': // right-to-left mark
		return true
	case r == '\uFEFF': // BOM / zero-width no-break space
		return true
	// Bidirectional overrides
	case r >= '\u202A' && r <= '\u202E':
		return true
	// Additional invisible formatters
	case r >= '\u2060' && r <= '\u2064':
		return true
	case r == '\u2066' || r == '\u2067' || r == '\u2068' || r == '\u2069':
		return true
	}
	return false
}
