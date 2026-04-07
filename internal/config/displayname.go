package config

import (
	"fmt"
	"strings"
	"unicode"
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
	}

	return name, nil
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
