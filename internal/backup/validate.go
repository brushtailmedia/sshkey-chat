package backup

import (
	"fmt"
	"regexp"
)

// labelPattern is the allowed character set for backup labels.
// Phase 19 decision #7: whitelist [A-Za-z0-9_-]{1,32}. The
// character set is path-safe (no slashes, no dots, no spaces) and
// the length cap prevents operators from embedding novel-length
// strings into backup filenames. Rejects path-traversal attempts
// (../../etc/passwd) at the earliest possible point — before any
// filesystem operations.
var labelPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

// ValidateLabel returns nil if label is either empty (no label — a
// valid case) or matches the whitelist pattern. All other inputs
// produce a clear error naming the offending input so CLI callers
// can surface it to the operator.
func ValidateLabel(label string) error {
	if label == "" {
		return nil
	}
	if !labelPattern.MatchString(label) {
		return fmt.Errorf("invalid label %q: must match %s", label, labelPattern.String())
	}
	return nil
}
