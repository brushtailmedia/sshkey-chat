package audit

// Phase 16 — audit log reader. Phase 16 added many CLI commands that
// write audit entries via the Log type above (bootstrap-admin,
// retire-user, unretire-user, promote, demote, rename-user,
// update-topic, rename-room, revoke-device, etc.) but the entries
// were invisible to operators because nothing read the file.
//
// This reader supplies the missing piece: parse the line-oriented
// text format, filter by time range / count / user, return entries
// in newest-first order. The CLI commands `audit-log` and
// `audit-user` are thin wrappers around the helpers here.
//
// The format is documented at the top of audit.go:
//
//	<RFC3339 timestamp>  <source padded>  <action padded>  <details>
//
// Padding is variable: the writer uses %-12s for source and %-15s
// for action, but values longer than the minimum are written
// unpadded. So the reader cannot use fixed column offsets — it must
// split on runs of whitespace. The regex below captures four
// non-overlapping fields with whitespace separators between them.

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Entry is a single parsed audit log line.
type Entry struct {
	Timestamp time.Time // parsed from the RFC3339 prefix
	Source    string    // e.g. "server", "user", "usr_3f9a...", "os:1000"
	Action    string    // e.g. "promote", "retire-user", "bootstrap-admin"
	Details   string    // free-form rest of the line
	Raw       string    // the original line as read from the file (for fallback display)
}

// entryPattern parses one audit line. Field 1 is the RFC3339
// timestamp (no internal spaces), 2 is source (no internal spaces),
// 3 is action (no internal spaces), 4 is the details remainder
// (anything until end of line, may contain spaces).
var entryPattern = regexp.MustCompile(`^(\S+)\s+(\S+)\s+(\S+)\s+(.*)$`)

// Parse parses a single audit log line into an Entry. Returns an
// error if the line doesn't match the expected format. Used by the
// reader functions below and exposed for tests.
func Parse(line string) (*Entry, error) {
	line = strings.TrimRight(line, "\r\n")
	if line == "" {
		return nil, fmt.Errorf("empty line")
	}
	m := entryPattern.FindStringSubmatch(line)
	if m == nil {
		return nil, fmt.Errorf("malformed audit line: %q", line)
	}
	ts, err := time.Parse(time.RFC3339, m[1])
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp %q: %w", m[1], err)
	}
	return &Entry{
		Timestamp: ts,
		Source:    m[2],
		Action:    m[3],
		Details:   m[4],
		Raw:       line,
	}, nil
}

// ReadOptions controls which entries are returned by Read.
type ReadOptions struct {
	// Since, if non-zero, filters entries to those at or after this
	// time. Set to time.Now().Add(-24*time.Hour) to get the last 24
	// hours, etc.
	Since time.Time

	// Limit caps the number of returned entries. 0 means no limit.
	// Applied AFTER all other filters, so the most recent N entries
	// matching the filters are returned.
	Limit int

	// User, if non-empty, filters to entries that mention this user
	// ID either in the Source field or anywhere in Details. Used by
	// the `audit-user` CLI command.
	User string
}

// Read reads the audit log file and returns matching entries in
// newest-first order. Malformed lines are skipped silently — they're
// logged to stderr but don't fail the whole call, since one bad row
// shouldn't poison an entire audit query.
//
// Returns an empty slice (not an error) if the file doesn't exist —
// a fresh server with no audit activity yet should produce a clean
// "no entries" output, not an error.
func Read(path string, opts ReadOptions) ([]*Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open audit log %s: %w", path, err)
	}
	defer f.Close()

	var all []*Entry
	scanner := bufio.NewScanner(f)
	// Audit lines are short (typically <300 chars) but we bump the
	// buffer to 64KB defensively in case future audit details grow
	// (e.g. JSON metadata blobs).
	scanner.Buffer(make([]byte, 0, 64*1024), 64*1024)
	for scanner.Scan() {
		entry, err := Parse(scanner.Text())
		if err != nil {
			// Skip silently — caller sees the parse failure via
			// the missing entry, not an aborted call. Log to
			// stderr so the operator notices.
			fmt.Fprintf(os.Stderr, "audit: skipping malformed line: %v\n", err)
			continue
		}
		if !matchesFilters(entry, opts) {
			continue
		}
		all = append(all, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read audit log: %w", err)
	}

	// Newest-first.
	sort.Slice(all, func(i, j int) bool {
		return all[i].Timestamp.After(all[j].Timestamp)
	})

	if opts.Limit > 0 && len(all) > opts.Limit {
		all = all[:opts.Limit]
	}
	return all, nil
}

// matchesFilters returns true if the entry passes all filters in
// opts. Empty/zero filter fields are treated as "match all".
func matchesFilters(e *Entry, opts ReadOptions) bool {
	if !opts.Since.IsZero() && e.Timestamp.Before(opts.Since) {
		return false
	}
	if opts.User != "" {
		// Match if the user appears in Source or Details. Both are
		// case-sensitive — user IDs are case-sensitive nanoids in
		// ssh-chat.
		if !strings.Contains(e.Source, opts.User) && !strings.Contains(e.Details, opts.User) {
			return false
		}
	}
	return true
}

// ParseDuration is a wrapper around time.ParseDuration that also
// accepts "<N>d" for N days, since Go's standard time.ParseDuration
// only supports h/m/s/ms/us/ns. The audit-log CLI accepts --since
// arguments like "24h", "7d", "30d" — operators expect d to work.
//
// "1d" → 24h, "7d" → 168h, etc. Falls through to time.ParseDuration
// for anything else.
func ParseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	if strings.HasSuffix(s, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil {
			return 0, fmt.Errorf("invalid days in %q: %w", s, err)
		}
		if days < 0 {
			return 0, fmt.Errorf("negative duration: %q", s)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}
