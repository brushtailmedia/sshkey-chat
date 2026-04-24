package audit

// Phase 16 — tests for the audit log reader.
//
// Coverage:
//   - Parse: happy path, malformed line, empty line, bad timestamp
//     - variable-width source/action fields (the writer's %-12s/%-15s
//       padding produces unpredictable space runs when values exceed
//       the minimum width)
//     - details with internal spaces preserved
//   - Read: empty file, missing file, multiple entries newest-first,
//     limit applied after sort, since filter, user filter
//   - ParseDuration: standard h/m/s, custom d, invalid input

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- Parse tests ---

func TestParse_HappyPath(t *testing.T) {
	line := "2026-04-16T10:30:45Z  os:1000      promote          user=usr_alice"
	entry, err := Parse(line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if entry.Source != "os:1000" {
		t.Errorf("Source = %q", entry.Source)
	}
	if entry.Action != "promote" {
		t.Errorf("Action = %q", entry.Action)
	}
	if entry.Details != "user=usr_alice" {
		t.Errorf("Details = %q", entry.Details)
	}
	if entry.Timestamp.Year() != 2026 || entry.Timestamp.Month() != time.April {
		t.Errorf("Timestamp = %v", entry.Timestamp)
	}
}

func TestParse_LongSourceField(t *testing.T) {
	// Source longer than the 12-char minimum width — written
	// without padding, so the gap to action is just the separator
	// (2 spaces).
	line := "2026-04-16T10:30:45Z  usr_3f9a1b2c  bootstrap-admin  user_id=usr_alice"
	entry, err := Parse(line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if entry.Source != "usr_3f9a1b2c" {
		t.Errorf("Source = %q, want usr_3f9a1b2c", entry.Source)
	}
	if entry.Action != "bootstrap-admin" {
		t.Errorf("Action = %q", entry.Action)
	}
	if entry.Details != "user_id=usr_alice" {
		t.Errorf("Details = %q", entry.Details)
	}
}

func TestParse_DetailsWithInternalSpaces(t *testing.T) {
	line := `2026-04-16T10:30:45Z  os:1000      rename-user      user=usr_alice old=Alice new=Alicia`
	entry, err := Parse(line)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if entry.Details != "user=usr_alice old=Alice new=Alicia" {
		t.Errorf("Details = %q", entry.Details)
	}
}

func TestParse_EmptyLine(t *testing.T) {
	_, err := Parse("")
	if err == nil {
		t.Fatal("expected error on empty line")
	}
}

func TestParse_Malformed(t *testing.T) {
	_, err := Parse("just a single token")
	if err == nil {
		t.Fatal("expected error on malformed line")
	}
}

func TestParse_BadTimestamp(t *testing.T) {
	_, err := Parse("not-a-date  source  action  details")
	if err == nil {
		t.Fatal("expected error on bad timestamp")
	}
}

// --- Read tests ---

func writeAuditFile(t *testing.T, lines []string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	content := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0640); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

func TestRead_MissingFileReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log") // doesn't exist
	entries, err := Read(path, ReadOptions{})
	if err != nil {
		t.Fatalf("read missing file should return nil error, got: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries from missing file, got %d", len(entries))
	}
}

func TestRead_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	os.WriteFile(path, []byte{}, 0640)

	entries, err := Read(path, ReadOptions{})
	if err != nil {
		t.Fatalf("read empty file: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected 0 entries from empty file, got %d", len(entries))
	}
}

func TestRead_NewestFirst(t *testing.T) {
	// Lines are written in chronological order, but Read should
	// return them newest-first.
	path := writeAuditFile(t, []string{
		"2026-04-16T10:00:00Z  os:1000      promote          user=usr_a",
		"2026-04-16T11:00:00Z  os:1000      demote           user=usr_b",
		"2026-04-16T12:00:00Z  os:1000      retire-user      user=usr_c",
	})

	entries, err := Read(path, ReadOptions{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("expected 3 entries, got %d", len(entries))
	}
	if entries[0].Action != "retire-user" {
		t.Errorf("first entry should be newest (retire-user), got %q", entries[0].Action)
	}
	if entries[2].Action != "promote" {
		t.Errorf("last entry should be oldest (promote), got %q", entries[2].Action)
	}
}

func TestRead_LimitAfterSort(t *testing.T) {
	path := writeAuditFile(t, []string{
		"2026-04-16T10:00:00Z  os:1000      promote          user=usr_a",
		"2026-04-16T11:00:00Z  os:1000      demote           user=usr_b",
		"2026-04-16T12:00:00Z  os:1000      retire-user      user=usr_c",
	})

	entries, err := Read(path, ReadOptions{Limit: 2})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries (limit), got %d", len(entries))
	}
	// Limit picks the NEWEST 2, not the first 2 written.
	if entries[0].Action != "retire-user" {
		t.Errorf("first = %q, want retire-user", entries[0].Action)
	}
	if entries[1].Action != "demote" {
		t.Errorf("second = %q, want demote", entries[1].Action)
	}
}

func TestRead_SinceFilter(t *testing.T) {
	path := writeAuditFile(t, []string{
		"2026-04-16T08:00:00Z  os:1000      promote          user=usr_a",
		"2026-04-16T10:00:00Z  os:1000      demote           user=usr_b",
		"2026-04-16T12:00:00Z  os:1000      retire-user      user=usr_c",
	})

	since, _ := time.Parse(time.RFC3339, "2026-04-16T09:30:00Z")
	entries, err := Read(path, ReadOptions{Since: since})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries after since filter, got %d", len(entries))
	}
	for _, e := range entries {
		if e.Timestamp.Before(since) {
			t.Errorf("entry %q is before since=%v", e.Raw, since)
		}
	}
}

func TestRead_UserFilter_MatchesSource(t *testing.T) {
	path := writeAuditFile(t, []string{
		"2026-04-16T10:00:00Z  usr_alice    promote          user=usr_b",
		"2026-04-16T11:00:00Z  os:1000      demote           user=usr_c",
		"2026-04-16T12:00:00Z  usr_alice    retire-user      user=usr_d",
	})

	entries, err := Read(path, ReadOptions{User: "usr_alice"})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries matching usr_alice in source, got %d", len(entries))
	}
}

func TestRead_UserFilter_MatchesDetails(t *testing.T) {
	path := writeAuditFile(t, []string{
		"2026-04-16T10:00:00Z  os:1000      promote          user=usr_alice",
		"2026-04-16T11:00:00Z  os:1000      demote           user=usr_bob",
		"2026-04-16T12:00:00Z  os:1000      retire-user      user=usr_alice",
	})

	entries, err := Read(path, ReadOptions{User: "usr_alice"})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries matching usr_alice in details, got %d", len(entries))
	}
}

func TestRead_SkipsMalformedLines(t *testing.T) {
	path := writeAuditFile(t, []string{
		"2026-04-16T10:00:00Z  os:1000      promote          user=usr_a",
		"this is not a valid audit line",
		"2026-04-16T12:00:00Z  os:1000      retire-user      user=usr_c",
	})

	entries, err := Read(path, ReadOptions{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("expected 2 valid entries (skipping malformed), got %d", len(entries))
	}
}

// --- ParseDuration tests ---

func TestParseDuration_StandardUnits(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"24h", 24 * time.Hour},
		{"30m", 30 * time.Minute},
		{"15s", 15 * time.Second},
		{"1h30m", 90 * time.Minute},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseDuration(tc.in)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("ParseDuration(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseDuration_Days(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"1d", 24 * time.Hour},
		{"7d", 7 * 24 * time.Hour},
		{"30d", 30 * 24 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseDuration(tc.in)
			if err != nil {
				t.Fatalf("parse %q: %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("ParseDuration(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseDuration_Invalid(t *testing.T) {
	cases := []string{"", "abc", "5x", "-1d", "1.5d"}
	for _, in := range cases {
		t.Run(in, func(t *testing.T) {
			_, err := ParseDuration(in)
			if err == nil {
				t.Errorf("expected error for %q", in)
			}
		})
	}
}
