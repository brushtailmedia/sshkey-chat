package config

import (
	"strings"
	"testing"
)

func TestValidateDisplayName_Valid(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Alice", "Alice"},
		{"  Alice  ", "Alice"},       // trimmed
		{"Alice Chen", "Alice Chen"}, // spaces ok
		{"José", "José"},             // accented
		{"田中太郎", "田中太郎"},             // CJK
		{"Al", "Al"},                 // min length
		{"abcdefghijklmnopqrstuvwxyz123456", "abcdefghijklmnopqrstuvwxyz123456"}, // 32 chars
	}
	for _, tc := range tests {
		got, err := ValidateDisplayName(tc.input)
		if err != nil {
			t.Errorf("ValidateDisplayName(%q) error: %v", tc.input, err)
		}
		if got != tc.want {
			t.Errorf("ValidateDisplayName(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestValidateDisplayName_Invalid(t *testing.T) {
	tests := []struct {
		input string
		desc  string
	}{
		{"", "empty"},
		{"   ", "whitespace only"},
		{"A", "too short"},
		{"abcdefghijklmnopqrstuvwxyz1234567", "too long (33 chars)"},
		{"hello\x00world", "null byte"},
		{"hello\nworld", "newline"},
		{"hello\tworld", "tab"},
		{"test\u200Bname", "zero-width space"},
		{"test\u200Dname", "zero-width joiner"},
		{"test\u200Ename", "left-to-right mark"},
		{"test\uFEFFname", "BOM"},
		{"test\u202Aname", "bidi override"},
		{"test\u2060name", "word joiner"},
		{"alice+bob", "plus sign (DP9)"},
		{"+alice", "leading plus (DP9)"},
	}
	for _, tc := range tests {
		_, err := ValidateDisplayName(tc.input)
		if err == nil {
			t.Errorf("ValidateDisplayName(%q) should reject (%s)", tc.input, tc.desc)
		}
	}
}

func TestSanitizeRequestedNameHint(t *testing.T) {
	// Accepted \u2192 returned trimmed, unchanged. (A 1-char hint is transport-safe;
	// the 2\u201332 length policy is ValidateDisplayName's job at approve, not the
	// sanitizer's \u2014 \u00A70.1-B two-layer rule.)
	valid := map[string]string{
		"Alice":                    "Alice",
		"  Alice  ":                "Alice",
		"Alice Smith":              "Alice Smith",
		"Jos\u00E9":                "Jos\u00E9",
		"\u7530\u4E2D\u592A\u90CE": "\u7530\u4E2D\u592A\u90CE",
		"a":                        "a",
	}
	for in, want := range valid {
		if got := SanitizeRequestedNameHint(in); got != want {
			t.Errorf("SanitizeRequestedNameHint(%q) = %q, want %q", in, got, want)
		}
	}

	// Rejected \u2192 "" (whole-string reject, never a coerced substring).
	reject := []struct {
		in   string
		desc string
	}{
		{"", "empty"},
		{"   ", "whitespace only"},
		{strings.Repeat("a", 65), "65 bytes (over the 64 raw cap)"},
		{"alice+inv", "plus (DP3)"},
		{"+x", "leading plus"},
		{"alice+", "trailing plus"},
		{"hello\x00world", "null byte"},
		{"hello\nworld", "newline"},
		{"hello\rworld", "carriage return"},
		{"hello\tworld", "tab"},
		{"\x1b[31mx", "ESC / ANSI"},
		{"test\u200Bname", "zero-width space"},
		{"test\u202Aname", "bidi override"},
		{"test\u2060name", "word joiner"},
		{"\xff\xfe", "invalid UTF-8"},
	}
	for _, tc := range reject {
		if got := SanitizeRequestedNameHint(tc.in); got != "" {
			t.Errorf("SanitizeRequestedNameHint(%q) = %q, want \"\" (%s)", tc.in, got, tc.desc)
		}
	}
}
