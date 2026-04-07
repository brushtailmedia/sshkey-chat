package config

import "testing"

func TestValidateDisplayName_Valid(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Alice", "Alice"},
		{"  Alice  ", "Alice"},           // trimmed
		{"Alice Chen", "Alice Chen"},     // spaces ok
		{"José", "José"},                 // accented
		{"田中太郎", "田中太郎"},               // CJK
		{"Al", "Al"},                     // min length
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
	}
	for _, tc := range tests {
		_, err := ValidateDisplayName(tc.input)
		if err == nil {
			t.Errorf("ValidateDisplayName(%q) should reject (%s)", tc.input, tc.desc)
		}
	}
}
