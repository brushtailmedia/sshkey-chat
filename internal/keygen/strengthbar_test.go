package keygen

// Tests for StrengthBar — the 5-segment unicode bar used by
// sshkey-ctl bootstrap-admin for post-submit passphrase feedback.

import (
	"strings"
	"testing"
)

// TestStrengthBar_TooShort verifies that passphrases under the minimum
// length produce an empty bar + "too short" label, not a misleading
// score visualization.
func TestStrengthBar_TooShort(t *testing.T) {
	bar, label := StrengthBar("abc", nil)
	if bar != "▱▱▱▱▱" {
		t.Errorf("too-short bar = %q, want all-empty segments", bar)
	}
	if label != "too short" {
		t.Errorf("too-short label = %q, want 'too short'", label)
	}
}

// TestStrengthBar_VeryWeak covers a passphrase at score 0 — the
// bar should show exactly one filled segment.
func TestStrengthBar_VeryWeak(t *testing.T) {
	bar, label := StrengthBar("password1234", nil)
	// "password1234" hits score 0-1 depending on zxcvbn tuning; accept
	// either and assert the bar/label are consistent.
	if !strings.HasPrefix(bar, "▰") {
		t.Errorf("weak bar = %q, want at least one filled segment", bar)
	}
	if len(bar) == 0 {
		t.Error("weak bar should never be empty")
	}
	if label == "" || label == "too short" {
		t.Errorf("weak label = %q, want a score-based label", label)
	}
}

// TestStrengthBar_Strong covers a passphrase at score 3-4 — the bar
// should show 4 or 5 filled segments.
func TestStrengthBar_Strong(t *testing.T) {
	// Four unrelated words — reliably high zxcvbn score.
	bar, label := StrengthBar("correct horse battery staple elephant", nil)
	filled := strings.Count(bar, "▰")
	if filled < 4 {
		t.Errorf("strong bar = %q (%d filled), want >= 4 segments", bar, filled)
	}
	if !strings.Contains(label, "strong") {
		t.Errorf("strong label = %q, want to contain 'strong'", label)
	}
}

// TestStrengthBar_SegmentMapping verifies the exact score-to-segment
// mapping defined in the docstring. Uses the internal renderBar for
// deterministic input.
func TestStrengthBar_SegmentMapping(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{0, "▰▱▱▱▱"},
		{1, "▰▰▱▱▱"},
		{2, "▰▰▰▱▱"},
		{3, "▰▰▰▰▱"},
		{4, "▰▰▰▰▰"},
	}
	for _, tc := range cases {
		if got := renderBar(tc.score); got != tc.want {
			t.Errorf("renderBar(%d) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

// TestStrengthBar_ScoreLabel verifies the score-to-label mapping.
func TestStrengthBar_ScoreLabel(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{
		{0, "very weak"},
		{1, "weak"},
		{2, "borderline"},
		{3, "strong"},
		{4, "very strong"},
	}
	for _, tc := range cases {
		if got := scoreLabel(tc.score); got != tc.want {
			t.Errorf("scoreLabel(%d) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

// TestStrengthBar_Clamps ensures out-of-range scores don't produce
// malformed bars. zxcvbn should never return <0 or >4 but guard
// anyway — rendering a bar with 0 or 7 segments would break the UI.
func TestStrengthBar_Clamps(t *testing.T) {
	for _, score := range []int{-1, -100, 5, 99} {
		bar := renderBar(score)
		if len([]rune(bar)) != 5 {
			t.Errorf("renderBar(%d) produced %d runes, want 5", score, len([]rune(bar)))
		}
	}
}
