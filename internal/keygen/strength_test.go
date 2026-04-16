package keygen

// Phase 16 Gap 4 — tests for the zxcvbn-based passphrase strength
// checker used by `sshkey-ctl bootstrap-admin`. Covers:
//
//   - empty passphrase rejection
//   - short passphrase rejection (< MinPassphraseLength)
//   - score tier classification (weak / strong) via representative
//     passphrases pulled from common breach lists
//   - error message content (should mention crack time + reason)
//   - context-aware rejection (user's own display name)
//
// Does NOT test zxcvbn itself — the point is to verify our wrapper
// and tier thresholds, not re-litigate zxcvbn's entropy analysis.

import (
	"strings"
	"testing"
)

func TestValidateAdminPassphrase_Empty(t *testing.T) {
	err := ValidateAdminPassphrase("")
	if err == nil {
		t.Fatal("expected empty passphrase to be rejected")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("empty error should mention 'required', got: %v", err)
	}
}

func TestValidateAdminPassphrase_TooShort(t *testing.T) {
	cases := []string{
		"a",
		"abc",
		"password",      // 8 chars, below min
		"hunter2hunt",   // 11 chars, just below min (if MinPassphraseLength=12)
	}
	for _, pass := range cases {
		t.Run(pass, func(t *testing.T) {
			err := ValidateAdminPassphrase(pass)
			if err == nil {
				t.Fatalf("expected %q to be rejected for length", pass)
			}
			if !strings.Contains(err.Error(), "at least") {
				t.Errorf("short error should mention 'at least', got: %v", err)
			}
		})
	}
}

// TestValidateAdminPassphrase_WeakPatterns checks that passphrases
// meeting the length floor but failing zxcvbn's pattern analysis are
// still rejected. Each case is at least MinPassphraseLength chars so
// it passes the length gate — we're testing the zxcvbn score gate.
func TestValidateAdminPassphrase_WeakPatterns(t *testing.T) {
	cases := []struct {
		name string
		pass string
	}{
		{"common_password_padded", "password1234"},     // top-100 breached word + trivial digits
		{"keyboard_walk", "qwertyuiopas"},               // spatial pattern
		{"dictionary_word_repeated", "bananabanana"},    // dictionary + repetition
		{"date_pattern_long", "december252025"},         // date pattern
		{"number_sequence", "123456789012"},             // numeric sequence
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateAdminPassphrase(tc.pass)
			if err == nil {
				t.Errorf("expected %q to be rejected (weak pattern)", tc.pass)
				return
			}
			msg := err.Error()
			if !strings.Contains(msg, "cracked in") {
				t.Errorf("weak-pattern error should mention crack time, got: %v", err)
			}
		})
	}
}

// TestValidateAdminPassphrase_StrongPatterns verifies that genuinely
// strong passphrases are accepted. These should clear zxcvbn score >= 3
// under an offline-fast attacker model. If this test breaks after a
// zxcvbn dictionary update, the fix is to pick a different random
// passphrase, not to lower the floor.
func TestValidateAdminPassphrase_StrongPatterns(t *testing.T) {
	cases := []struct {
		name string
		pass string
	}{
		// Random passphrase from a password manager — high entropy,
		// no patterns. Should sail through.
		{"random_gibberish", "xK9#mPq2Rt$Lw7"},
		// Four unrelated words (diceware-style). Classic xkcd 936.
		{"four_words", "correct horse battery staple"},
		// Mixed case + digits + symbols, 16 chars, no dictionary hits.
		{"mixed_random", "Tz!4pQ@9nW#8vR$x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateAdminPassphrase(tc.pass)
			if err != nil {
				t.Errorf("expected %q to pass, got error: %v", tc.pass, err)
			}
		})
	}
}

// TestValidateAdminPassphraseWithContext verifies that a passphrase
// built primarily out of context strings (the admin's own display
// name) is treated as weak. zxcvbn penalizes context-word matches the
// same way it penalizes dictionary-word matches — they become a
// recognizable "word" that zxcvbn counts as a single guess, so a
// passphrase that's mostly context is scored like a passphrase that's
// mostly a dictionary word.
func TestValidateAdminPassphraseWithContext(t *testing.T) {
	// Passphrase is almost entirely the context string with trivial
	// padding. This should be rejected because zxcvbn treats "alice"
	// (with context) the way it treats "password" (without) — a
	// recognizable token that costs ~1 guess to try.
	pass := "alicealicealice"
	context := []string{"alice"}

	err := ValidateAdminPassphraseWithContext(pass, context)
	if err == nil {
		t.Errorf("expected %q with context %v to be rejected (passphrase is just the context word repeated)", pass, context)
	}
}

// TestValidateAdminPassphrase_ErrorMessageContent verifies the error
// message has the expected shape: crack time + reason + guidance on
// what to pick instead. This is a contract test for the CLI layer —
// if the message format changes, CLI tests that grep for these
// substrings will need to update too.
func TestValidateAdminPassphrase_ErrorMessageContent(t *testing.T) {
	err := ValidateAdminPassphrase("password1234")
	if err == nil {
		t.Fatal("expected rejection")
	}
	msg := err.Error()
	wantSubstrings := []string{
		"too weak",
		"cracked in",
		"Choose a stronger one",
	}
	for _, want := range wantSubstrings {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q, got: %v", want, err)
		}
	}
}

// TestCrackTimeDisplay exercises the tier thresholds directly — each
// tier should produce a distinct human-readable string. Under the
// offline-fast attacker model (10^10 guesses/sec), crack-time seconds
// = guesses / 1e10, so the thresholds land as:
//
//	< 1e10 guesses    → less than a second
//	< 6e11            → seconds
//	< 3.6e13          → minutes
//	< 8.64e14         → hours
//	< 2.59e16         → days
//	< 3.15e17         → months
//	< 3.15e18         → years
//	else              → centuries
func TestCrackTimeDisplay(t *testing.T) {
	cases := []struct {
		guesses float64
		wantHas string
	}{
		{1, "less than"},     // 1e-10 seconds → less than a second
		{1e10, "second"},     // 1 second
		{1e12, "minutes"},    // 100 seconds → 1 minute
		{1e14, "hours"},      // 10000 seconds → 2 hours
		{1e15, "days"},       // 100000 seconds → 1 day
		{1e17, "months"},     // 1e7 seconds → ~3 months
		{1e18, "years"},      // 1e8 seconds → ~3 years
		{1e25, "centuries"},  // far beyond 10-year threshold
	}
	for _, tc := range cases {
		got := crackTimeDisplay(tc.guesses)
		if !strings.Contains(got, tc.wantHas) {
			t.Errorf("crackTimeDisplay(%g) = %q, want substring %q", tc.guesses, got, tc.wantHas)
		}
	}
}

// TestPatternExplanation_EmptySequence covers the defensive path when
// zxcvbn returns no patterns at all. Shouldn't happen with a non-empty
// passphrase but we want a useful fallback message.
func TestPatternExplanation_EmptySequence(t *testing.T) {
	got := patternExplanation(nil)
	if got == "" {
		t.Error("empty sequence should produce a non-empty explanation")
	}
	if !strings.Contains(got, "predictable") && !strings.Contains(got, "short") {
		t.Errorf("fallback explanation should mention predictability or length, got: %q", got)
	}
}
