// Package keygen provides passphrase strength validation for
// key-generation CLI flows (bootstrap-admin and any future server-side
// keygen commands).
//
// Uses zxcvbn (https://github.com/trustelem/zxcvbn) for entropy scoring
// instead of the HaveIBeenPwned Pwned Passwords dataset. Rationale:
//
//   - HIBP is ~40GB and designed for credential-stuffing defense against
//     web login forms. ssh-chat has no login form — authentication is
//     SSH keys. The threat model is offline dictionary attack on a
//     stolen encrypted private key file, which zxcvbn's pattern-based
//     entropy analysis addresses directly.
//   - zxcvbn ships ~30KB of bundled dictionaries and produces a 0-4
//     score plus a guesses estimate we convert to a crack-time display
//     using an offline-fast attacker model (10^10 guesses/sec, which
//     corresponds to a GPU rig attacking stolen encrypted keys).
//
// Admin passphrases (this package) require score >= 3. User passphrases
// on the client side (sshkey-term's mirror of this package) allow
// score >= 2 with a warn-and-continue UX. Admin keys warrant the
// stricter floor because compromise impact is higher.
package keygen

import (
	"fmt"
	"strings"

	"github.com/trustelem/zxcvbn"
	"github.com/trustelem/zxcvbn/match"
)

// MinPassphraseLength is the hard floor below which any passphrase is
// rejected regardless of zxcvbn score. 12 chars is enough that a purely
// random passphrase (even mixed case + digits + some symbols) clears
// zxcvbn score 3. Anything shorter is rejected before we spend the
// zxcvbn cycles to analyze it.
const MinPassphraseLength = 12

// MinAdminScore is the zxcvbn score floor for admin passphrases.
// Scores map to these rough crack-time estimates under an offline-fast
// attacker model (10^10 guesses/sec):
//
//	0 = seconds
//	1 = minutes
//	2 = hours
//	3 = days
//	4 = centuries
//
// Admins must hit at least 3. Regular users (client-side) have a
// softer floor with warn-and-continue at 2.
const MinAdminScore = 3

// offlineFastGuessesPerSec is the attacker model we use for crack-time
// estimates. Assumes a GPU rig attacking a stolen, encrypted SSH
// private key file offline. 10^10 is a commonly cited figure for this
// class of attacker in 2026 with modern hardware.
const offlineFastGuessesPerSec = 1e10

// ValidateAdminPassphrase returns nil if the passphrase is strong
// enough to use for a bootstrap-admin keygen, or a descriptive error
// otherwise. The error message includes the zxcvbn-estimated crack
// time and a reason explaining what pattern made the passphrase weak.
// The CLI layer surfaces this error directly to the operator so they
// can pick a better passphrase on the next attempt.
func ValidateAdminPassphrase(pass string) error {
	return ValidateAdminPassphraseWithContext(pass, nil)
}

// ValidateAdminPassphraseWithContext is like ValidateAdminPassphrase
// but allows the caller to pass context strings (display name, server
// hostname) that zxcvbn will penalize if they appear in the passphrase.
// This catches the common "passphrase is my own username backwards" or
// "passphrase is the server name + 123" failure modes.
func ValidateAdminPassphraseWithContext(pass string, context []string) error {
	if pass == "" {
		return fmt.Errorf("passphrase is required — empty passphrases are never accepted for admin keys")
	}
	if len(pass) < MinPassphraseLength {
		return fmt.Errorf("passphrase must be at least %d characters (got %d)", MinPassphraseLength, len(pass))
	}

	result := zxcvbn.PasswordStrength(pass, context)
	if result.Score < MinAdminScore {
		return buildStrengthError(result)
	}
	return nil
}

// buildStrengthError formats a zxcvbn result into a user-facing error.
// Surfaces the crack-time estimate (computed from Guesses using the
// offline-fast attacker model) and a pattern-based explanation drawn
// from the top-scoring Match in the Sequence.
func buildStrengthError(r zxcvbn.Result) error {
	crackTime := crackTimeDisplay(r.Guesses)
	reason := patternExplanation(r.Sequence)
	return fmt.Errorf("passphrase is too weak: could be cracked in %s — %s. Choose a stronger one (try a random passphrase from a password manager, or 4+ unrelated words)", crackTime, reason)
}

// crackTimeDisplay converts a zxcvbn guesses estimate into a
// human-readable crack-time string under the offline-fast attacker
// model. Tiered thresholds match zxcvbn's own score boundaries so the
// display string aligns with the numeric score the operator sees in
// other tools.
func crackTimeDisplay(guesses float64) string {
	seconds := guesses / offlineFastGuessesPerSec
	switch {
	case seconds < 1:
		return "less than a second"
	case seconds < 60:
		return fmt.Sprintf("%d seconds", int(seconds))
	case seconds < 3600:
		return fmt.Sprintf("%d minutes", int(seconds/60))
	case seconds < 86400:
		return fmt.Sprintf("%d hours", int(seconds/3600))
	case seconds < 2592000: // 30 days
		return fmt.Sprintf("%d days", int(seconds/86400))
	case seconds < 31536000: // 1 year
		return fmt.Sprintf("%d months", int(seconds/2592000))
	case seconds < 315360000: // 10 years
		return fmt.Sprintf("%d years", int(seconds/31536000))
	default:
		return "centuries"
	}
}

// patternExplanation walks the zxcvbn match sequence and returns a
// human-readable explanation of the dominant weakness. zxcvbn's Go
// port doesn't provide a Feedback.Warning field like the JS API does,
// so we synthesize one from the Match.Pattern values. Prioritizes
// specific patterns (dictionary hits, dates) over generic ones
// (bruteforce segments) because specific patterns are what the user
// most wants to know about.
func patternExplanation(seq []*match.Match) string {
	if len(seq) == 0 {
		return "passphrase is too short or too predictable"
	}

	// Scan the sequence for the most diagnostic pattern and build a
	// short explanation. We prefer signals that tell the user
	// something actionable about why their choice was weak.
	var reasons []string
	for _, m := range seq {
		switch m.Pattern {
		case "dictionary":
			if m.L33t {
				reasons = append(reasons, fmt.Sprintf("leetspeak substitutions in %q are easy to guess", m.MatchedWord))
			} else if m.Reversed {
				reasons = append(reasons, fmt.Sprintf("reversed word %q is easy to guess", m.MatchedWord))
			} else {
				reasons = append(reasons, fmt.Sprintf("%q is a common word in the %s dictionary", m.MatchedWord, humanDictName(m.DictionaryName)))
			}
		case "spatial":
			reasons = append(reasons, fmt.Sprintf("keyboard pattern %q is easy to guess", m.Token))
		case "repeat":
			reasons = append(reasons, fmt.Sprintf("repeated sequence %q is easy to guess", m.Token))
		case "sequence":
			reasons = append(reasons, fmt.Sprintf("sequence %q (like abc or 123) is easy to guess", m.Token))
		case "regex":
			if m.RegexName == "recent_year" {
				reasons = append(reasons, fmt.Sprintf("recent year %q is easy to guess", m.Token))
			}
		case "date":
			reasons = append(reasons, fmt.Sprintf("date pattern %q is easy to guess", m.Token))
		}
	}

	if len(reasons) == 0 {
		// No specific pattern flagged — passphrase is just too short
		// or too simple overall (bruteforce fallback).
		return "passphrase is too short or too simple"
	}

	// Show at most two distinct reasons so the error message stays
	// terminal-friendly. If there are more, the first two are the
	// most diagnostic.
	if len(reasons) > 2 {
		reasons = reasons[:2]
	}
	return strings.Join(reasons, "; ")
}

// humanDictName translates zxcvbn's internal dictionary names into
// something more friendly for an error message.
func humanDictName(name string) string {
	switch name {
	case "passwords":
		return "common password"
	case "english_wikipedia":
		return "English"
	case "female_names", "male_names", "surnames":
		return "names"
	case "us_tv_and_film":
		return "pop-culture"
	default:
		return name
	}
}
