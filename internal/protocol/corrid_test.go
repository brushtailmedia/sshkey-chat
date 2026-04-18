package protocol

// Phase 17c Step 1 — corr_id validator tests.

import (
	"errors"
	"strings"
	"testing"
)

func TestValidateCorrID_EmptyIsValid(t *testing.T) {
	// Empty corr_id is valid — field is omitempty on the wire.
	if err := ValidateCorrID(""); err != nil {
		t.Errorf("empty corr_id = %v, want nil (omitempty convention)", err)
	}
}

func TestValidateCorrID_ValidNanoID(t *testing.T) {
	// Every alphabet character permutation must pass. Use the full
	// alphabet spread over the 21-char body.
	valid := "corr_0123456789ABCDEFGHIJK"
	if err := ValidateCorrID(valid); err != nil {
		t.Errorf("valid corr_id %q = %v, want nil", valid, err)
	}
}

func TestValidateCorrID_WrongPrefix(t *testing.T) {
	// 26-char length is correct, but prefix isn't "corr_".
	invalid := "usr__0123456789ABCDEFGHIJK"
	err := ValidateCorrID(invalid)
	if err == nil {
		t.Fatalf("wrong-prefix %q accepted, want rejection", invalid)
	}
	if !errors.Is(err, ErrInvalidCorrIDPrefix) {
		t.Errorf("error sentinel = %v, want ErrInvalidCorrIDPrefix", err)
	}
}

func TestValidateCorrID_WrongLength(t *testing.T) {
	cases := []struct {
		name, id string
	}{
		{"too_short", "corr_abc"},
		{"too_long", "corr_0123456789ABCDEFGHIJK_extra"},
		{"prefix_only", "corr_"},
		{"empty_body_plus_one", "corr_A"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCorrID(tc.id)
			if err == nil {
				t.Fatalf("wrong-length %q accepted, want rejection", tc.id)
			}
			if !errors.Is(err, ErrInvalidCorrIDLength) {
				t.Errorf("error sentinel = %v, want ErrInvalidCorrIDLength", err)
			}
		})
	}
}

func TestValidateCorrID_BadAlphabet(t *testing.T) {
	// 26 chars with prefix "corr_" but a body character outside the
	// nanoid alphabet.
	cases := []struct {
		name, id string
	}{
		{"space", "corr_01234567890123456789 "},
		{"dot", "corr_0123456789012345678.A"},
		{"exclamation", "corr_!123456789012345678AB"},
		{"tab", "corr_\t123456789012345678AB"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateCorrID(tc.id)
			if err == nil {
				t.Fatalf("bad-alphabet %q accepted, want rejection", tc.id)
			}
			if !errors.Is(err, ErrInvalidCorrIDAlphabet) {
				t.Errorf("error sentinel = %v, want ErrInvalidCorrIDAlphabet", err)
			}
		})
	}
}

func TestValidateCorrID_AllAlphabetCharsAccepted(t *testing.T) {
	// Every character in the alphabet must be accepted in the body.
	// Alphabet is 64 chars; 21 of them in the body.
	for _, ch := range corrIDAlphabet {
		body := strings.Repeat(string(ch), 21)
		id := "corr_" + body
		if err := ValidateCorrID(id); err != nil {
			t.Errorf("alphabet char %q rejected: %v", ch, err)
		}
	}
}
