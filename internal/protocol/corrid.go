package protocol

// Phase 17c Step 1 — correlation ID validation.
//
// Format: `corr_` prefix + 21 characters from the nanoid alphabet
// (0-9, A-Z, a-z, '_', '-'). Total length 26 bytes; 126 bits of
// entropy in the body.
//
// Client generates via store.GenerateID("corr_") (or equivalent on
// the sshkey-term side); server never persists it — just validates
// shape on inbound, echoes on outbound. Empty (omitted) is valid
// because the field is marked `omitempty` in the protocol structs.
// Non-empty must pass ValidateCorrID or the handler rejects the
// envelope via SignalMalformedFrame.
//
// The alphabet + checks are duplicated from store.ValidateNanoID
// rather than imported because the protocol package is a leaf
// dependency — importing store from here would invert the layering.
// 15 lines of duplication are cheaper than the cross-package dance.

import (
	"errors"
	"fmt"
	"strings"
)

const (
	// corrIDPrefix is the required prefix for correlation IDs on the
	// wire. Fixed to match existing nanoid-with-prefix conventions
	// elsewhere in the protocol (usr_, room_, msg_, etc.).
	corrIDPrefix = "corr_"

	// corrIDBodyLen is the length of the random body after the prefix.
	// 21 chars × 6 bits/char = 126 bits of entropy — matches the rest
	// of the nanoid family.
	corrIDBodyLen = 21

	// corrIDAlphabet is the set of characters permitted in the random
	// body. Identical to store's nanoid alphabet; duplicated here to
	// keep the protocol package leaf-dependency-free.
	corrIDAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-"
)

// Sentinel errors for ValidateCorrID. Use errors.Is to classify.
var (
	// ErrInvalidCorrIDLength indicates the id is not exactly
	// len("corr_") + 21 bytes.
	ErrInvalidCorrIDLength = errors.New("invalid corr_id length")

	// ErrInvalidCorrIDPrefix indicates the id does not start with
	// "corr_".
	ErrInvalidCorrIDPrefix = errors.New("invalid corr_id prefix")

	// ErrInvalidCorrIDAlphabet indicates the id body contains a byte
	// outside the nanoid alphabet.
	ErrInvalidCorrIDAlphabet = errors.New("invalid corr_id alphabet")
)

// ValidateCorrID reports whether id is a well-formed corr_xxx
// correlation identifier. Empty id is valid (the protocol field is
// `omitempty`; absent == "no correlation tag", not an error).
//
// Non-empty must be exactly `corr_` + 21 body characters from the
// nanoid alphabet. Shape violations fire `counters.SignalMalformedFrame`
// at the caller (handler unmarshal-check block).
func ValidateCorrID(id string) error {
	if id == "" {
		return nil
	}
	want := len(corrIDPrefix) + corrIDBodyLen
	if len(id) != want {
		return fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidCorrIDLength, len(id), want)
	}
	if !strings.HasPrefix(id, corrIDPrefix) {
		return fmt.Errorf("%w: id does not start with %q", ErrInvalidCorrIDPrefix, corrIDPrefix)
	}
	for i := len(corrIDPrefix); i < len(id); i++ {
		if strings.IndexByte(corrIDAlphabet, id[i]) < 0 {
			return fmt.Errorf("%w: byte outside alphabet at position %d", ErrInvalidCorrIDAlphabet, i)
		}
	}
	return nil
}
