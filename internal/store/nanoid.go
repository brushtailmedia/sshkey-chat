package store

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

const idAlphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-"

// GenerateID creates a nanoid with the given prefix (e.g. "usr_", "room_").
// 21 random characters from a 64-char alphabet = 126 bits entropy.
// Uses crypto/rand for cryptographic safety.
func GenerateID(prefix string) string {
	b := make([]byte, 21)
	for i := range b {
		n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(idAlphabet))))
		b[i] = idAlphabet[n.Int64()]
	}
	return prefix + string(b)
}

// GenerateRoomID creates a nanoid with room_ prefix.
func GenerateRoomID() string {
	return GenerateID("room_")
}

// Error sentinels for ValidateNanoID. Use errors.Is to classify failures.
var (
	// ErrInvalidNanoIDPrefix indicates the id does not start with the expected
	// prefix, OR the expectedPrefix itself is empty or contains a byte outside
	// the nanoid alphabet (a caller / programmer error).
	ErrInvalidNanoIDPrefix = errors.New("invalid nanoid prefix")

	// ErrInvalidNanoIDLength indicates the id length does not equal
	// len(expectedPrefix) + 21.
	ErrInvalidNanoIDLength = errors.New("invalid nanoid length")

	// ErrInvalidNanoIDAlphabet indicates the id body contains a byte outside
	// the 64-char nanoid alphabet (0-9, A-Z, a-z, '_', '-').
	ErrInvalidNanoIDAlphabet = errors.New("invalid nanoid alphabet")
)

// ValidateNanoID reports whether id is a well-formed nanoid that starts with
// expectedPrefix.
//
// Validation proceeds in this order, and the ordering is part of the contract
// (asserted by tests):
//
//  1. expectedPrefix precondition — must be non-empty and every byte must be
//     in the nanoid alphabet. Caller / programmer check; a malformed prefix
//     means the rest of validation cannot be meaningfully performed. Returns
//     ErrInvalidNanoIDPrefix on failure.
//  2. Length — id must be exactly len(expectedPrefix) + 21 bytes. Performed
//     first among id-side checks to bound the id before subsequent steps
//     look at its contents (so a gigabyte bogus input is rejected cheaply
//     without allocating a gigabyte error string). Returns
//     ErrInvalidNanoIDLength on failure.
//  3. Prefix match — id must begin with expectedPrefix. Returns
//     ErrInvalidNanoIDPrefix on failure.
//  4. Alphabet — every byte in the 21-char body must be in the nanoid
//     alphabet. Byte iteration (not rune) matches the byte-based length
//     check; a multi-byte UTF-8 character produces bytes ≥128 which are not
//     in the alphabet and are correctly rejected. Returns
//     ErrInvalidNanoIDAlphabet on failure.
//
// Use errors.Is to classify failures:
//
//	switch {
//	case errors.Is(err, ErrInvalidNanoIDLength):   // wrong size
//	case errors.Is(err, ErrInvalidNanoIDPrefix):   // wrong prefix / caller bug
//	case errors.Is(err, ErrInvalidNanoIDAlphabet): // bad byte in body
//	}
//
// Error messages intentionally omit the full id value on length failure
// (prevents formatting a huge error string for a giant bogus input) and on
// alphabet failure (messages include only the offending byte position).
// expectedPrefix IS included in messages where relevant, quoted via %q to
// neutralize any log-injection attempt via control characters.
//
// Performance: O(len(id)) time, zero allocation on the happy path. The
// function is a pure function with no package-level state; safe for
// concurrent use from any number of goroutines.
func ValidateNanoID(id, expectedPrefix string) error {
	// Step 0: precondition — expectedPrefix must itself be well-formed.
	// Run before the length check because if the prefix is malformed we
	// cannot even compute the expected length correctly.
	if expectedPrefix == "" {
		return fmt.Errorf("%w: expectedPrefix is empty", ErrInvalidNanoIDPrefix)
	}
	for i := 0; i < len(expectedPrefix); i++ {
		if strings.IndexByte(idAlphabet, expectedPrefix[i]) < 0 {
			return fmt.Errorf("%w: expectedPrefix %q contains byte outside alphabet at position %d",
				ErrInvalidNanoIDPrefix, expectedPrefix, i)
		}
	}

	// Step 1: length check. Bounds the id before we inspect its contents.
	want := len(expectedPrefix) + 21
	if len(id) != want {
		return fmt.Errorf("%w: got %d bytes, want %d", ErrInvalidNanoIDLength, len(id), want)
	}

	// Step 2: prefix match.
	if !strings.HasPrefix(id, expectedPrefix) {
		return fmt.Errorf("%w: id does not start with %q", ErrInvalidNanoIDPrefix, expectedPrefix)
	}

	// Step 3: alphabet check on the 21-char body. Byte iteration.
	for i := len(expectedPrefix); i < len(id); i++ {
		if strings.IndexByte(idAlphabet, id[i]) < 0 {
			return fmt.Errorf("%w: byte outside alphabet at position %d",
				ErrInvalidNanoIDAlphabet, i)
		}
	}

	return nil
}
