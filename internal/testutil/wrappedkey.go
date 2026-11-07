package testutil

import (
	"crypto/sha512"
	"encoding/base64"
)

// WrappedKeyChars is the length of a production wrapped_keys value: a
// 92-byte wrap (ephemeral public key, nonce, sealed key) base64-encoded.
const WrappedKeyChars = 124

// WrappedKey returns a deterministic, real-size wrapped_keys value for test
// fixtures: 92 bytes derived from seed, base64-encoded to WrappedKeyChars.
// Fixtures must use real-size entries — a four-character dummy hid, for
// months, that a group at the member cap could not send a message under the
// 16 KB frame check, because every test frame was tiny. The server package's
// TestFixtures_NoDummyWrappedKeys fails the build on a short literal.
// Distinct seeds give distinct values, so a test asserting that an edit
// replaced the keys keeps working.
func WrappedKey(seed string) string {
	a := sha512.Sum512([]byte(seed))
	b := sha512.Sum512([]byte(seed + "\x00"))
	raw := append(a[:], b[:]...)[:92]
	return base64.StdEncoding.EncodeToString(raw)
}
