package store

import (
	"crypto/rand"
	"math/big"
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
