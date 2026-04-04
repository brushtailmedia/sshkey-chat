package server

import (
	"crypto/rand"
	"math/big"
)

const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-"

// generateID creates a Nano ID with the given prefix.
// 21 characters of random data (126 bits entropy).
func generateID(prefix string) string {
	b := make([]byte, 21)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			panic("crypto/rand failed: " + err.Error())
		}
		b[i] = alphabet[n.Int64()]
	}
	return prefix + string(b)
}
