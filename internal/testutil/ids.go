// Package testutil provides deterministic, production-shaped test fixtures.
package testutil

import (
	"crypto/sha256"
	"encoding/base64"
)

// ID derives a stable fixture ID from a readable label. It is test data,
// not a random identifier generator for production use.
func ID(prefix, label string) string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-"
	sum := sha256.Sum256([]byte(label))
	var body [21]byte
	for i := range body {
		body[i] = alphabet[int(sum[i])%len(alphabet)]
	}
	return prefix + string(body[:])
}

func DeviceID(label string) string   { return ID("dev_", label) }
func UserID(label string) string     { return ID("usr_", label) }
func MsgID(label string) string      { return ID("msg_", label) }
func ReactionID(label string) string { return ID("react_", label) }
func RoomID(label string) string     { return ID("room_", label) }
func GroupID(label string) string    { return ID("group_", label) }
func DMID(label string) string       { return ID("dm_", label) }
func FileID(label string) string     { return ID("file_", label) }
func UploadID(label string) string   { return ID("up_", label) }

// Signature is a size-only Ed25519 envelope fixture. It is NOT a signature
// over a message: verification tests must sign with a real private key.
func Signature(label string) string {
	return base64.StdEncoding.EncodeToString(sizedBytes(label, 64))
}

// Payload supplies size-only opaque bytes, base64 encoded. It is NOT
// decryptable ciphertext; encryption/decryption tests use real crypto.
func Payload(label string, size int) string {
	return base64.StdEncoding.EncodeToString(sizedBytes(label, size))
}

func sizedBytes(label string, size int) []byte {
	sum := sha256.Sum256([]byte(label))
	b := make([]byte, size)
	for i := range b {
		b[i] = sum[i%len(sum)]
	}
	return b
}
