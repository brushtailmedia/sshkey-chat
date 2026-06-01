// Package actionauth is the server's independent implementation of the F6
// signed-action canonical-form protocol spec (see the f6-delete-authentication
// design). It verifies client-signed mutation requests (delete now; un-react to
// follow) as a DATA-INTEGRITY gate — so the server never executes an
// irreversible mutation (e.g. a soft-delete that blanks content) on a
// cryptographically-invalid request, and never persists a tombstone that
// conformant clients would reject.
//
// It is NOT the security boundary: the SSH session is already authenticated, so
// verifying only confirms the session user signed their own action; a malicious
// server is still defeated solely by client-side re-verification on receipt.
//
// This package deliberately depends on NO sshkey-term code. The canonical forms
// here ("delete:v1", length-prefixed via AppendField) are an independent
// implementation of the normative protocol spec; byte-identity with every
// client is the interop contract guaranteed by the cross-repo conformance
// vector, not by code sharing. A third-party client that follows the spec
// interoperates with no change here.
package actionauth

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// AppendField appends field to out, prefixed by its big-endian uint32 length —
// the length-prefixing primitive that makes adjacent variable-length fields in a
// signed canonical form unambiguous (so two different field tuples can never
// produce identical signed bytes, without relying on any field being a fixed
// length). Independent re-implementation of the client's appendField; the two
// MUST produce identical bytes.
func AppendField(out, field []byte) []byte {
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(field)))
	out = append(out, l[:]...)
	return append(out, field...)
}

// BuildDeleteCanonical builds the byte string signed by the client's SignDelete
// and verified by VerifyDelete. Normative form (kind ∈ {"room","group","dm"};
// contextID is the room/group/DM id):
//
//	"delete:v1" || u32_be(len(kind)) || kind || u32_be(len(contextID)) || contextID || u32_be(len(msgID)) || msgID
func BuildDeleteCanonical(kind, contextID, msgID string) []byte {
	const tag = "delete:v1"
	out := make([]byte, 0, len(tag)+4+len(kind)+4+len(contextID)+4+len(msgID))
	out = append(out, tag...)
	out = AppendField(out, []byte(kind))
	out = AppendField(out, []byte(contextID))
	return AppendField(out, []byte(msgID))
}

// VerifyDelete reports whether sig is a valid Ed25519 signature by pub over the
// BuildDeleteCanonical form for (kind, contextID, msgID). It guards the key/sig
// sizes so a malformed input can never panic ed25519.Verify.
func VerifyDelete(pub ed25519.PublicKey, kind, contextID, msgID string, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, BuildDeleteCanonical(kind, contextID, msgID), sig)
}

// ParseSSHEd25519PubKey extracts an ed25519.PublicKey from an SSH
// authorized_keys-format string (the format users.Key is stored in). Returns an
// error for an unparseable or non-Ed25519 key. Independent of, but byte-for-byte
// equivalent to, the client's ParseSSHPubKey.
func ParseSSHEd25519PubKey(authorizedKey string) (ed25519.PublicKey, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return nil, err
	}
	cryptoPub, ok := pub.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("key does not implement CryptoPublicKey")
	}
	edKey, ok := cryptoPub.CryptoPublicKey().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an Ed25519 key")
	}
	return edKey, nil
}

// DecodeEd25519Signature base64-decodes a wire signature and confirms it is
// exactly ed25519.SignatureSize bytes, so a caller can reject a malformed or
// wrong-length signature before verifying.
func DecodeEd25519Signature(b64 string) ([]byte, error) {
	sig, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("signature not base64: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, fmt.Errorf("signature wrong length: got %d, want %d", len(sig), ed25519.SignatureSize)
	}
	return sig, nil
}
