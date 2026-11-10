// Package testutil provides shared test infrastructure for sshkey-chat.
package testutil

// Shared named identities use the same canonical builders as other fixtures.
var (
	AliceUsername = UserID("alice_test")
	BobUsername   = UserID("bob_test")
	CarolUsername = UserID("carol_test")
)

const (
	AliceDisplayName = "alice"
	BobDisplayName   = "bob"
	CarolDisplayName = "carol"
)
