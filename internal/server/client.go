package server

import (
	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey/internal/protocol"
)

// Client represents a connected client session.
type Client struct {
	Username      string
	DeviceID      string
	Encoder       *protocol.Encoder
	Decoder       *protocol.Decoder
	Channel       ssh.Channel  // Channel 1: NDJSON protocol
	BinaryChannel ssh.Channel  // Channel 2: raw file bytes (may be nil)
	Conn          *ssh.ServerConn
	Capabilities  []string // negotiated capabilities
}
