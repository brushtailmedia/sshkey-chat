package server

import (
	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey/internal/protocol"
)

// Client represents a connected client session.
type Client struct {
	Username    string
	DeviceID    string
	Encoder     *protocol.Encoder
	Decoder     *protocol.Decoder
	Channel     ssh.Channel
	Conn        *ssh.ServerConn
	Capabilities []string // negotiated capabilities
}
