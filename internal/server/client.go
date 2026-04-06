package server

import (
	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// Client represents a connected client session.
type Client struct {
	Username        string
	DeviceID        string
	Encoder         *protocol.Encoder
	Decoder         *protocol.Decoder
	Channel         ssh.Channel // Channel 1: NDJSON protocol
	DownloadChannel ssh.Channel // Channel 2: server writes file bytes here (may be nil)
	Conn            *ssh.ServerConn
	Capabilities    []string // negotiated capabilities
	// The upload channel (Channel 3) is read by handleBinaryChannel and
	// does not need to be stored here — the server only receives uploads,
	// never writes to it.
}
