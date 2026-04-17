package server

import (
	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// Client represents a connected client session.
//
// Phase 17 Step 4.f removed the per-session `DownloadChannel` field.
// Downloads now open their own SSH channel per request (type
// `sshkey-chat-download`), handled by `handleDownloadChannel` outside
// this struct's lifecycle. The upload channel is still server-receives-
// only, read by `handleBinaryChannel`, and does not need storage here.
type Client struct {
	UserID       string // nanoid (usr_ prefix) — immutable identity
	DeviceID     string
	Encoder      *protocol.Encoder
	Decoder      *protocol.Decoder
	Channel      ssh.Channel // NDJSON control-plane channel (the 1st "session" channel on this connection)
	Conn         *ssh.ServerConn
	Capabilities []string // negotiated capabilities
}
