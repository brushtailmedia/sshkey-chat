package server

import (
	"golang.org/x/crypto/ssh"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// Client represents a connected client session.
//
// Three SSH session channels are opened per connection, in fixed order:
//
//  1. Control / NDJSON (this struct's `Channel`). Long-lived control
//     plane — protocol verbs including `download` requests.
//  2. Download channel (`DownloadChannel`). Server writes raw file
//     bytes here in response to `download` verbs. One in-flight
//     download per session; client serializes.
//  3. Upload channel (handled elsewhere). Client writes raw bytes.
//
// Authorization (`authorizeDownload`), `file_contexts` binding, cascade
// cleanup, hash verification, and counter signals are all enforced on
// Channel 1's dispatch path before bytes move on Channel 2.
type Client struct {
	UserID          string // nanoid (usr_ prefix) — immutable identity
	DeviceID        string
	Encoder         *protocol.Encoder
	Decoder         *protocol.Decoder
	Channel         ssh.Channel // NDJSON control-plane channel (1st "session" channel)
	DownloadChannel ssh.Channel // shared download channel (2nd "session" channel); nil only if the client failed to open it within the grace period — downloads fail closed with not_found
	Conn            *ssh.ServerConn
	Capabilities    []string // negotiated capabilities
}
