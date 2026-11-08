package server

import (
	"encoding/json"
	"fmt"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

// groupMaxMembers is the group-DM membership cap in force: [groups]
// max_members, or config.DefaultMaxGroupMembers when the section was elided
// or set to a non-positive value. Every reader of the cap (create, add,
// wrapped_keys envelope, frame budget, server_hello) goes through here so
// they cannot disagree.
func (s *Server) groupMaxMembers() int {
	s.cfg.RLock()
	n := s.cfg.Server.Groups.MaxMembers
	s.cfg.RUnlock()
	if n <= 0 {
		return config.DefaultMaxGroupMembers
	}
	return n
}

// groupFrameBudget is the largest raw group frame the server will parse: the
// body cap plus one protocol.WrappedKeyEntryBytes allowance for every member
// the cap allows. A group frame carries a wrapped key per member on top of
// the body, so a bare 16 KB frame check left a 100-member group about 400
// characters of body and stopped a group at the old cap from sending at all.
// The body itself is held to maxPayloadBytes after parsing (checkBodySize),
// so the budget buys room for keys, never a larger message.
func (s *Server) groupFrameBudget() int {
	return maxPayloadBytes + protocol.WrappedKeyEntryBytes*s.groupMaxMembers()
}

// checkGroupFrameSize rejects a raw group frame over groupFrameBudget before
// it is parsed. Same signal and wire error as the bare frame check on the
// other send verbs; the log line carries the arithmetic.
func (s *Server) checkGroupFrameSize(c *Client, raw json.RawMessage, verb string) bool {
	members := s.groupMaxMembers()
	budget := maxPayloadBytes + protocol.WrappedKeyEntryBytes*members
	if len(raw) > budget {
		s.rejectAndLog(c, counters.SignalOversizedBody, verb,
			fmt.Sprintf("raw=%d bytes exceeds group frame budget=%d (body %d + %d x %d wrapped-key entries)",
				len(raw), budget, maxPayloadBytes, protocol.WrappedKeyEntryBytes, members), nil)
		s.respondError(c, "", protocol.ErrMessageTooLarge, "Message exceeds 16KB limit", 0)
		return false
	}
	return true
}

// checkBodySize holds a parsed message body to maxPayloadBytes. The 16 KB
// rule is a rule about the body: on the group verbs the frame check above is
// looser than this by design, so this is what enforces it there.
func (s *Server) checkBodySize(c *Client, payload string, verb string) bool {
	if len(payload) > maxPayloadBytes {
		s.rejectAndLog(c, counters.SignalOversizedBody, verb,
			fmt.Sprintf("payload=%d bytes exceeds maxPayloadBytes=%d", len(payload), maxPayloadBytes), nil)
		s.respondError(c, "", protocol.ErrMessageTooLarge, "Message exceeds 16KB limit", 0)
		return false
	}
	return true
}

// serverLimits is the limits block sent in every server_hello: the size
// rules in force on this server, complete, so a client never hard-codes a
// number the operator may have set differently and needs no defaults of
// its own. Built per connection from the live config.
func (s *Server) serverLimits() protocol.ServerLimits {
	s.cfg.RLock()
	typing := s.cfg.Server.Rooms.TypingMaxMembers
	fileIDs := s.cfg.Server.Files.MaxFileIDsPerMessage
	s.cfg.RUnlock()
	return protocol.ServerLimits{
		MaxGroupMembers:      s.groupMaxMembers(),
		RoomTypingMaxMembers: typing,
		MaxBodyBytes:         maxPayloadBytes,
		WrappedKeyEntryBytes: protocol.WrappedKeyEntryBytes,
		MaxFileIDsPerMessage: fileIDs,
	}
}
