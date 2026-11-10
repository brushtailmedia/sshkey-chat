package server

import (
	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// validateIDOrReject checks syntax only. The caller keeps authorization,
// visibility and signature verification, and supplies its existing response
// action (nil for silent verbs). Callers return immediately on false, so a
// request with several malformed fields contributes one invalid-ID event.
func (s *Server) validateIDOrReject(c *Client, verb, id, prefix string, reject func()) bool {
	if err := store.ValidateNanoID(id, prefix); err != nil {
		s.rejectAndLog(c, counters.SignalInvalidNanoID, verb, "malformed identifier: "+err.Error(), nil)
		if reject != nil {
			reject()
		}
		return false
	}
	return true
}

// validateOptionalContexts checks supplied contexts without changing the
// caller's existing cardinality policy. Empty fields remain absent.
func (s *Server) validateOptionalContexts(c *Client, verb, room, group, dm string, reject func(string)) bool {
	for _, id := range []struct{ value, prefix, kind string }{{room, "room_", "room"}, {group, "group_", "group"}, {dm, "dm_", "dm"}} {
		if id.value == "" {
			continue
		}
		var action func()
		if reject != nil {
			action = func() { reject(id.kind) }
		}
		if !s.validateIDOrReject(c, verb, id.value, id.prefix, action) {
			return false
		}
	}
	return true
}
