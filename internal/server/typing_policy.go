package server

// roomTypingEnabled is the one rule for typing in rooms: relay while the
// room has [rooms] typing_max_members members or fewer, drop above it, and
// drop everywhere when the knob is zero. Typing is a per-person signal — a
// name on a "… is typing" line — and in a room of a thousand people it is a
// thousand-way fan-out of noise nobody reads. The same "100 people or fewer"
// rule governs every per-person signal the product has; this is where it
// lives for rooms. Groups are bounded by the group cap and 1:1 DMs always
// relay, so neither consults it.
//
// The count comes from the member list the caller already holds (the typing
// handler fetches it once for the broadcast; room_list and room_added_to
// build their payload from it), so the policy costs no query of its own.
func (s *Server) roomTypingEnabled(memberCount int) bool {
	s.cfg.RLock()
	k := s.cfg.Server.Rooms.TypingMaxMembers
	s.cfg.RUnlock()
	return k > 0 && memberCount <= k
}
