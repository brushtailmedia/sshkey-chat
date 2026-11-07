package server

// sendToOwnOtherDevices relays verb/msg to every connected session of the
// same user except the one that produced it (same UserID, different
// DeviceID) — the multi-device-sync recipient set. Generalized from
// notifyNewDevice (devicemgmt.go); under Tier 1.5 this is
// otherUserSessions(c.UserID, c.DeviceID).
//
// Phase 17 Step 3 lock-release discipline: RLock → collect targets →
// release → fanOut, so no send happens under s.mu.
func (s *Server) sendToOwnOtherDevices(c *Client, verb string, msg any) {
	s.mu.RLock()
	var targets []*Client
	for _, cl := range s.clients {
		if cl.UserID == c.UserID && cl.DeviceID != c.DeviceID {
			targets = append(targets, cl)
		}
	}
	s.mu.RUnlock()
	if len(targets) == 0 {
		return
	}
	s.fanOut(verb, msg, targets)
}
