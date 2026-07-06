package server

import "testing"

// TestUnregisterClient_GuardsAgainstStaleTeardown locks the s.clients teardown
// guard (docs/planning/open/device-identity-transparency.md §4.5): a
// reconnecting client's new session overwrites the routing entry for its
// device_id, and the OLD session's teardown — which can run seconds later, when
// keepalive finally notices the dead connection — must not delete the live
// session's route. Unguarded, that left the live session connected but absent
// from every fan-out (silent broadcast starvation) and from revocation kicks.
func TestUnregisterClient_GuardsAgainstStaleTeardown(t *testing.T) {
	s := newTestServer(t)

	stale := testClientFor("alice", "dev_race")
	live := testClientFor("alice", "dev_race") // same device_id — the reconnect race

	// Session 1 registers, then session 2 replaces the route (exactly what
	// registration's map write does on a reconnect with the same device_id).
	s.mu.Lock()
	s.clients["dev_race"] = stale.Client
	s.clients["dev_race"] = live.Client
	s.mu.Unlock()

	// The stale session's teardown must NOT remove the live session's route.
	s.unregisterClient("dev_race", stale.Client)
	s.mu.RLock()
	got := s.clients["dev_race"]
	s.mu.RUnlock()
	if got != live.Client {
		t.Fatal("stale teardown removed the live session's route (the reconnect-race regression)")
	}

	// The owning session's teardown removes it.
	s.unregisterClient("dev_race", live.Client)
	s.mu.RLock()
	_, ok := s.clients["dev_race"]
	s.mu.RUnlock()
	if ok {
		t.Fatal("owner teardown should remove the route")
	}

	// Unregistering an already-absent route is a no-op (session-2-exits-first
	// ordering) — must not panic or recreate an entry.
	s.unregisterClient("dev_race", stale.Client)
	s.mu.RLock()
	n := len(s.clients)
	s.mu.RUnlock()
	if n != 0 {
		t.Fatalf("no-op unregister mutated the map: %d entries", n)
	}
}
