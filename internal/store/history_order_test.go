package store

import (
	"testing"
)

// History scroll-back helpers (history-state-model.md S3 + S4): page by
// server_order, return oldest-first (S3), and resolve the cursor + apply
// visibility IN SQL before LIMIT so has_more counts visible rows only and a
// cursor outside the visible window is reported as not-OK -> invalid_cursor (S4).

func idsOf(msgs []StoredMessage) []string {
	ids := make([]string, len(msgs))
	for i, m := range msgs {
		ids[i] = m.ID
	}
	return ids
}

func eqStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func newRoomStore(t *testing.T) (*Store, string) {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	s.SeedRooms(map[string]RoomSeed{"general": {Topic: "Chat"}})
	room := s.RoomDisplayNameToID("general")
	if room == "" {
		t.Fatal("room seed failed")
	}
	return s, room
}

// S3 carried forward to the S4 signature: no visibility restriction (firstSeen /
// firstEpoch == 0), oldest-first order, and a limited page returns the rows
// adjacent to the cursor.
func TestGetRoomHistoryBefore_OrderAndAdjacentPage(t *testing.T) {
	s, room := newRoomStore(t)
	for i, id := range []string{"m1", "m2", "m3", "m4", "m5"} {
		if _, err := s.InsertRoomMessage(room, StoredMessage{ID: id, Sender: "alice", TS: int64(100 + i), Payload: "p"}); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}

	// All before m5, generous limit -> oldest-first [m1 m2 m3 m4], cursorOK.
	msgs, hasMore, cursorOK, err := s.GetRoomHistoryBefore(room, "m5", 0, 0, 10)
	if err != nil {
		t.Fatalf("before m5: %v", err)
	}
	if !cursorOK {
		t.Fatal("cursorOK should be true for a resolvable cursor")
	}
	if hasMore {
		t.Error("has_more should be false (m5 has only 4 older rows)")
	}
	if got := idsOf(msgs); !eqStrings(got, []string{"m1", "m2", "m3", "m4"}) {
		t.Fatalf("before m5 = %v, want [m1 m2 m3 m4] (oldest-first)", got)
	}

	// Limited page: the rows adjacent to the cursor, oldest-first [m3 m4], has_more.
	msgs, hasMore, cursorOK, err = s.GetRoomHistoryBefore(room, "m5", 0, 0, 2)
	if err != nil || !cursorOK {
		t.Fatalf("before m5 limit2: err=%v cursorOK=%v", err, cursorOK)
	}
	if !hasMore {
		t.Error("has_more should be true (m1/m2 remain below the page)")
	}
	if got := idsOf(msgs); !eqStrings(got, []string{"m3", "m4"}) {
		t.Fatalf("before m5 limit2 = %v, want [m3 m4] (adjacent page)", got)
	}
}

// S4: an empty, unknown, or out-of-visibility cursor is reported cursorOK=false
// (no error, no rows) so the handler can emit a correlated invalid_cursor.
func TestGetRoomHistoryBefore_InvalidCursor(t *testing.T) {
	s, room := newRoomStore(t)
	// m1 is pre-join (ts 50 < firstSeen 150); m2/m3 are visible.
	s.InsertRoomMessage(room, StoredMessage{ID: "m1", Sender: "a", TS: 50, Payload: "p"})
	s.InsertRoomMessage(room, StoredMessage{ID: "m2", Sender: "a", TS: 200, Payload: "p"})
	s.InsertRoomMessage(room, StoredMessage{ID: "m3", Sender: "a", TS: 300, Payload: "p"})

	cases := []struct {
		name, before string
		firstSeen    int64
	}{
		{"empty cursor", "", 0},
		{"unknown cursor", "does_not_exist", 0},
		{"cursor outside visibility window", "m1", 150}, // m1 is pre-join
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			msgs, hasMore, cursorOK, err := s.GetRoomHistoryBefore(room, tc.before, tc.firstSeen, 0, 10)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if cursorOK {
				t.Errorf("cursorOK = true, want false (-> invalid_cursor)")
			}
			if len(msgs) != 0 || hasMore {
				t.Errorf("invalid cursor should yield no rows / no has_more, got %d msgs hasMore=%v", len(msgs), hasMore)
			}
		})
	}
}

// S4: visibility is applied IN SQL before LIMIT, so invisible rows are excluded
// AND cannot consume the +1 lookahead to make has_more falsely false. The shape
// here is the realistic backfill case: m2 is an older message (low ts) that was
// committed with a higher-than-m1 server_order, so it sits *between* visible rows
// by server_order — exactly what the old in-memory post-filter mishandled.
func TestGetRoomHistoryBefore_VisibilityAndHasMore(t *testing.T) {
	s, room := newRoomStore(t)
	// server_order 1..5 in insert order; ts chosen so m2 is pre-join (invisible).
	s.InsertRoomMessage(room, StoredMessage{ID: "m1", Sender: "a", TS: 200, Payload: "p"}) // visible
	s.InsertRoomMessage(room, StoredMessage{ID: "m2", Sender: "a", TS: 50, Payload: "p"})  // invisible (backfilled-old)
	s.InsertRoomMessage(room, StoredMessage{ID: "m3", Sender: "a", TS: 250, Payload: "p"}) // visible
	s.InsertRoomMessage(room, StoredMessage{ID: "m4", Sender: "a", TS: 300, Payload: "p"}) // visible
	s.InsertRoomMessage(room, StoredMessage{ID: "m5", Sender: "a", TS: 400, Payload: "p"}) // visible (cursor)
	const firstSeen = int64(150)

	// limit=2 before m5: the two newest *visible* rows below m5 are m4, m3, and a
	// third visible row (m1) remains below -> has_more=true. The old post-filter
	// would have fetched [m4,m3,m2], dropped m2, and falsely reported has_more=false.
	msgs, hasMore, cursorOK, err := s.GetRoomHistoryBefore(room, "m5", firstSeen, 0, 2)
	if err != nil || !cursorOK {
		t.Fatalf("before m5: err=%v cursorOK=%v", err, cursorOK)
	}
	if !hasMore {
		t.Error("has_more should be true (visible m1 remains below) — invisible rows must not consume the lookahead")
	}
	if got := idsOf(msgs); !eqStrings(got, []string{"m3", "m4"}) {
		t.Fatalf("page = %v, want [m3 m4] (visible, adjacent, oldest-first)", got)
	}

	// Generous limit: all visible rows below m5, with m2 excluded entirely.
	msgs, hasMore, _, _ = s.GetRoomHistoryBefore(room, "m5", firstSeen, 0, 10)
	if hasMore {
		t.Error("has_more should be false on the full visible page")
	}
	if got := idsOf(msgs); !eqStrings(got, []string{"m1", "m3", "m4"}) {
		t.Fatalf("full visible page = %v, want [m1 m3 m4] (m2 pre-join excluded)", got)
	}
}

// S4: deleted tombstones obey the epoch visibility gate too — a tombstone for a
// pre-epoch message must not leak that a message existed before the caller could
// see the room. (The prior in-memory filter exempted deleted rows from the epoch
// gate; this tightens that.)
func TestGetRoomHistoryBefore_TombstoneObeysEpochGate(t *testing.T) {
	s, room := newRoomStore(t)
	s.InsertRoomMessage(room, StoredMessage{ID: "m1", Sender: "a", TS: 100, Epoch: 1, Payload: "p"})
	s.InsertRoomMessage(room, StoredMessage{ID: "m2", Sender: "a", TS: 200, Epoch: 1, Payload: "p"})
	s.InsertRoomMessage(room, StoredMessage{ID: "m3", Sender: "a", TS: 300, Epoch: 2, Payload: "p"}) // cursor
	if _, err := s.DeleteRoomMessage(room, "m1", "a"); err != nil {
		t.Fatalf("delete m1: %v", err)
	}

	// Positive control: with no epoch restriction, the m1 tombstone is visible.
	msgs, _, cursorOK, err := s.GetRoomHistoryBefore(room, "m3", 0, 0, 10)
	if err != nil || !cursorOK {
		t.Fatalf("no-gate: err=%v cursorOK=%v", err, cursorOK)
	}
	if got := idsOf(msgs); !eqStrings(got, []string{"m1", "m2"}) {
		t.Fatalf("no-gate page = %v, want [m1 m2] (tombstone m1 included)", got)
	}

	// With firstEpoch=2, the epoch-1 rows — including the m1 tombstone — are gated
	// out. The tombstone must not appear.
	msgs, _, cursorOK, err = s.GetRoomHistoryBefore(room, "m3", 0, 2, 10)
	if err != nil || !cursorOK {
		t.Fatalf("gated: err=%v cursorOK=%v", err, cursorOK)
	}
	if len(msgs) != 0 {
		t.Fatalf("gated page = %v, want [] (epoch-1 tombstone must obey the gate)", idsOf(msgs))
	}
}
