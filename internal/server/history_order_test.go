package server

import (
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// S3 (history-state-model.md): handleHistory emits the history_result wire batch
// oldest-first (server history helpers now reverse at the store boundary), and a
// limited page returns the rows ADJACENT to the cursor — the far-end trim that
// pairs with oldest-first helpers (the +1 lookahead row is the oldest element).

func eqIDs(a, b []string) bool {
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

func lastHistoryResult(t *testing.T, cc *captureClient) protocol.HistoryResult {
	t.Helper()
	var hr protocol.HistoryResult
	found := false
	for _, m := range cc.messages() {
		var probe struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(m, &probe) == nil && probe.Type == "history_result" {
			if err := json.Unmarshal(m, &hr); err != nil {
				t.Fatalf("decode history_result: %v", err)
			}
			found = true
		}
	}
	if !found {
		t.Fatalf("no history_result frame in %d captured frames", len(cc.messages()))
	}
	return hr
}

func historyWireIDs(t *testing.T, hr protocol.HistoryResult) []string {
	t.Helper()
	ids := make([]string, 0, len(hr.Messages))
	for _, raw := range hr.Messages {
		var m protocol.Message
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("decode wire message: %v", err)
		}
		ids = append(ids, m.ID)
	}
	return ids
}

func TestHandleHistory_RoomOldestFirstWireAndAdjacentTrim(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	// first_epoch=0 so the epoch filter is skipped. joined_at defaults to now, so
	// use far-future timestamps that survive the first_seen (m.TS < joined_at)
	// filter — the test cares about server_order ordering, not TS semantics.
	if err := s.store.AddRoomMember(generalID, "alice", 0); err != nil {
		t.Fatalf("add member: %v", err)
	}
	const baseTS = int64(4000000000) // year ~2096, always > joined_at
	for i, id := range []string{"m1", "m2", "m3", "m4", "m5"} {
		if _, err := s.store.InsertRoomMessage(generalID, store.StoredMessage{ID: id, Sender: "alice", TS: baseTS + int64(i), Payload: "p"}); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}

	// Full page before m5: oldest-first wire [m1 m2 m3 m4], has_more=false.
	full := testClientFor("alice", "dev_alice_hist_full")
	raw, _ := json.Marshal(protocol.History{Type: "history", Room: generalID, Before: "m5", Limit: 10})
	s.handleHistory(full.Client, raw)
	hr := lastHistoryResult(t, full)
	if got := historyWireIDs(t, hr); !eqIDs(got, []string{"m1", "m2", "m3", "m4"}) {
		t.Fatalf("full wire order = %v, want [m1 m2 m3 m4] (oldest-first)", got)
	}
	if hr.HasMore {
		t.Error("full page has_more = true, want false")
	}

	// Limited page (limit=2) before m5: the adjacent page, oldest-first [m3 m4],
	// has_more=true. Locks the far-end trim — with oldest-first helpers the +1
	// lookahead is dropped from the FRONT, so the page stays adjacent to the
	// cursor rather than collapsing to the oldest rows [m1 m2].
	paged := testClientFor("alice", "dev_alice_hist_paged")
	raw2, _ := json.Marshal(protocol.History{Type: "history", Room: generalID, Before: "m5", Limit: 2})
	s.handleHistory(paged.Client, raw2)
	hr2 := lastHistoryResult(t, paged)
	if got := historyWireIDs(t, hr2); !eqIDs(got, []string{"m3", "m4"}) {
		t.Fatalf("paged wire order = %v, want [m3 m4] (adjacent page, oldest-first)", got)
	}
	if !hr2.HasMore {
		t.Error("paged has_more = false, want true (m1/m2 remain below the page)")
	}
}

// firstHistoryError returns the first protocol.Error frame from a captureClient.
func firstHistoryError(t *testing.T, cc *captureClient) protocol.Error {
	t.Helper()
	for _, m := range cc.messages() {
		var probe struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(m, &probe) == nil && probe.Type == "error" {
			var e protocol.Error
			if err := json.Unmarshal(m, &e); err != nil {
				t.Fatalf("decode error frame: %v", err)
			}
			return e
		}
	}
	t.Fatalf("no error frame in %d captured frames", len(cc.messages()))
	return protocol.Error{}
}

// S4: an accepted history request whose `before` cursor does not resolve to a
// visible row is rejected with a correlated invalid_cursor (Category C),
// rather than silently returning an empty page (the old behavior). The corr_id
// is echoed so the term client drains it through the generic history abort path.
func TestHandleHistory_InvalidCursorIsCorrelated(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	if err := s.store.AddRoomMember(generalID, "alice", 0); err != nil {
		t.Fatalf("add member: %v", err)
	}
	const baseTS = int64(4000000000)
	for i, id := range []string{"m1", "m2"} {
		if _, err := s.store.InsertRoomMessage(generalID, store.StoredMessage{ID: id, Sender: "alice", TS: baseTS + int64(i), Payload: "p"}); err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}

	// corr_id must be exactly corr_ + 21 nanoid chars (protocol.ValidateCorrID).
	cases := []struct {
		name, before, corrID string
	}{
		{"empty before", "", "corr_AAAAAAAAAAAAAAAAAAAAA"},
		{"unknown before", "msg_does_not_exist", "corr_BBBBBBBBBBBBBBBBBBBBB"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cc := testClientFor("alice", "dev_alice_badcursor_"+tc.name)
			raw, _ := json.Marshal(protocol.History{Type: "history", Room: generalID, Before: tc.before, Limit: 10, CorrID: tc.corrID})
			s.handleHistory(cc.Client, raw)

			e := firstHistoryError(t, cc)
			if e.Code != protocol.CodeInvalidCursor {
				t.Errorf("code = %q, want %q", e.Code, protocol.CodeInvalidCursor)
			}
			if e.CorrID != tc.corrID {
				t.Errorf("corr_id = %q, want %q (echoed for correlation)", e.CorrID, tc.corrID)
			}
		})
	}
}
