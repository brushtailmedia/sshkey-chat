package server

import (
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// Pinned-message envelopes must carry server_order like the live / sync /
// history shapes, so every hydrated message has the same ordering metadata
// (history-state-model.md step 8). Before the fix, sendPins hydrated the pinned
// protocol.Message without server_order.
func TestSendPins_MessageDataCarriesServerOrder(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general") // alice is a member (first_epoch=0)

	// Far-future ts so the pin clears alice's first_seen (joined_at) gate in
	// sendPins; first_epoch is 0 so the epoch gate is a no-op.
	const ts = int64(4000000000)
	order, err := s.store.InsertRoomMessage(generalID, store.StoredMessage{ID: "pm1", Sender: "alice", TS: ts, Epoch: 1, Payload: "p"})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}
	if order <= 0 {
		t.Fatalf("insert returned non-positive server_order %d", order)
	}
	db, err := s.store.RoomDB(generalID)
	if err != nil {
		t.Fatalf("roomdb: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO pins (message_id, pinned_by, ts) VALUES (?, ?, ?)`, "pm1", "alice", ts); err != nil {
		t.Fatalf("pin: %v", err)
	}

	cc := testClientFor("alice", "dev_alice_pins")
	s.sendPins(cc.Client)

	found := false
	for _, m := range cc.messages() {
		var probe struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(m, &probe) != nil || probe.Type != "pins" {
			continue
		}
		var pins protocol.Pins
		if err := json.Unmarshal(m, &pins); err != nil {
			t.Fatalf("decode pins: %v", err)
		}
		for _, raw := range pins.MessageData {
			var msg protocol.Message
			if json.Unmarshal(raw, &msg) == nil && msg.ID == "pm1" {
				found = true
				if msg.ServerOrder != order {
					t.Errorf("pinned message_data server_order = %d, want %d (committed order)", msg.ServerOrder, order)
				}
			}
		}
	}
	if !found {
		t.Fatalf("pinned message pm1 not found in any pins frame (%d frames captured)", len(cc.messages()))
	}
}
