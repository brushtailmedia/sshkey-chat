package server

import (
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
	"github.com/brushtailmedia/sshkey-chat/internal/testutil"
)

// syncBatchMessageIDs collects the ids of every message/tombstone in the
// sync_batch frame(s) a captureClient received.
func syncBatchMessageIDs(t *testing.T, cc *captureClient) map[string]bool {
	t.Helper()
	ids := map[string]bool{}
	found := false
	for _, m := range cc.messages() {
		var probe struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(m, &probe) != nil || probe.Type != "sync_batch" {
			continue
		}
		found = true
		var batch protocol.SyncBatch
		if err := json.Unmarshal(m, &batch); err != nil {
			t.Fatalf("decode sync_batch: %v", err)
		}
		for _, raw := range batch.Messages {
			var inner struct {
				ID string `json:"id"`
			}
			if json.Unmarshal(raw, &inner) == nil && inner.ID != "" {
				ids[inner.ID] = true
			}
		}
	}
	if !found {
		t.Fatalf("no sync_batch frame in %d captured frames", len(cc.messages()))
	}
	return ids
}

// A deleted tombstone must obey the same first_epoch visibility gate as a live
// message in the sync (reconnect-catchup) path — not just the history path
// (history-state-model.md S4). A tombstone's existence is itself information, so
// a pre-membership tombstone must never appear in a member's sync_batch. Before
// the fix, sync exempted deleted rows from the epoch gate (`|| m.Deleted`),
// leaking that a pre-first_epoch message had existed.
func TestSyncRoom_TombstoneObeysEpochGate(t *testing.T) {
	s := newTestServer(t)
	// newTestServer seeds bob into general only, and AddRoomMember is INSERT OR
	// IGNORE — so adding bob to engineering here is a *fresh* membership and the
	// first_epoch=2 takes effect (vs a no-op on an existing membership).
	roomID := s.store.RoomDisplayNameToID("engineering")
	if roomID == "" {
		t.Fatal("engineering room not seeded")
	}
	// first_epoch=2 → messages from epoch < 2 are pre-membership for bob.
	// joined_at defaults to now, so use far-future timestamps that clear the
	// first_seen (ts) gate; this isolates the epoch gate.
	if err := s.store.AddRoomMember(roomID, testutil.UserID("bob"), 2); err != nil {
		t.Fatalf("add member: %v", err)
	}
	const baseTS = int64(4000000000)
	s.store.InsertRoomMessage(roomID, store.StoredMessage{ID: testutil.MsgID("m1"), Sender: testutil.UserID("alice"), TS: baseTS, Epoch: 1, Payload: "p"})     // pre-epoch live
	s.store.InsertRoomMessage(roomID, store.StoredMessage{ID: testutil.MsgID("m2"), Sender: testutil.UserID("alice"), TS: baseTS + 1, Epoch: 1, Payload: "p"}) // pre-epoch (to be deleted)
	s.store.InsertRoomMessage(roomID, store.StoredMessage{ID: testutil.MsgID("m3"), Sender: testutil.UserID("alice"), TS: baseTS + 2, Epoch: 2, Payload: "p"}) // visible
	if _, err := s.store.DeleteRoomMessage(roomID, testutil.MsgID("m2"), testutil.UserID("alice")); err != nil {
		t.Fatalf("delete m2: %v", err)
	}

	cc := testClientFor(testutil.UserID("bob"), "dev_bob_sync_tomb")
	s.syncRoom(cc.Client, roomID, 0, 100)

	ids := syncBatchMessageIDs(t, cc)
	if !ids[testutil.MsgID("m3")] {
		t.Errorf("m3 (epoch >= first_epoch) should be in the sync batch; got %v", ids)
	}
	if ids[testutil.MsgID("m1")] {
		t.Error("m1 (pre-first_epoch live) must not be in the sync batch")
	}
	if ids[testutil.MsgID("m2")] {
		t.Error("m2 (pre-first_epoch tombstone) must not leak into the sync batch — its existence is information")
	}
}
