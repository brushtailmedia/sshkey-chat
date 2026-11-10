package server

import (
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
	"github.com/brushtailmedia/sshkey-chat/internal/testutil"
)

// S1 (server_order, history-state-model.md step 8): the sync/history emission
// builders carry server_order on every server-originated envelope shape — room
// message, group message, 1:1 DM message, and the deleted tombstone for room,
// group, and DM — so a client can page by the server's committed order.
func TestStoredToRaw_CarriesServerOrder(t *testing.T) {
	// Room message + room tombstone.
	roomRaw := storedToRawMessages([]store.StoredMessage{
		{ID: testutil.MsgID("m1"), ServerOrder: 7, Sender: testutil.UserID("alice"), TS: 1, Payload: "p"},
		{ID: testutil.MsgID("m2"), ServerOrder: 8, Sender: testutil.UserID("bob"), TS: 2, Deleted: true},
	}, testutil.RoomID("x"), "")
	var rm protocol.Message
	if err := json.Unmarshal(roomRaw[0], &rm); err != nil {
		t.Fatalf("unmarshal room message: %v", err)
	}
	if rm.ServerOrder != 7 {
		t.Errorf("room message server_order = %d, want 7", rm.ServerOrder)
	}
	var rtomb protocol.Deleted
	if err := json.Unmarshal(roomRaw[1], &rtomb); err != nil {
		t.Fatalf("unmarshal room tombstone: %v", err)
	}
	if rtomb.ServerOrder != 8 {
		t.Errorf("room tombstone server_order = %d, want 8 (preserved)", rtomb.ServerOrder)
	}

	// Group message.
	grpRaw := storedToRawMessages([]store.StoredMessage{
		{ID: testutil.MsgID("g1"), ServerOrder: 9, Sender: testutil.UserID("alice"), TS: 1, Payload: "p"},
	}, "", testutil.GroupID("x"))
	var gm protocol.GroupMessage
	if err := json.Unmarshal(grpRaw[0], &gm); err != nil {
		t.Fatalf("unmarshal group message: %v", err)
	}
	if gm.ServerOrder != 9 {
		t.Errorf("group message server_order = %d, want 9", gm.ServerOrder)
	}

	// DM message + DM tombstone.
	dmRaw := storedToRawDMMessages([]store.StoredMessage{
		{ID: testutil.MsgID("d1"), ServerOrder: 10, Sender: testutil.UserID("alice"), TS: 1, Payload: "p"},
		{ID: testutil.MsgID("d2"), ServerOrder: 11, Sender: testutil.UserID("bob"), TS: 2, Deleted: true},
	}, testutil.DMID("x"))
	var dm protocol.DM
	if err := json.Unmarshal(dmRaw[0], &dm); err != nil {
		t.Fatalf("unmarshal dm: %v", err)
	}
	if dm.ServerOrder != 10 {
		t.Errorf("dm server_order = %d, want 10", dm.ServerOrder)
	}
	var dtomb protocol.Deleted
	if err := json.Unmarshal(dmRaw[1], &dtomb); err != nil {
		t.Fatalf("unmarshal dm tombstone: %v", err)
	}
	if dtomb.ServerOrder != 11 {
		t.Errorf("dm tombstone server_order = %d, want 11 (preserved)", dtomb.ServerOrder)
	}
}

func TestHandleDelete_LiveDeletedBroadcastCarriesServerOrder(t *testing.T) {
	requireDeleted := func(t *testing.T, cc *captureClient, msgID string) protocol.Deleted {
		t.Helper()
		for _, raw := range cc.messages() {
			var probe struct {
				Type string `json:"type"`
				ID   string `json:"id"`
			}
			if err := json.Unmarshal(raw, &probe); err != nil {
				t.Fatalf("unmarshal probe: %v", err)
			}
			if probe.Type != "deleted" || probe.ID != msgID {
				continue
			}
			var d protocol.Deleted
			if err := json.Unmarshal(raw, &d); err != nil {
				t.Fatalf("unmarshal deleted: %v", err)
			}
			return d
		}
		t.Fatalf("missing deleted broadcast for %s; got %d frame(s)", msgID, len(cc.messages()))
		return protocol.Deleted{}
	}

	register := func(s *Server, cc *captureClient) {
		s.mu.Lock()
		s.clients[cc.DeviceID] = cc.Client
		s.mu.Unlock()
	}

	t.Run("room", func(t *testing.T) {
		s := newTestServer(t)
		generalID := s.store.RoomDisplayNameToID("general")
		priv := seedKeyedUser(t, s, testutil.UserID("dave"), "Dave", false, []string{"general"})
		order, err := s.store.InsertRoomMessage(generalID, store.StoredMessage{
			ID: testutil.MsgID("live_room_order"), Sender: testutil.UserID("dave"), TS: 100, Epoch: 1, Payload: "p", Signature: "s",
		})
		if err != nil {
			t.Fatalf("insert room message: %v", err)
		}
		dave := testClientFor(testutil.UserID("dave"), "dev_dave_live_room_delete")
		register(s, dave)

		req := signedDelete("room", generalID, testutil.MsgID("live_room_order"), priv)
		raw, _ := json.Marshal(req)
		s.handleDelete(dave.Client, raw)

		deleted := requireDeleted(t, dave, testutil.MsgID("live_room_order"))
		if deleted.Room != generalID {
			t.Errorf("deleted room = %q, want %q", deleted.Room, generalID)
		}
		if deleted.ServerOrder != order {
			t.Errorf("live room deleted server_order = %d, want %d", deleted.ServerOrder, order)
		}
		if deleted.Signature != req.Signature {
			t.Errorf("live room deleted signature = %q, want forwarded %q", deleted.Signature, req.Signature)
		}
	})

	t.Run("group", func(t *testing.T) {
		s := newTestServer(t)
		priv := seedKeyedUser(t, s, testutil.UserID("dave"), "Dave", false, nil)
		groupID := store.GenerateID("group_")
		if err := s.store.CreateGroup(groupID, testutil.UserID("dave"), []string{testutil.UserID("dave"), testutil.UserID("bob")}, "Test"); err != nil {
			t.Fatalf("create group: %v", err)
		}
		order, err := s.store.InsertGroupMessage(groupID, store.StoredMessage{
			ID:          testutil.MsgID("live_group_order"),
			Sender:      testutil.UserID("dave"),
			TS:          100,
			Payload:     "p",
			Signature:   "s",
			WrappedKeys: map[string]string{testutil.UserID("dave"): testutil.WrappedKey("wa"), testutil.UserID("bob"): testutil.WrappedKey("wb")},
		})
		if err != nil {
			t.Fatalf("insert group message: %v", err)
		}
		dave := testClientFor(testutil.UserID("dave"), "dev_dave_live_group_delete")
		register(s, dave)

		req := signedDelete("group", groupID, testutil.MsgID("live_group_order"), priv)
		raw, _ := json.Marshal(req)
		s.handleDelete(dave.Client, raw)

		deleted := requireDeleted(t, dave, testutil.MsgID("live_group_order"))
		if deleted.Group != groupID {
			t.Errorf("deleted group = %q, want %q", deleted.Group, groupID)
		}
		if deleted.ServerOrder != order {
			t.Errorf("live group deleted server_order = %d, want %d", deleted.ServerOrder, order)
		}
		if deleted.Signature != req.Signature {
			t.Errorf("live group deleted signature = %q, want forwarded %q", deleted.Signature, req.Signature)
		}
	})

	t.Run("dm", func(t *testing.T) {
		s := newTestServer(t)
		priv := seedKeyedUser(t, s, testutil.UserID("dave"), "Dave", false, nil)
		dm, err := s.store.CreateOrGetDirectMessage(store.GenerateID("dm_"), testutil.UserID("dave"), testutil.UserID("bob"))
		if err != nil {
			t.Fatalf("create dm: %v", err)
		}
		order, err := s.store.InsertDMMessage(dm.ID, store.StoredMessage{
			ID:          testutil.MsgID("live_dm_order"),
			Sender:      testutil.UserID("dave"),
			TS:          100,
			Payload:     "p",
			Signature:   "s",
			WrappedKeys: map[string]string{testutil.UserID("dave"): testutil.WrappedKey("wa"), testutil.UserID("bob"): testutil.WrappedKey("wb")},
		})
		if err != nil {
			t.Fatalf("insert dm message: %v", err)
		}
		dave := testClientFor(testutil.UserID("dave"), "dev_dave_live_dm_delete")
		register(s, dave)

		req := signedDelete("dm", dm.ID, testutil.MsgID("live_dm_order"), priv)
		raw, _ := json.Marshal(req)
		s.handleDelete(dave.Client, raw)

		deleted := requireDeleted(t, dave, testutil.MsgID("live_dm_order"))
		if deleted.DM != dm.ID {
			t.Errorf("deleted dm = %q, want %q", deleted.DM, dm.ID)
		}
		if deleted.ServerOrder != order {
			t.Errorf("live dm deleted server_order = %d, want %d", deleted.ServerOrder, order)
		}
		if deleted.Signature != req.Signature {
			t.Errorf("live dm deleted signature = %q, want forwarded %q", deleted.Signature, req.Signature)
		}
	})
}
