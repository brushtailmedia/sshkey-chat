package server

import (
	"encoding/json"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

func TestProcessPendingAddToRoom_HappyPath(t *testing.T) {
	s := newTestServer(t)
	engineeringID := s.store.RoomDisplayNameToID("engineering")

	// Precondition: bob is not in engineering.
	if s.store.IsRoomMemberByID(engineeringID, "bob") {
		t.Fatal("precondition: bob should not be in engineering")
	}

	// Simulate CLI add: membership first, then queue row.
	if err := s.store.AddRoomMember(engineeringID, "bob", 0); err != nil {
		t.Fatalf("add member: %v", err)
	}
	if err := s.store.RecordPendingAddToRoom("bob", engineeringID, "os:1000"); err != nil {
		t.Fatalf("enqueue: %v", err)
	}

	// Seed an existing epoch for the active room; bob deliberately has
	// no wrapped key for this epoch (the bug case).
	if err := s.store.StoreEpochKey(engineeringID, 1, "alice", "wk_e1_alice"); err != nil {
		t.Fatalf("seed epoch key: %v", err)
	}
	s.epochs.getOrCreate(engineeringID, 1)

	// Keep only alice online so rotation trigger target is deterministic.
	alice := testClientFor("alice", "dev_alice_join")
	s.mu.Lock()
	s.clients["dev_alice_join"] = alice.Client
	s.mu.Unlock()

	s.processPendingAddToRoom()

	// Queue drained.
	pending, err := s.store.ConsumePendingAddToRooms()
	if err != nil {
		t.Fatalf("consume queue: %v", err)
	}
	if len(pending) != 0 {
		t.Fatalf("expected empty queue, got %d rows", len(pending))
	}

	// Alice should get both room_event(join) and epoch_trigger.
	msgs := alice.messages()
	if len(msgs) < 2 {
		t.Fatalf("expected at least 2 messages, got %d", len(msgs))
	}
	var sawJoin, sawTrigger bool
	var trigger protocol.EpochTrigger
	for _, raw := range msgs {
		var envelope struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil {
			t.Fatalf("parse envelope: %v", err)
		}
		switch envelope.Type {
		case "room_event":
			var ev protocol.RoomEvent
			if err := json.Unmarshal(raw, &ev); err != nil {
				t.Fatalf("parse room_event: %v", err)
			}
			if ev.Event == "join" && ev.User == "bob" && ev.Room == engineeringID {
				sawJoin = true
			}
		case "epoch_trigger":
			if err := json.Unmarshal(raw, &trigger); err != nil {
				t.Fatalf("parse epoch_trigger: %v", err)
			}
			sawTrigger = true
		}
	}
	if !sawJoin {
		t.Fatal("expected room_event join broadcast")
	}
	if !sawTrigger {
		t.Fatal("expected epoch_trigger")
	}

	// Complete rotation and verify bob gets a wrapped key in new epoch.
	wrapped := map[string]string{}
	for _, m := range trigger.Members {
		wrapped[m.User] = "wk_" + m.User
	}
	rotate := protocol.EpochRotate{
		Type:        "epoch_rotate",
		Room:        trigger.Room,
		Epoch:       trigger.NewEpoch,
		WrappedKeys: wrapped,
	}
	rotateRaw, _ := json.Marshal(rotate)
	s.handleEpochRotate(alice.Client, rotateRaw)

	got, err := s.store.GetEpochKey(engineeringID, trigger.NewEpoch, "bob")
	if err != nil {
		t.Fatalf("get epoch key for bob: %v", err)
	}
	if got != "wk_bob" {
		t.Fatalf("bob wrapped key = %q, want wk_bob", got)
	}
}

func TestTriggerPostConnectRoomRotations_MissingMemberKey(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")
	engineeringID := s.store.RoomDisplayNameToID("engineering")

	// Keep bob's existing "general" membership from triggering the
	// initial-epoch path so this test isolates missing_member_key on
	// engineering.
	if err := s.store.StoreEpochKey(generalID, 2, "bob", "wk_g2_bob"); err != nil {
		t.Fatalf("seed general epoch key: %v", err)
	}

	// Active room with existing epoch/key for alice only.
	if err := s.store.StoreEpochKey(engineeringID, 3, "alice", "wk_e3_alice"); err != nil {
		t.Fatalf("seed epoch key: %v", err)
	}
	s.epochs.getOrCreate(engineeringID, 3)

	// Simulate add-to-room having already committed membership.
	if err := s.store.AddRoomMember(engineeringID, "bob", 0); err != nil {
		t.Fatalf("add member: %v", err)
	}

	bob := testClientFor("bob", "dev_bob_join")
	s.triggerPostConnectRoomRotations(bob.Client)

	msgs := bob.messages()
	if len(msgs) == 0 {
		t.Fatal("expected epoch_trigger for missing_member_key path")
	}

	var trigger protocol.EpochTrigger
	found := false
	for _, raw := range msgs {
		var env struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &env); err != nil {
			t.Fatalf("parse envelope: %v", err)
		}
		if env.Type == "epoch_trigger" {
			if err := json.Unmarshal(raw, &trigger); err != nil {
				t.Fatalf("parse epoch_trigger: %v", err)
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected epoch_trigger in post-connect rotation checks")
	}
	if trigger.Room != engineeringID {
		t.Fatalf("trigger room = %q, want %q", trigger.Room, engineeringID)
	}
}
