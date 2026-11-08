package server

// server_hello limits and the per-room typing flag: the server tells a
// client its size rules, completely and on every connection, instead of
// the client hard-coding them.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
)

func TestServerLimits_FollowsLiveConfigAndFallback(t *testing.T) {
	s := newTestServer(t)

	got := s.serverLimits()
	want := protocol.ServerLimits{
		MaxGroupMembers:      config.DefaultMaxGroupMembers,
		RoomTypingMaxMembers: config.DefaultRoomTypingMaxMembers,
		MaxBodyBytes:         maxPayloadBytes,
		WrappedKeyEntryBytes: protocol.WrappedKeyEntryBytes,
		MaxFileIDsPerMessage: 20,
	}
	if got != want {
		t.Errorf("default limits = %+v, want %+v", got, want)
	}
	if got.MaxBodyBytes != 16384 || got.WrappedKeyEntryBytes != 160 || got.MaxGroupMembers != 100 || got.RoomTypingMaxMembers != 100 {
		t.Errorf("advertised numbers = %+v, want body 16384, entry 160, group cap 100, typing 100", got)
	}

	// Operator settings are what is advertised.
	s.cfg.Lock()
	s.cfg.Server.Groups.MaxMembers = 7
	s.cfg.Server.Rooms.TypingMaxMembers = 0
	s.cfg.Server.Files.MaxFileIDsPerMessage = 3
	s.cfg.Unlock()
	got = s.serverLimits()
	if got.MaxGroupMembers != 7 || got.RoomTypingMaxMembers != 0 || got.MaxFileIDsPerMessage != 3 {
		t.Errorf("configured limits = %+v, want group 7, typing 0, file ids 3", got)
	}

	// A non-positive group cap in the config advertises the default the
	// handlers use (a config default, not a client fallback).
	s.cfg.Lock()
	s.cfg.Server.Groups.MaxMembers = 0
	s.cfg.Unlock()
	if got := s.serverLimits().MaxGroupMembers; got != config.DefaultMaxGroupMembers {
		t.Errorf("MaxGroupMembers with max_members=0 = %d, want %d", got, config.DefaultMaxGroupMembers)
	}
	if got := s.groupMaxMembers(); got != config.DefaultMaxGroupMembers {
		t.Errorf("groupMaxMembers() with max_members=0 = %d, want %d", got, config.DefaultMaxGroupMembers)
	}
}

func TestServerHello_LimitsWireShape(t *testing.T) {
	s := newTestServer(t)
	raw, err := json.Marshal(protocol.ServerHello{
		Type: "server_hello", Protocol: "sshkey-chat", Version: 1, ServerID: "127.0.0.1",
		Limits: s.serverLimits(),
	})
	if err != nil {
		t.Fatal(err)
	}
	const wantLimits = `"limits":{"max_group_members":100,"room_typing_max_members":100,"max_body_bytes":16384,"wrapped_key_entry_bytes":160,"max_file_ids_per_message":20}`
	if !strings.Contains(string(raw), wantLimits) {
		t.Errorf("server_hello = %s\nwant it to contain %s", raw, wantLimits)
	}

	// Typing 0 is "off": the field is present with its zero, like every
	// other field — the block is always complete.
	s.cfg.Lock()
	s.cfg.Server.Rooms.TypingMaxMembers = 0
	s.cfg.Unlock()
	raw, _ = json.Marshal(protocol.ServerHello{Type: "server_hello", Limits: s.serverLimits()})
	if !strings.Contains(string(raw), `"room_typing_max_members":0`) {
		t.Errorf("room_typing_max_members must be present when zero, got %s", raw)
	}

	// No field is ever omitted: a hello carries the whole block.
	for _, key := range []string{"max_group_members", "room_typing_max_members", "max_body_bytes", "wrapped_key_entry_bytes", "max_file_ids_per_message"} {
		if !strings.Contains(string(raw), `"`+key+`":`) {
			t.Errorf("limits must always carry %s, got %s", key, raw)
		}
	}
}

func roomTypingFlag(t *testing.T, s *Server, cc *captureClient, roomID string) bool {
	t.Helper()
	cc.buf.Reset()
	s.sendRoomList(cc.Client)
	msgs := cc.messages()
	if len(msgs) != 1 {
		t.Fatalf("sendRoomList produced %d frame(s), want 1", len(msgs))
	}
	var list protocol.RoomList
	if err := json.Unmarshal(msgs[0], &list); err != nil {
		t.Fatalf("parse room_list: %v", err)
	}
	for _, r := range list.Rooms {
		if r.ID == roomID {
			return r.Typing
		}
	}
	t.Fatalf("room %s not in room_list", roomID)
	return false
}

func TestSendRoomList_TypingFlagFollowsThreshold(t *testing.T) {
	s := newTestServer(t)
	genID := s.store.RoomDisplayNameToID("general") // alice, bob, carol
	alice := testClientFor("alice", "dev_alice_roomlist_typing")

	if !roomTypingFlag(t, s, alice, genID) {
		t.Error("3-member room: typing = false, want true")
	}
	fillRoom(t, s, genID, 100)
	if !roomTypingFlag(t, s, alice, genID) {
		t.Error("100-member room: typing = false, want true (at the limit)")
	}
	fillRoom(t, s, genID, 101)
	if roomTypingFlag(t, s, alice, genID) {
		t.Error("101-member room: typing = true, want false")
	}
	setRoomTypingMax(s, 101)
	if !roomTypingFlag(t, s, alice, genID) {
		t.Error("101-member room with limit 101: typing = false, want true")
	}
	setRoomTypingMax(s, 0)
	if roomTypingFlag(t, s, alice, genID) {
		t.Error("limit 0: typing = true, want false")
	}

	// The wire key is present either way (a bool, never omitted).
	alice.buf.Reset()
	s.sendRoomList(alice.Client)
	if raw := alice.messages()[0]; !strings.Contains(string(raw), `"typing":false`) {
		t.Errorf("room_list must carry an explicit typing flag, got %s", raw)
	}
}
