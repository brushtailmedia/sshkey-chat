package server

// Group frame budget. A group frame carries one wrapped key per member on
// top of the body, so the 16 KB rule is applied to the parsed `payload`
// while the raw frame is allowed maxPayloadBytes + WrappedKeyEntryBytes ×
// max_members. Before this, the bare 16 KB frame check left a 100-member
// group about 400 characters of body — unseen because every fixture carried
// a four-character dummy key.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
	"github.com/brushtailmedia/sshkey-chat/internal/testutil"
)

// capGroup creates a group at the default member cap with alice in it and
// returns its ID and a wrapped_keys map of real-size entries, one per
// member, keyed by production-shape user IDs.
func capGroup(t *testing.T, s *Server) (string, map[string]string) {
	t.Helper()
	members := append([]string{"alice"}, syntheticUserIDs("cap", s.groupMaxMembers()-1)...)
	groupID := store.GenerateID("group_")
	if err := s.store.CreateGroup(groupID, "alice", members, "At cap"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	wk := make(map[string]string, len(members))
	for _, m := range members {
		wk[m] = testutil.WrappedKey(m)
	}
	return groupID, wk
}

func errorCodes(msgs []json.RawMessage) []string {
	var codes []string
	for _, m := range msgs {
		var e protocol.Error
		if json.Unmarshal(m, &e) == nil && e.Type == "error" {
			codes = append(codes, e.Code)
		}
	}
	return codes
}

func TestGroupFrameBudget_Arithmetic(t *testing.T) {
	s := newTestServer(t)
	if got, want := s.groupFrameBudget(), maxPayloadBytes+protocol.WrappedKeyEntryBytes*100; got != want {
		t.Errorf("groupFrameBudget() = %d, want %d", got, want)
	}
	if got := s.groupFrameBudget(); got != 32384 {
		t.Errorf("groupFrameBudget() at the defaults = %d, want 32384 (16384 + 160 x 100)", got)
	}
	// Documented entry size: a 124-character wrap plus a 25-character key
	// and JSON punctuation fits the per-entry allowance.
	entry := len(`"usr_` + strings.Repeat("x", 21) + `":"` + testutil.WrappedKey("x") + `",`)
	if entry > protocol.WrappedKeyEntryBytes {
		t.Errorf("a real entry is %d bytes, over the %d allowance", entry, protocol.WrappedKeyEntryBytes)
	}
	if len(testutil.WrappedKey("x")) != testutil.WrappedKeyChars {
		t.Errorf("WrappedKey length = %d, want %d", len(testutil.WrappedKey("x")), testutil.WrappedKeyChars)
	}
}

func TestHandleSendGroup_AtCap_OneByteBodyAccepted(t *testing.T) {
	s := newTestServer(t)
	groupID, wk := capGroup(t, s)
	alice := testClientFor("alice", "dev_alice_fb_small")

	raw, _ := json.Marshal(protocol.SendGroup{Type: "send_group", Group: groupID, WrappedKeys: wk, Payload: "a", Signature: "s"})
	s.handleSendGroup(alice.Client, raw)

	if codes := errorCodes(alice.messages()); len(codes) != 0 {
		t.Fatalf("send to a group at the cap rejected: %v", codes)
	}
	if got := s.counters.Get(counters.SignalOversizedBody, alice.DeviceID); got != 0 {
		t.Errorf("SignalOversizedBody = %d, want 0", got)
	}
}

func TestHandleSendGroup_AtCap_FullBodyAccepted(t *testing.T) {
	s := newTestServer(t)
	groupID, wk := capGroup(t, s)
	alice := testClientFor("alice", "dev_alice_fb_full")

	raw, _ := json.Marshal(protocol.SendGroup{Type: "send_group", Group: groupID, WrappedKeys: wk,
		Payload: strings.Repeat("a", maxPayloadBytes), Signature: "s"})
	// This frame is what the old check refused: well over 16 KB, and only
	// because of the keys.
	if len(raw) <= maxPayloadBytes {
		t.Fatalf("test frame is %d bytes; it must exceed %d for the budget to matter", len(raw), maxPayloadBytes)
	}
	if len(raw) > s.groupFrameBudget() {
		t.Fatalf("test frame is %d bytes, over the %d budget — the allowance is too small for real entries", len(raw), s.groupFrameBudget())
	}
	s.handleSendGroup(alice.Client, raw)

	if codes := errorCodes(alice.messages()); len(codes) != 0 {
		t.Fatalf("16 KB body to a group at the cap rejected: %v", codes)
	}
	if got := s.counters.Get(counters.SignalOversizedBody, alice.DeviceID); got != 0 {
		t.Errorf("SignalOversizedBody = %d, want 0", got)
	}
}

func TestHandleSendGroup_BodyOverLimitRejected(t *testing.T) {
	s := newTestServer(t)
	groupID, wk := capGroup(t, s)
	alice := testClientFor("alice", "dev_alice_fb_over")

	raw, _ := json.Marshal(protocol.SendGroup{Type: "send_group", Group: groupID, WrappedKeys: wk,
		Payload: strings.Repeat("a", maxPayloadBytes+1), Signature: "s"})
	if len(raw) > s.groupFrameBudget() {
		t.Fatalf("test frame is %d bytes, over the budget: this case must reach the body check", len(raw))
	}
	s.handleSendGroup(alice.Client, raw)

	if codes := errorCodes(alice.messages()); len(codes) != 1 || codes[0] != protocol.ErrMessageTooLarge {
		t.Fatalf("16 KB + 1 body: codes = %v, want [%s]", codes, protocol.ErrMessageTooLarge)
	}
	if got := s.counters.Get(counters.SignalOversizedBody, alice.DeviceID); got != 1 {
		t.Errorf("SignalOversizedBody = %d, want 1", got)
	}
}

func TestHandleSendGroup_OverCapKeys_FailOnMemberCapNotFrameSize(t *testing.T) {
	s := newTestServer(t)
	groupID, wk := capGroup(t, s)
	extra := "usr_" + strings.Repeat("z", 21)
	wk[extra] = testutil.WrappedKey(extra) // 101 entries
	alice := testClientFor("alice", "dev_alice_fb_101")

	raw, _ := json.Marshal(protocol.SendGroup{Type: "send_group", Group: groupID, WrappedKeys: wk, Payload: "a", Signature: "s"})
	s.handleSendGroup(alice.Client, raw)

	if codes := errorCodes(alice.messages()); len(codes) != 1 || codes[0] != "wrapped_keys_over_cap" {
		t.Fatalf("101 keys: codes = %v, want [wrapped_keys_over_cap]", codes)
	}
	if got := s.counters.Get(counters.SignalWrappedKeysOverCap, alice.DeviceID); got != 1 {
		t.Errorf("SignalWrappedKeysOverCap = %d, want 1", got)
	}
	if got := s.counters.Get(counters.SignalOversizedBody, alice.DeviceID); got != 0 {
		t.Errorf("SignalOversizedBody = %d, want 0: the member cap, not the frame size, bounds a group", got)
	}
}

func TestHandleSendGroup_FrameOverBudgetRejectedBeforeParse(t *testing.T) {
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_fb_budget")

	// Over the whole budget: a body that would also fail the body check,
	// but the frame check fires first and never parses it. The frame is
	// deliberately unparseable to prove that.
	raw := json.RawMessage(`{"type":"send_group","payload":"` + strings.Repeat("a", s.groupFrameBudget()) + `"`)
	s.handleSendGroup(alice.Client, raw)

	if codes := errorCodes(alice.messages()); len(codes) != 1 || codes[0] != protocol.ErrMessageTooLarge {
		t.Fatalf("over-budget frame: codes = %v, want [%s]", codes, protocol.ErrMessageTooLarge)
	}
	if got := s.counters.Get(counters.SignalOversizedBody, alice.DeviceID); got != 1 {
		t.Errorf("SignalOversizedBody = %d, want 1", got)
	}
	if got := s.counters.Get(counters.SignalMalformedFrame, alice.DeviceID); got != 0 {
		t.Errorf("SignalMalformedFrame = %d, want 0 (rejected before parsing)", got)
	}
}

func TestHandleEditGroup_SameBudget(t *testing.T) {
	s := newTestServer(t)
	groupID, wk := capGroup(t, s)
	alice := testClientFor("alice", "dev_alice_fb_edit")

	// A full 16 KB body with keys for a group at the cap passes the frame
	// and body checks; whatever happens after is not a size rejection.
	raw, _ := json.Marshal(protocol.EditGroup{Type: "edit_group", ID: "msg_none", Group: groupID, WrappedKeys: wk,
		Payload: strings.Repeat("a", maxPayloadBytes), Signature: "s"})
	if len(raw) <= maxPayloadBytes {
		t.Fatalf("test frame is %d bytes; it must exceed %d", len(raw), maxPayloadBytes)
	}
	s.handleEditGroup(alice.Client, raw)
	for _, code := range errorCodes(alice.messages()) {
		if code == protocol.ErrMessageTooLarge {
			t.Fatal("edit_group at the cap with a 16 KB body was rejected as message_too_large")
		}
	}
	if got := s.counters.Get(counters.SignalOversizedBody, alice.DeviceID); got != 0 {
		t.Errorf("SignalOversizedBody = %d, want 0", got)
	}

	// One byte over on the body is refused.
	bob := testClientFor("alice", "dev_alice_fb_edit_over")
	raw, _ = json.Marshal(protocol.EditGroup{Type: "edit_group", ID: "msg_none", Group: groupID, WrappedKeys: wk,
		Payload: strings.Repeat("a", maxPayloadBytes+1), Signature: "s"})
	s.handleEditGroup(bob.Client, raw)
	if codes := errorCodes(bob.messages()); len(codes) != 1 || codes[0] != protocol.ErrMessageTooLarge {
		t.Fatalf("edit_group 16 KB + 1 body: codes = %v, want [%s]", codes, protocol.ErrMessageTooLarge)
	}
}

func TestHandleSendAndSendDM_KeepBareFrameCheck(t *testing.T) {
	// Rooms and 1:1 DMs carry no per-member envelope worth budgeting for
	// (an epoch key, or two entries), so their frame check is still the
	// bare 16 KB.
	s := newTestServer(t)
	alice := testClientFor("alice", "dev_alice_fb_room")
	big := strings.Repeat("a", maxPayloadBytes)
	raw := json.RawMessage(`{"type":"send","payload":"` + big + `"`)
	s.handleSend(alice.Client, raw)
	if codes := errorCodes(alice.messages()); len(codes) != 1 || codes[0] != protocol.ErrMessageTooLarge {
		t.Fatalf("send over 16 KB: codes = %v, want [%s]", codes, protocol.ErrMessageTooLarge)
	}
	bob := testClientFor("alice", "dev_alice_fb_dm")
	raw = json.RawMessage(`{"type":"send_dm","payload":"` + big + `"`)
	s.handleSendDM(bob.Client, raw)
	if codes := errorCodes(bob.messages()); len(codes) != 1 || codes[0] != protocol.ErrMessageTooLarge {
		t.Fatalf("send_dm over 16 KB: codes = %v, want [%s]", codes, protocol.ErrMessageTooLarge)
	}
}
