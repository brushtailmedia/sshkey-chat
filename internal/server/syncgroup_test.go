package server

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

// Phase 14 post-implementation fix: new-member pre-join history gate.
//
// Before this fix, a user added to an existing group would receive every
// historical message and every historical group_event on their first
// sync_batch. The wrapped-key crypto model prevents them from DECRYPTING
// the messages (no wrapped key for them), but the server was still
// SERVING the rows — leaking timestamps, sender IDs, and audit-trail
// metadata (pre-join /rename, /promote, /demote, /kick events).
//
// The fix wires the existing `group_members.joined_at` column into
// syncGroup (raises sinceTS) and handleHistory's group branch
// (post-query TS filter). These tests lock in the behaviour and also
// cover the positive assertion (post-join data still visible) and the
// re-add reset (leave + rejoin gets a fresh joined_at).

// TestSyncGroup_FiltersPreJoinMessages covers the basic message-filter
// case plus a positive assertion (post-join messages ARE delivered).
// This is the primary regression: add a new member to an existing group
// with old messages and verify they see only messages from their join
// time onward.
func TestSyncGroup_FiltersPreJoinMessages(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("grp_prejoin_msg", "alice", []string{"alice", "bob"}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	// Pre-join messages at TS=100, 200 (year 1970, definitely before any
	// possible joined_at from datetime('now')).
	if err := s.store.InsertGroupMessage("grp_prejoin_msg", store.StoredMessage{
		ID: "m_pre1", Sender: "alice", TS: 100, Payload: "pre1",
	}); err != nil {
		t.Fatalf("insert pre-join msg: %v", err)
	}
	if err := s.store.InsertGroupMessage("grp_prejoin_msg", store.StoredMessage{
		ID: "m_pre2", Sender: "bob", TS: 200, Payload: "pre2",
	}); err != nil {
		t.Fatalf("insert pre-join msg: %v", err)
	}

	// Add charlie — joined_at is set to datetime('now') which is
	// approximately time.Now().Unix() (large number, definitely > 200).
	if err := s.store.AddGroupMember("grp_prejoin_msg", "charlie", false); err != nil {
		t.Fatalf("add member: %v", err)
	}

	// Post-join message at now+3600 (one hour in the future, definitely
	// after charlie's joined_at).
	postTS := time.Now().Unix() + 3600
	if err := s.store.InsertGroupMessage("grp_prejoin_msg", store.StoredMessage{
		ID: "m_post", Sender: "alice", TS: postTS, Payload: "post",
	}); err != nil {
		t.Fatalf("insert post-join msg: %v", err)
	}

	// Charlie syncs with sinceTS=0 (first connect). With the fix,
	// syncGroup raises sinceTS to charlie's joined_at, so only m_post
	// should be returned.
	charlie := testClientFor("charlie", "dev_charlie_1")
	s.syncGroup(charlie.Client, "grp_prejoin_msg", 0, 200)

	msgs := charlie.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected exactly 1 sync_batch for charlie, got %d", len(msgs))
	}

	var batch protocol.SyncBatch
	if err := json.Unmarshal(msgs[0], &batch); err != nil {
		t.Fatalf("parse sync_batch: %v", err)
	}
	if batch.Type != "sync_batch" {
		t.Errorf("type = %q, want sync_batch", batch.Type)
	}

	// Positive assertion: post-join message IS delivered.
	if len(batch.Messages) != 1 {
		t.Fatalf("expected exactly 1 message (post-join only), got %d", len(batch.Messages))
	}
	var gotMsg protocol.GroupMessage
	if err := json.Unmarshal(batch.Messages[0], &gotMsg); err != nil {
		t.Fatalf("parse message: %v", err)
	}
	if gotMsg.ID != "m_post" {
		t.Errorf("got message ID = %q, want m_post (pre-join leak)", gotMsg.ID)
	}
	if gotMsg.TS != postTS {
		t.Errorf("got message TS = %d, want %d", gotMsg.TS, postTS)
	}
}

// TestSyncGroup_FiltersPreJoinEvents verifies that group_events are
// filtered by joined_at alongside messages. Mix pre-join and post-join
// events and assert only post-join events reach the new member. This
// locks in that the single sinceTS raise in syncGroup covers both
// branches (messages + events) of the sync_batch.
func TestSyncGroup_FiltersPreJoinEvents(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("grp_prejoin_evt", "alice", []string{"alice", "bob"}, "Original"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	// Pre-join events: alice renamed the group at TS=150, alice promoted
	// bob at TS=180. Both definitely before any future joined_at.
	if err := s.store.RecordGroupEvent("grp_prejoin_evt", "rename", "alice", "alice", "", "Original", false, 150); err != nil {
		t.Fatalf("record pre-join rename: %v", err)
	}
	if err := s.store.RecordGroupEvent("grp_prejoin_evt", "promote", "bob", "alice", "", "", false, 180); err != nil {
		t.Fatalf("record pre-join promote: %v", err)
	}

	// Add charlie.
	if err := s.store.AddGroupMember("grp_prejoin_evt", "charlie", false); err != nil {
		t.Fatalf("add member: %v", err)
	}

	// Post-join event: alice promotes bob again at now+3600.
	postTS := time.Now().Unix() + 3600
	if err := s.store.RecordGroupEvent("grp_prejoin_evt", "promote", "bob", "alice", "", "", false, postTS); err != nil {
		t.Fatalf("record post-join promote: %v", err)
	}

	charlie := testClientFor("charlie", "dev_charlie_1")
	s.syncGroup(charlie.Client, "grp_prejoin_evt", 0, 200)

	msgs := charlie.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected exactly 1 sync_batch, got %d", len(msgs))
	}

	var batch protocol.SyncBatch
	if err := json.Unmarshal(msgs[0], &batch); err != nil {
		t.Fatalf("parse sync_batch: %v", err)
	}

	// Zero pre-join events, exactly one post-join event.
	if len(batch.Events) != 1 {
		t.Fatalf("expected exactly 1 event (post-join only), got %d", len(batch.Events))
	}
	var gotEvt protocol.GroupEvent
	if err := json.Unmarshal(batch.Events[0], &gotEvt); err != nil {
		t.Fatalf("parse event: %v", err)
	}
	if gotEvt.Event != "promote" {
		t.Errorf("got event = %q, want promote", gotEvt.Event)
	}
	// If the pre-join rename leaked, we'd see a "rename" or extra "promote"
	// event — the count check above catches both.
}

// TestSyncGroup_ReAddResetsJoinedAt verifies that a leaver who is
// re-added gets a fresh joined_at (because AddGroupMember is a DELETE
// then INSERT pattern with DEFAULT datetime('now')), and therefore
// cannot see messages sent during their absence. This covers the
// round-trip invariant: leaving is not a permanent visibility loss but
// re-joining is not a visibility rewind.
func TestSyncGroup_ReAddResetsJoinedAt(t *testing.T) {
	s := newTestServer(t)
	// Create group with alice as admin and charlie as initial member.
	if err := s.store.CreateGroup("grp_readd", "alice", []string{"alice", "charlie"}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	// A message sent while charlie is a member (TS=now+100). Actually we
	// use a past TS here because we want it to predate charlie's SECOND
	// joined_at (the re-add). Using TS=1000 keeps it well before the
	// re-add's datetime('now').
	if err := s.store.InsertGroupMessage("grp_readd", store.StoredMessage{
		ID: "m_during_first_membership", Sender: "alice", TS: 1000, Payload: "during1",
	}); err != nil {
		t.Fatalf("insert msg: %v", err)
	}

	// Charlie leaves (removed from group_members).
	if err := s.store.RemoveGroupMember("grp_readd", "charlie"); err != nil {
		t.Fatalf("remove member: %v", err)
	}

	// A message sent while charlie is absent (TS=2000).
	if err := s.store.InsertGroupMessage("grp_readd", store.StoredMessage{
		ID: "m_while_absent", Sender: "alice", TS: 2000, Payload: "absent",
	}); err != nil {
		t.Fatalf("insert msg: %v", err)
	}

	// Charlie is re-added — gets a FRESH joined_at via datetime('now'),
	// which will be at time.Now() (much greater than 2000).
	if err := s.store.AddGroupMember("grp_readd", "charlie", false); err != nil {
		t.Fatalf("re-add member: %v", err)
	}

	// Post-re-add message.
	postTS := time.Now().Unix() + 3600
	if err := s.store.InsertGroupMessage("grp_readd", store.StoredMessage{
		ID: "m_after_readd", Sender: "alice", TS: postTS, Payload: "post",
	}); err != nil {
		t.Fatalf("insert msg: %v", err)
	}

	// Charlie syncs from scratch.
	charlie := testClientFor("charlie", "dev_charlie_1")
	s.syncGroup(charlie.Client, "grp_readd", 0, 200)

	msgs := charlie.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 sync_batch, got %d", len(msgs))
	}

	var batch protocol.SyncBatch
	if err := json.Unmarshal(msgs[0], &batch); err != nil {
		t.Fatalf("parse sync_batch: %v", err)
	}

	// Charlie should see ONLY m_after_readd — not m_during_first_membership
	// (which is earlier than the re-add joined_at) and definitely not
	// m_while_absent.
	if len(batch.Messages) != 1 {
		var ids []string
		for _, m := range batch.Messages {
			var gm protocol.GroupMessage
			json.Unmarshal(m, &gm)
			ids = append(ids, gm.ID)
		}
		t.Fatalf("expected 1 message (m_after_readd only), got %d: %v", len(batch.Messages), ids)
	}
	var gotMsg protocol.GroupMessage
	if err := json.Unmarshal(batch.Messages[0], &gotMsg); err != nil {
		t.Fatalf("parse message: %v", err)
	}
	if gotMsg.ID != "m_after_readd" {
		t.Errorf("got message ID = %q, want m_after_readd (re-add did not reset joined_at)", gotMsg.ID)
	}
}

// TestHandleHistory_FiltersPreJoinGroupMessages covers the scroll-back
// path. The sync path uses a sinceTS raise; handleHistory uses a
// post-query filter (because GetGroupMessagesBefore is id+limit shaped,
// not timestamp-shaped — `WHERE rowid < (SELECT rowid WHERE id = ?)`).
// Both paths must filter pre-join messages.
//
// Note on test shape: `GetGroupMessagesBefore` returns nothing when
// Before is empty (the subquery resolves to NULL). Clients paginate
// history with a real message ID as the cursor, so the test inserts a
// trailing "cursor" message and passes its ID as req.Before. The cursor
// itself is excluded from the result by the `<` comparison, leaving
// only the earlier messages — which is exactly the set we want to
// verify the filter against.
func TestHandleHistory_FiltersPreJoinGroupMessages(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup("grp_hist", "alice", []string{"alice", "bob"}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	// Two pre-join messages at TS=100, 200 (well before any future
	// joined_at).
	if err := s.store.InsertGroupMessage("grp_hist", store.StoredMessage{
		ID: "h_pre1", Sender: "alice", TS: 100, Payload: "pre1",
	}); err != nil {
		t.Fatalf("insert msg: %v", err)
	}
	if err := s.store.InsertGroupMessage("grp_hist", store.StoredMessage{
		ID: "h_pre2", Sender: "bob", TS: 200, Payload: "pre2",
	}); err != nil {
		t.Fatalf("insert msg: %v", err)
	}

	// Add charlie.
	if err := s.store.AddGroupMember("grp_hist", "charlie", false); err != nil {
		t.Fatalf("add member: %v", err)
	}

	// One post-join message that should survive the filter.
	postTS := time.Now().Unix() + 3600
	if err := s.store.InsertGroupMessage("grp_hist", store.StoredMessage{
		ID: "h_post", Sender: "alice", TS: postTS, Payload: "post",
	}); err != nil {
		t.Fatalf("insert msg: %v", err)
	}

	// Trailing cursor message so we have a non-empty req.Before. This
	// message itself will be excluded from the result (the query is
	// `rowid <` not `<=`).
	cursorTS := postTS + 1
	if err := s.store.InsertGroupMessage("grp_hist", store.StoredMessage{
		ID: "h_cursor", Sender: "alice", TS: cursorTS, Payload: "cursor",
	}); err != nil {
		t.Fatalf("insert msg: %v", err)
	}

	// Charlie requests history with h_cursor as the anchor. Without the
	// filter, he'd get [h_post, h_pre2, h_pre1]. With the filter, only
	// [h_post] (TS >= joined_at).
	charlie := testClientFor("charlie", "dev_charlie_1")
	req := protocol.History{
		Type:   "history",
		Group:  "grp_hist",
		Before: "h_cursor",
		Limit:  100,
	}
	raw, _ := json.Marshal(req)
	s.handleHistory(charlie.Client, raw)

	msgs := charlie.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 history_result, got %d", len(msgs))
	}

	var hr protocol.HistoryResult
	if err := json.Unmarshal(msgs[0], &hr); err != nil {
		t.Fatalf("parse history_result: %v", err)
	}
	if hr.Type != "history_result" {
		t.Errorf("type = %q, want history_result", hr.Type)
	}

	// Only h_post should be visible.
	if len(hr.Messages) != 1 {
		var ids []string
		for _, m := range hr.Messages {
			var gm protocol.GroupMessage
			json.Unmarshal(m, &gm)
			ids = append(ids, gm.ID)
		}
		t.Fatalf("expected 1 message (h_post only), got %d: %v", len(hr.Messages), ids)
	}
	var gotMsg protocol.GroupMessage
	if err := json.Unmarshal(hr.Messages[0], &gotMsg); err != nil {
		t.Fatalf("parse message: %v", err)
	}
	if gotMsg.ID != "h_post" {
		t.Errorf("got message ID = %q, want h_post (pre-join leak via history)", gotMsg.ID)
	}
}

// TestSyncGroup_ExistingMemberSeesAllPostJoin is a negative-regression
// check: a long-standing member syncing from sinceTS=0 should see every
// message in the group (we haven't accidentally over-filtered). This
// catches the "creator's own history got hidden from them" bug that
// would happen if joined_at were interpreted too strictly.
func TestSyncGroup_ExistingMemberSeesAllPostJoin(t *testing.T) {
	s := newTestServer(t)
	// Alice creates the group. Her joined_at is set at creation time.
	if err := s.store.CreateGroup("grp_creator", "alice", []string{"alice"}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}

	// Messages sent AFTER creation (all post-alice-joined_at).
	postTS1 := time.Now().Unix() + 3600
	postTS2 := postTS1 + 1
	if err := s.store.InsertGroupMessage("grp_creator", store.StoredMessage{
		ID: "m_post1", Sender: "alice", TS: postTS1, Payload: "post1",
	}); err != nil {
		t.Fatalf("insert msg: %v", err)
	}
	if err := s.store.InsertGroupMessage("grp_creator", store.StoredMessage{
		ID: "m_post2", Sender: "alice", TS: postTS2, Payload: "post2",
	}); err != nil {
		t.Fatalf("insert msg: %v", err)
	}

	// Alice syncs — should see both of her own messages.
	alice := testClientFor("alice", "dev_alice_1")
	s.syncGroup(alice.Client, "grp_creator", 0, 200)

	msgs := alice.messages()
	if len(msgs) != 1 {
		t.Fatalf("expected 1 sync_batch, got %d", len(msgs))
	}

	var batch protocol.SyncBatch
	if err := json.Unmarshal(msgs[0], &batch); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(batch.Messages) != 2 {
		t.Errorf("expected 2 messages for creator, got %d (over-filter regression)", len(batch.Messages))
	}
}
