package server

// Phase 17 Step 4.f — download authorization tests. Covers:
//
//   - authorizeDownload ACL matrix: member/non-member × room/group/dm.
//   - Forward-secrecy gate for rooms (first_seen <= file.ts).
//   - Forward-secrecy gate for groups (joined_at <= file.ts).
//   - DMs: party check only, no left_at gate (ghost-conversation design —
//     see context_lifecycle_model memory note).
//   - Unknown file_id returns false (caller renders privacy-preserving
//     "not found" byte-identical to "no access").
//
// These tests exercise authorizeDownload directly — no SSH channel
// scaffolding needed. Concurrent-channel / cap / TTL tests require real
// SSH channels and live in a separate test file when implemented.

import (
	"testing"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/store"
	"github.com/brushtailmedia/sshkey-chat/internal/testutil"
)

// aliceFutureTS returns a timestamp guaranteed to be > alice's seeded
// first_seen (which is set to time.Now() when the test server is built).
// Use this for file-context ts in tests that want the forward-secrecy
// gate to PASS. Tests that want the gate to FAIL use a timestamp <
// alice's join time instead (the seed is recent, so any small positive
// constant like 100 works).
func aliceFutureTS() int64 {
	return time.Now().Add(1 * time.Hour).Unix()
}

func TestAuthorizeDownload_RoomMember_PostJoin_Allowed(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	// Alice was seeded into "general" with joined_at = time.Now(). File
	// ts must be > her joined_at for the forward-secrecy gate to pass.
	if err := s.store.InsertFileContext(testutil.FileID("post"), store.FileContextRoom, generalID, aliceFutureTS()); err != nil {
		t.Fatalf("bind file: %v", err)
	}

	if !s.authorizeDownload(testutil.UserID("alice"), testutil.FileID("post")) {
		t.Error("member with first_seen <= file.ts should be allowed")
	}
}

func TestAuthorizeDownload_RoomNonMember_Denied(t *testing.T) {
	s := newTestServer(t)
	engID := s.store.RoomDisplayNameToID("engineering")
	if err := s.store.InsertFileContext(testutil.FileID("eng"), store.FileContextRoom, engID, 100); err != nil {
		t.Fatalf("bind file: %v", err)
	}

	// bob is NOT a member of engineering per the seed.
	if s.authorizeDownload(testutil.UserID("bob"), testutil.FileID("eng")) {
		t.Error("non-member should be denied")
	}
}

func TestAuthorizeDownload_RoomMember_PreJoin_Denied(t *testing.T) {
	s := newTestServer(t)
	generalID := s.store.RoomDisplayNameToID("general")

	// Alice joined at t=500. File uploaded at t=100 (pre-join).
	if err := s.store.AddRoomMember(generalID, testutil.UserID("alice"), 500); err != nil {
		t.Fatalf("re-add alice: %v", err)
	}
	if err := s.store.InsertFileContext(testutil.FileID("prejoin"), store.FileContextRoom, generalID, 100); err != nil {
		t.Fatalf("bind file: %v", err)
	}

	if s.authorizeDownload(testutil.UserID("alice"), testutil.FileID("prejoin")) {
		t.Error("member must be denied for files attached before their first_seen (forward secrecy)")
	}
}

func TestAuthorizeDownload_GroupMember_PostJoin_Allowed(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup(testutil.GroupID("auth"), testutil.UserID("alice"), []string{testutil.UserID("alice"), testutil.UserID("bob")}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	// joined_at for bob must be <= file.ts. CreateGroup stamps joined_at
	// to time.Now(); bind the file AFTER using a large ts.
	joinedAt, _ := s.store.GetUserGroupJoinedAt(testutil.UserID("bob"), testutil.GroupID("auth"))
	if err := s.store.InsertFileContext(testutil.FileID("g_post"), store.FileContextGroup, testutil.GroupID("auth"), joinedAt+100); err != nil {
		t.Fatalf("bind file: %v", err)
	}

	if !s.authorizeDownload(testutil.UserID("bob"), testutil.FileID("g_post")) {
		t.Error("group member with joined_at <= file.ts should be allowed")
	}
}

func TestAuthorizeDownload_GroupNonMember_Denied(t *testing.T) {
	s := newTestServer(t)
	if err := s.store.CreateGroup(testutil.GroupID("auth_nm"), testutil.UserID("alice"), []string{testutil.UserID("alice"), testutil.UserID("bob")}, "Test"); err != nil {
		t.Fatalf("create group: %v", err)
	}
	if err := s.store.InsertFileContext(testutil.FileID("g_nm"), store.FileContextGroup, testutil.GroupID("auth_nm"), 100); err != nil {
		t.Fatalf("bind file: %v", err)
	}

	// carol is not in the group.
	if s.authorizeDownload(testutil.UserID("carol"), testutil.FileID("g_nm")) {
		t.Error("non-member of group should be denied")
	}
}

func TestAuthorizeDownload_DMParty_Allowed(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage(testutil.DMID("auth"), testutil.UserID("alice"), testutil.UserID("bob"))
	if err != nil {
		t.Fatalf("create dm: %v", err)
	}
	if err := s.store.InsertFileContext(testutil.FileID("dm_p"), store.FileContextDM, dm.ID, 100); err != nil {
		t.Fatalf("bind file: %v", err)
	}

	if !s.authorizeDownload(testutil.UserID("alice"), testutil.FileID("dm_p")) {
		t.Error("DM party should be allowed")
	}
	if !s.authorizeDownload(testutil.UserID("bob"), testutil.FileID("dm_p")) {
		t.Error("other DM party should also be allowed")
	}
}

func TestAuthorizeDownload_DMNonParty_Denied(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage(testutil.DMID("auth_np"), testutil.UserID("alice"), testutil.UserID("bob"))
	if err != nil {
		t.Fatalf("create dm: %v", err)
	}
	if err := s.store.InsertFileContext(testutil.FileID("dm_np"), store.FileContextDM, dm.ID, 100); err != nil {
		t.Fatalf("bind file: %v", err)
	}

	if s.authorizeDownload(testutil.UserID("carol"), testutil.FileID("dm_np")) {
		t.Error("non-party to DM should be denied")
	}
}

// TestAuthorizeDownload_DMPartyAfterLeaveRemainsAllowed locks in the
// ghost-conversation design (see context_lifecycle_model memory note):
// DM left_at is a history-hiding lower bound for MESSAGE reads, NOT an
// access gate for downloads. A party who /leave'd the DM before a file
// was uploaded can STILL download it — because the moment they "come
// back" via /newdm, they'd have access to the same post-leave messages
// and their attachments anyway. Download ACL must stay symmetric with
// the message-read semantics.
//
// Tempting misread: treat left_at as an upper bound (deny files with
// ts > left_at). That would break the symmetry — a leaver would see the
// message but not the attachment. Wrong direction. Test locks it in.
func TestAuthorizeDownload_DMPartyAfterLeaveRemainsAllowed(t *testing.T) {
	s := newTestServer(t)
	dm, err := s.store.CreateOrGetDirectMessage(testutil.DMID("leaver"), testutil.UserID("alice"), testutil.UserID("bob"))
	if err != nil {
		t.Fatalf("create dm: %v", err)
	}
	// Alice /leave's at t=500.
	if err := s.store.SetDMLeftAt(dm.ID, testutil.UserID("alice"), 500); err != nil {
		t.Fatalf("alice leave: %v", err)
	}
	// Bob attaches a file at t=600 (post-alice's-leave).
	if err := s.store.InsertFileContext(testutil.FileID("post_leave"), store.FileContextDM, dm.ID, 600); err != nil {
		t.Fatalf("bind file: %v", err)
	}

	// Alice remains a party (row still exists because Bob hasn't left).
	// Her left_at must NOT gate downloads — she's entitled to post-leave
	// content via the ghost-conversation design.
	if !s.authorizeDownload(testutil.UserID("alice"), testutil.FileID("post_leave")) {
		t.Error("party-with-left_at=500 must still be allowed to download " +
			"file with ts=600 — DM left_at is a history-hider for reads, " +
			"not an access gate. See context_lifecycle_model memory note.")
	}
}

func TestAuthorizeDownload_UnknownFileID_Denied(t *testing.T) {
	s := newTestServer(t)
	if s.authorizeDownload(testutil.UserID("alice"), testutil.FileID("never_uploaded")) {
		t.Error("unknown file_id should be denied (no binding row)")
	}
}
