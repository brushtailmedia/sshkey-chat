package server

import (
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
)

// Audit S6: handleBinaryChannel must bind the byte-commit to the authenticated
// uploader. The pending upload is keyed by uploadID alone, so a user who learned
// another's in-flight uploadID could otherwise write bytes to it on their own
// channel. The cross-user write is rejected, the offending channel is torn down,
// and — crucially — the victim's pending upload is left intact (no cross-user
// DoS via failUpload). The owner's own write is unaffected (covered by the
// existing TestHandleBinaryChannel_InBoundsFrameSucceeds, where user == channel).
func TestHandleBinaryChannel_CrossUserCommitRejected(t *testing.T) {
	s := newTestServer(t)

	// alice has a legitimate in-flight upload.
	uploadID := "up_victim_alice_42xyz0"
	s.files.mu.Lock()
	s.files.uploads[uploadID] = &pendingUpload{
		uploadID: uploadID,
		fileID:   "file_victim_alice_000",
		size:     1024,
		user:     "alice",
		room:     s.store.RoomDisplayNameToID("general"),
	}
	s.files.mu.Unlock()

	// mallory writes bytes to alice's uploadID on mallory's own channel.
	frame := buildUploadFrame(uploadID, 11, []byte("hello world"))
	ch := newBufferedChannel(frame)
	s.handleBinaryChannel("mallory", ch)

	// Offending channel torn down.
	if ch.closed.Load() == 0 {
		t.Error("upload channel should be closed after a cross-user commit rejection")
	}
	// Misbehavior counter fired (empty device attribution for Channel 3).
	if got := s.counters.Get(counters.SignalNonMemberContext, ""); got != 1 {
		t.Errorf("SignalNonMemberContext = %d, want 1", got)
	}
	// CRITICAL: the victim's pending upload must survive — an attacker must not
	// be able to drop it (failUpload must NOT have been called on a cross-user
	// write).
	s.files.mu.RLock()
	pending, exists := s.files.uploads[uploadID]
	s.files.mu.RUnlock()
	if !exists {
		t.Fatal("victim's pending upload was dropped by a cross-user write (DoS) — it must stay intact")
	}
	if pending.user != "alice" {
		t.Errorf("victim pending.user = %q, want alice (unchanged)", pending.user)
	}
}
