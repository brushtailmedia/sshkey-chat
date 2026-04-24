package main

import (
	"bytes"
	"database/sql"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
)

func uploadStartForPayload(uploadID, roomID string, payload []byte) protocol.UploadStart {
	sum := blake2b.Sum256(payload)
	return protocol.UploadStart{
		Type:        "upload_start",
		UploadID:    uploadID,
		Size:        int64(len(payload)),
		ContentHash: fmt.Sprintf("blake2b-256:%x", sum),
		Room:        roomID,
	}
}

func writeUploadFrame(w io.Writer, uploadID string, payload []byte) error {
	if _, err := w.Write([]byte{byte(len(uploadID))}); err != nil {
		return err
	}
	if _, err := w.Write([]byte(uploadID)); err != nil {
		return err
	}
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(payload)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func legacyUploadStart(tc *legacyClient, start protocol.UploadStart) (*protocol.UploadReady, *protocol.UploadError, error) {
	if err := tc.enc.Encode(start); err != nil {
		return nil, nil, fmt.Errorf("encode upload_start: %w", err)
	}
	raw, typ, err := readCh1UntilTypes(tc, "upload_ready", "upload_error")
	if err != nil {
		return nil, nil, err
	}
	if typ == "upload_error" {
		var ue protocol.UploadError
		if err := json.Unmarshal(raw, &ue); err != nil {
			return nil, nil, fmt.Errorf("unmarshal upload_error: %w", err)
		}
		return nil, &ue, nil
	}
	var ready protocol.UploadReady
	if err := json.Unmarshal(raw, &ready); err != nil {
		return nil, nil, fmt.Errorf("unmarshal upload_ready: %w", err)
	}
	return &ready, nil, nil
}

func legacyReadUploadOutcome(tc *legacyClient) (*protocol.UploadComplete, *protocol.UploadError, error) {
	raw, typ, err := readCh1UntilTypes(tc, "upload_complete", "upload_error")
	if err != nil {
		return nil, nil, err
	}
	if typ == "upload_error" {
		var ue protocol.UploadError
		if err := json.Unmarshal(raw, &ue); err != nil {
			return nil, nil, fmt.Errorf("unmarshal upload_error: %w", err)
		}
		return nil, &ue, nil
	}
	var complete protocol.UploadComplete
	if err := json.Unmarshal(raw, &complete); err != nil {
		return nil, nil, fmt.Errorf("unmarshal upload_complete: %w", err)
	}
	return &complete, nil, nil
}

func legacyUploadOnce(tc *legacyClient, start protocol.UploadStart, payload []byte) (*protocol.UploadComplete, *protocol.UploadError, error) {
	ready, uerr, err := legacyUploadStart(tc, start)
	if err != nil || uerr != nil {
		return nil, uerr, err
	}
	if err := writeUploadFrame(tc.uploadCh, ready.UploadID, payload); err != nil {
		return nil, nil, fmt.Errorf("write upload frame: %w", err)
	}
	return legacyReadUploadOutcome(tc)
}

func todayKeyUTC() string {
	return time.Now().UTC().Format("2006-01-02")
}

func yesterdayKeyUTC() string {
	return time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
}

func mustOpenStore(t *testing.T, dataDir string) *store.Store {
	t.Helper()
	st, err := store.Open(dataDir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func rowCount(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var n int
	query := "SELECT COUNT(*) FROM " + table
	if err := db.QueryRow(query).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func TestUploadQuota_BlockEnforcementEndToEnd(t *testing.T) {
	e := newTestEnvWithConfig(t, func(cfg *config.Config) {
		cfg.Server.Server.Quotas.User.Enabled = true
		cfg.Server.Server.Quotas.User.AllowExemptUsers = false
		cfg.Server.Server.Quotas.User.DailyUploadBytesWarn = "100B"
		cfg.Server.Server.Quotas.User.DailyUploadBytesBlock = "128B"
		cfg.Server.Server.Quotas.User.FlagConsecutiveDays = 2
		cfg.Server.Server.Quotas.User.RetentionDays = 30
	})
	alice := e.connectLegacy(fixtureKeyPath(t, "alice"), "dev_quota_block")
	roomID := e.roomIDByName("general")

	payloadA := bytes.Repeat([]byte("a"), 100)
	completeA, upErr, err := legacyUploadOnce(alice, uploadStartForPayload(store.GenerateID("up_"), roomID, payloadA), payloadA)
	if err != nil {
		t.Fatalf("first upload failed: %v", err)
	}
	if upErr != nil {
		t.Fatalf("first upload rejected unexpectedly: %+v", *upErr)
	}
	if completeA == nil || completeA.FileID == "" {
		t.Fatal("first upload should return upload_complete with file_id")
	}

	payloadB := bytes.Repeat([]byte("b"), 40)
	completeB, upErr, err := legacyUploadOnce(alice, uploadStartForPayload(store.GenerateID("up_"), roomID, payloadB), payloadB)
	if err != nil {
		t.Fatalf("second upload round-trip failed: %v", err)
	}
	if completeB != nil {
		t.Fatalf("second upload should not complete, got file_id=%s", completeB.FileID)
	}
	if upErr == nil {
		t.Fatal("second upload should be rejected at quota gate")
	}
	if upErr.Code != protocol.ErrDailyQuotaExceeded {
		t.Fatalf("quota reject code = %q, want %q", upErr.Code, protocol.ErrDailyQuotaExceeded)
	}
	wantMsg := "This is a chat app, not a file server. You've reached your daily upload quota (128 B). Try again after UTC midnight, or use a dedicated file-sharing service for bulk transfers."
	if upErr.Message != wantMsg {
		t.Fatalf("quota reject message mismatch:\n got: %q\nwant: %q", upErr.Message, wantMsg)
	}

	st := mustOpenStore(t, e.dataDir)
	bytesToday, _, exists, err := st.GetDailyUploadRow("usr_alice_test", todayKeyUTC())
	if err != nil {
		t.Fatalf("GetDailyUploadRow: %v", err)
	}
	if !exists {
		t.Fatal("daily_upload_quotas row should exist after successful upload")
	}
	if bytesToday != int64(len(payloadA)) {
		t.Fatalf("bytes_total = %d, want %d (rejected bytes must not be counted)", bytesToday, len(payloadA))
	}

	filesDir := filepath.Join(e.dataDir, "data", "files")
	entries, err := os.ReadDir(filesDir)
	if err != nil {
		t.Fatalf("ReadDir files: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("files dir entries = %d, want 1", len(entries))
	}
	if entries[0].Name() != completeA.FileID {
		t.Fatalf("unexpected file on disk: %q (want %q)", entries[0].Name(), completeA.FileID)
	}

	if got := rowCount(t, st.DataDB(), "file_hashes"); got != 1 {
		t.Fatalf("file_hashes row count = %d, want 1", got)
	}
	if got := rowCount(t, st.DataDB(), "file_contexts"); got != 1 {
		t.Fatalf("file_contexts row count = %d, want 1", got)
	}
}

func TestUploadQuota_TOCTOURejectsSecondUploadAndCleansArtifacts(t *testing.T) {
	e := newTestEnvWithConfig(t, func(cfg *config.Config) {
		cfg.Server.Server.Quotas.User.Enabled = true
		cfg.Server.Server.Quotas.User.AllowExemptUsers = false
		cfg.Server.Server.Quotas.User.DailyUploadBytesWarn = "64B"
		cfg.Server.Server.Quotas.User.DailyUploadBytesBlock = "150B"
		cfg.Server.Server.Quotas.User.FlagConsecutiveDays = 2
		cfg.Server.Server.Quotas.User.RetentionDays = 30
	})

	if err := e.srv.Store().SetAdmin("usr_bob_test", true); err != nil {
		t.Fatalf("set bob admin: %v", err)
	}
	bob := e.connect(fixtureKeyPath(t, "bob"), "dev_bob_quota_admin")
	alice := e.connectLegacy(fixtureKeyPath(t, "alice"), "dev_alice_quota_toctou")
	roomID := e.roomIDByName("general")

	payload1 := bytes.Repeat([]byte("x"), 100)
	payload2 := bytes.Repeat([]byte("y"), 100)
	start1 := uploadStartForPayload(store.GenerateID("up_"), roomID, payload1)
	start2 := uploadStartForPayload(store.GenerateID("up_"), roomID, payload2)

	if ready, upErr, err := legacyUploadStart(alice, start1); err != nil || upErr != nil || ready == nil {
		t.Fatalf("start1 failed: ready=%v errResp=%v err=%v", ready != nil, upErr, err)
	}
	if ready, upErr, err := legacyUploadStart(alice, start2); err != nil || upErr != nil || ready == nil {
		t.Fatalf("start2 failed: ready=%v errResp=%v err=%v", ready != nil, upErr, err)
	}

	if err := writeUploadFrame(alice.uploadCh, start1.UploadID, payload1); err != nil {
		t.Fatalf("write payload1: %v", err)
	}
	complete1, upErr, err := legacyReadUploadOutcome(alice)
	if err != nil {
		t.Fatalf("outcome1: %v", err)
	}
	if upErr != nil {
		t.Fatalf("first upload unexpectedly rejected: %+v", *upErr)
	}
	if complete1 == nil || complete1.FileID == "" {
		t.Fatal("first upload missing upload_complete")
	}

	if err := writeUploadFrame(alice.uploadCh, start2.UploadID, payload2); err != nil {
		t.Fatalf("write payload2: %v", err)
	}
	complete2, upErr, err := legacyReadUploadOutcome(alice)
	if err != nil {
		t.Fatalf("outcome2: %v", err)
	}
	if complete2 != nil {
		t.Fatalf("second upload should not complete, got file_id=%s", complete2.FileID)
	}
	if upErr == nil {
		t.Fatal("second upload should fail in TOCTOU quota recheck")
	}
	if upErr.Code != protocol.ErrDailyQuotaExceeded {
		t.Fatalf("second upload code = %q, want %q", upErr.Code, protocol.ErrDailyQuotaExceeded)
	}

	// Upload 1 (100B) crossed the warn threshold (64B) and fires
	// admin_notify quota_warn first. Upload 2's TOCTOU reject fires
	// admin_notify quota_block second. Read messages until we find
	// the quota_block event — warn is a permitted predecessor here,
	// any other admin_notify event or non-admin_notify message is
	// a failure.
	var notify protocol.AdminNotifyQuota
	for {
		msgType, raw := bob.readMessage()
		if msgType != "admin_notify" {
			t.Fatalf("bob expected admin_notify events, got %s: %s", msgType, string(raw))
		}
		if err := json.Unmarshal(raw, &notify); err != nil {
			t.Fatalf("unmarshal admin_notify: %v", err)
		}
		if notify.Event == "quota_block" {
			break
		}
		if notify.Event != "quota_warn" {
			t.Fatalf("unexpected admin_notify event before quota_block: %q", notify.Event)
		}
	}
	if notify.User != "usr_alice_test" {
		t.Fatalf("admin_notify user = %q, want usr_alice_test", notify.User)
	}

	st := mustOpenStore(t, e.dataDir)
	bytesToday, _, exists, err := st.GetDailyUploadRow("usr_alice_test", todayKeyUTC())
	if err != nil {
		t.Fatalf("GetDailyUploadRow: %v", err)
	}
	if !exists {
		t.Fatal("daily_upload_quotas row should exist")
	}
	if bytesToday != int64(len(payload1)) {
		t.Fatalf("bytes_total = %d, want %d after TOCTOU reject", bytesToday, len(payload1))
	}

	filesDir := filepath.Join(e.dataDir, "data", "files")
	entries, err := os.ReadDir(filesDir)
	if err != nil {
		t.Fatalf("ReadDir files: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("files dir entries = %d, want 1 (rejected upload blob must be removed)", len(entries))
	}
	if entries[0].Name() != complete1.FileID {
		t.Fatalf("unexpected remaining file %q, want %q", entries[0].Name(), complete1.FileID)
	}
	if got := rowCount(t, st.DataDB(), "file_hashes"); got != 1 {
		t.Fatalf("file_hashes rows = %d, want 1", got)
	}
	if got := rowCount(t, st.DataDB(), "file_contexts"); got != 1 {
		t.Fatalf("file_contexts rows = %d, want 1", got)
	}
}

func TestUploadQuota_WarnNotifyFiresOncePerDay(t *testing.T) {
	e := newTestEnvWithConfig(t, func(cfg *config.Config) {
		cfg.Server.Server.Quotas.User.Enabled = true
		cfg.Server.Server.Quotas.User.AllowExemptUsers = false
		cfg.Server.Server.Quotas.User.DailyUploadBytesWarn = "100B"
		cfg.Server.Server.Quotas.User.DailyUploadBytesBlock = "1000B"
		cfg.Server.Server.Quotas.User.FlagConsecutiveDays = 2
		cfg.Server.Server.Quotas.User.RetentionDays = 30
	})

	if err := e.srv.Store().SetAdmin("usr_bob_test", true); err != nil {
		t.Fatalf("set bob admin: %v", err)
	}
	bob := e.connect(fixtureKeyPath(t, "bob"), "dev_bob_quota_warn_admin")
	alice := e.connectLegacy(fixtureKeyPath(t, "alice"), "dev_alice_quota_warn")
	roomID := e.roomIDByName("general")

	first := bytes.Repeat([]byte("w"), 120)
	complete, upErr, err := legacyUploadOnce(alice, uploadStartForPayload(store.GenerateID("up_"), roomID, first), first)
	if err != nil {
		t.Fatalf("first warn upload: %v", err)
	}
	if upErr != nil || complete == nil {
		t.Fatalf("first warn upload should succeed, got complete=%v upErr=%v", complete != nil, upErr)
	}

	msgType, raw := bob.readMessage()
	if msgType != "admin_notify" {
		t.Fatalf("expected quota_warn admin_notify, got %s: %s", msgType, string(raw))
	}
	var notify protocol.AdminNotifyQuota
	if err := json.Unmarshal(raw, &notify); err != nil {
		t.Fatalf("unmarshal admin_notify: %v", err)
	}
	if notify.Event != "quota_warn" {
		t.Fatalf("admin_notify event = %q, want quota_warn", notify.Event)
	}

	second := bytes.Repeat([]byte("z"), 10)
	complete, upErr, err = legacyUploadOnce(alice, uploadStartForPayload(store.GenerateID("up_"), roomID, second), second)
	if err != nil {
		t.Fatalf("second upload: %v", err)
	}
	if upErr != nil || complete == nil {
		t.Fatalf("second upload should succeed without warn re-fire, got complete=%v upErr=%v", complete != nil, upErr)
	}

	if err := alice.enc.Encode(protocol.Send{
		Type:    "send",
		Room:    roomID,
		Epoch:   1,
		Payload: "quota_warn_probe_message",
	}); err != nil {
		t.Fatalf("probe send: %v", err)
	}
	_, _ = alice.readMessage() // sender echo
	msgType, _ = bob.readMessage()
	if msgType != "message" {
		t.Fatalf("expected normal message after second upload; got %s (warn should not re-fire)", msgType)
	}

	st := mustOpenStore(t, e.dataDir)
	_, warned, _, err := st.GetDailyUploadRow("usr_alice_test", todayKeyUTC())
	if err != nil {
		t.Fatalf("GetDailyUploadRow: %v", err)
	}
	if !warned {
		t.Fatal("warn_notified should be true after first warn-cross")
	}
}

func TestUploadQuota_SustainedPatternFiresQuotaSustained(t *testing.T) {
	e := newTestEnvWithConfig(t, func(cfg *config.Config) {
		cfg.Server.Server.Quotas.User.Enabled = true
		cfg.Server.Server.Quotas.User.AllowExemptUsers = false
		cfg.Server.Server.Quotas.User.DailyUploadBytesWarn = "100B"
		cfg.Server.Server.Quotas.User.DailyUploadBytesBlock = "2000B"
		cfg.Server.Server.Quotas.User.FlagConsecutiveDays = 2
		cfg.Server.Server.Quotas.User.RetentionDays = 30
	})
	st := mustOpenStore(t, e.dataDir)
	if _, err := st.IncrementDailyUploadBytes("usr_alice_test", yesterdayKeyUTC(), 120, true); err != nil {
		t.Fatalf("seed yesterday row: %v", err)
	}
	if _, _, exists, err := st.GetDailyUploadRow("usr_alice_test", todayKeyUTC()); err != nil {
		t.Fatalf("read today row: %v", err)
	} else if exists {
		t.Fatal("today row should be empty before first upload")
	}

	if err := e.srv.Store().SetAdmin("usr_bob_test", true); err != nil {
		t.Fatalf("set bob admin: %v", err)
	}
	bob := e.connect(fixtureKeyPath(t, "bob"), "dev_bob_quota_sustained_admin")
	alice := e.connectLegacy(fixtureKeyPath(t, "alice"), "dev_alice_quota_sustained")
	roomID := e.roomIDByName("general")

	payload := bytes.Repeat([]byte("s"), 120)
	complete, upErr, err := legacyUploadOnce(alice, uploadStartForPayload(store.GenerateID("up_"), roomID, payload), payload)
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if upErr != nil || complete == nil {
		t.Fatalf("upload should succeed, got complete=%v upErr=%v", complete != nil, upErr)
	}

	msgType, raw := bob.readMessage()
	if msgType != "admin_notify" {
		t.Fatalf("expected quota_sustained admin_notify, got %s: %s", msgType, string(raw))
	}
	var notify protocol.AdminNotifyQuota
	if err := json.Unmarshal(raw, &notify); err != nil {
		t.Fatalf("unmarshal admin_notify: %v", err)
	}
	if notify.Event != "quota_sustained" {
		t.Fatalf("admin_notify event = %q, want quota_sustained", notify.Event)
	}
	if notify.ConsecutiveDays != 2 {
		t.Fatalf("consecutive_days = %d, want 2", notify.ConsecutiveDays)
	}
}

func TestUploadQuota_EnabledTransitionDoesNotCorruptAccounting(t *testing.T) {
	e := newTestEnvWithConfig(t, func(cfg *config.Config) {
		cfg.Server.Server.Quotas.User.Enabled = true
		cfg.Server.Server.Quotas.User.AllowExemptUsers = false
		cfg.Server.Server.Quotas.User.DailyUploadBytesWarn = "100B"
		cfg.Server.Server.Quotas.User.DailyUploadBytesBlock = "128B"
		cfg.Server.Server.Quotas.User.FlagConsecutiveDays = 2
		cfg.Server.Server.Quotas.User.RetentionDays = 30
	})
	alice := e.connectLegacy(fixtureKeyPath(t, "alice"), "dev_alice_quota_toggle")
	roomID := e.roomIDByName("general")

	base := bytes.Repeat([]byte("b"), 100)
	complete, upErr, err := legacyUploadOnce(alice, uploadStartForPayload(store.GenerateID("up_"), roomID, base), base)
	if err != nil || upErr != nil || complete == nil {
		t.Fatalf("base upload failed: complete=%v upErr=%v err=%v", complete != nil, upErr, err)
	}

	e.cfg.Lock()
	e.cfg.Server.Server.Quotas.User.Enabled = false
	e.cfg.Unlock()

	whileDisabled := bytes.Repeat([]byte("d"), 80)
	complete, upErr, err = legacyUploadOnce(alice, uploadStartForPayload(store.GenerateID("up_"), roomID, whileDisabled), whileDisabled)
	if err != nil || upErr != nil || complete == nil {
		t.Fatalf("upload while disabled should succeed: complete=%v upErr=%v err=%v", complete != nil, upErr, err)
	}

	e.cfg.Lock()
	e.cfg.Server.Server.Quotas.User.Enabled = true
	e.cfg.Unlock()

	afterReenable := bytes.Repeat([]byte("e"), 40) // 100 + 40 > 128, should reject
	complete, upErr, err = legacyUploadOnce(alice, uploadStartForPayload(store.GenerateID("up_"), roomID, afterReenable), afterReenable)
	if err != nil {
		t.Fatalf("post-reenable upload failed unexpectedly: %v", err)
	}
	if complete != nil {
		t.Fatalf("post-reenable upload should not complete, got file_id=%s", complete.FileID)
	}
	if upErr == nil || upErr.Code != protocol.ErrDailyQuotaExceeded {
		t.Fatalf("post-reenable upload should be quota rejected, got %+v", upErr)
	}

	st := mustOpenStore(t, e.dataDir)
	bytesToday, _, _, err := st.GetDailyUploadRow("usr_alice_test", todayKeyUTC())
	if err != nil {
		t.Fatalf("GetDailyUploadRow: %v", err)
	}
	if bytesToday != 100 {
		t.Fatalf("bytes_total = %d, want 100 (disabled period should not accumulate)", bytesToday)
	}
}
