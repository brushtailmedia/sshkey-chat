package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
	"github.com/brushtailmedia/sshkey-chat/internal/testutil"
)

type pinPersistenceEnv struct {
	s             *Server
	origin, peer  *captureClient
	room, message string
	logs          *bytes.Buffer
}

func newPinPersistenceEnv(t *testing.T, seedMessage bool) pinPersistenceEnv {
	t.Helper()
	s := newTestServer(t)
	room := s.store.RoomDisplayNameToID("general")
	message := testutil.MsgID("pin-persistence")
	if seedMessage {
		if _, err := s.store.InsertRoomMessage(room, store.StoredMessage{ID: message, Sender: testutil.UserID("alice"), TS: 42, Payload: testutil.Payload("pin", 32), Signature: testutil.Signature("pin")}); err != nil {
			t.Fatal(err)
		}
	}
	origin := testClientFor(testutil.UserID("alice"), "dev_pin_origin")
	peer := testClientFor(testutil.UserID("bob"), "dev_pin_peer")
	s.clients[origin.DeviceID], s.clients[peer.DeviceID] = origin.Client, peer.Client
	logs := new(bytes.Buffer)
	s.logger = slog.New(slog.NewJSONHandler(logs, nil))
	return pinPersistenceEnv{s, origin, peer, room, message, logs}
}

func (e pinPersistenceEnv) invoke(t *testing.T, verb string) {
	t.Helper()
	raw, err := json.Marshal(protocol.Pin{Type: verb, Room: e.room, ID: e.message, CorrID: "corr_AAAAAAAAAAAAAAAAAAAAA"})
	if err != nil {
		t.Fatal(err)
	}
	e.s.handleMessage(e.origin.Client, verb, raw)
}

func (e pinPersistenceEnv) roomDB(t *testing.T) *store.DB {
	t.Helper()
	db, err := e.s.store.RoomDB(e.room)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// A directory at a not-yet-opened room database path fails SQLite open on
// every platform, including privileged runs. No chmod, sleeps or new seam.
func (e pinPersistenceEnv) blockRoomDBOpen(t *testing.T) {
	t.Helper()
	path := filepath.Join(e.s.dataDir, "data", "room-"+e.room+".db")
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("room DB already exists: %v", err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := e.s.store.RoomDB(e.room); err == nil {
		t.Fatal("fixture did not block the actual room database open")
	}
}

func (e pinPersistenceEnv) assertError(t *testing.T, code, message string) {
	t.Helper()
	var expected bytes.Buffer
	if err := protocol.NewEncoder(&expected).Encode(protocol.Error{Type: "error", Code: code, Message: message, CorrID: "corr_AAAAAAAAAAAAAAAAAAAAA"}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(e.origin.buf.Bytes(), expected.Bytes()) {
		t.Fatalf("origin response:\n got %s\nwant %s\npeer received: %s", e.origin.buf.Bytes(), expected.Bytes(), e.peer.buf.Bytes())
	}
	if e.peer.buf.Len() != 0 {
		t.Fatalf("peer received success: %s", e.peer.buf.Bytes())
	}
	if e.s.counters.Get(counters.SignalInvalidNanoID, e.origin.DeviceID) != 0 || e.s.counters.Get(counters.SignalInvalidNanoID, e.peer.DeviceID) != 0 {
		t.Fatal("storage failure counted as invalid ID")
	}
}

func (e pinPersistenceEnv) assertFailureLog(t *testing.T) {
	t.Helper()
	var entry map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(e.logs.Bytes()), &entry); err != nil {
		t.Fatalf("missing structured failure log: %v; %s", err, e.logs.Bytes())
	}
	cause, _ := entry["error"].(string)
	if entry["level"] != "ERROR" || cause == "" || entry["room"] != e.room || entry["message_id"] != e.message {
		t.Fatalf("failure log lacks cause/context: %v", entry)
	}
}

func TestPinPersistence_WriteFailure(t *testing.T) {
	for _, verb := range []string{"pin", "unpin"} {
		t.Run(verb, func(t *testing.T) {
			e := newPinPersistenceEnv(t, true)
			if _, err := e.roomDB(t).Exec(`DROP TABLE pins`); err != nil {
				t.Fatal(err)
			}
			before := logicalIDState(t, e.s)
			e.invoke(t, verb)
			e.assertError(t, protocol.CodeInternal, "Failed to "+verb+" message")
			e.assertFailureLog(t)
			if !reflect.DeepEqual(before, logicalIDState(t, e.s)) {
				t.Fatal("failed write changed application state")
			}
		})
	}
}

func TestPinPersistence_FailedUnpinPreservesPin(t *testing.T) {
	e := newPinPersistenceEnv(t, true)
	db := e.roomDB(t)
	if _, err := db.Exec(`INSERT INTO pins(message_id,pinned_by,ts) VALUES(?,?,?)`, e.message, e.peer.UserID, 42); err != nil {
		t.Fatal(err)
	}
	// Keep the real pin row available for inspection while forcing DELETE to
	// fail. The trigger lives only in this test's temporary room database.
	if _, err := db.Exec(`CREATE TRIGGER reject_pin_delete BEFORE DELETE ON pins
		BEGIN SELECT RAISE(ABORT, 'test pin delete failure'); END`); err != nil {
		t.Fatal(err)
	}
	before := logicalIDState(t, e.s)
	e.invoke(t, "unpin")
	e.assertError(t, protocol.CodeInternal, "Failed to unpin message")
	e.assertFailureLog(t)
	if !reflect.DeepEqual(before, logicalIDState(t, e.s)) {
		t.Fatal("failed unpin changed application state")
	}
	var by string
	var ts int64
	if err := db.QueryRow(`SELECT pinned_by,ts FROM pins WHERE message_id=?`, e.message).Scan(&by, &ts); err != nil {
		t.Fatalf("failed unpin lost the stored pin: %v", err)
	}
	if by != e.peer.UserID || ts != 42 {
		t.Fatalf("failed unpin changed pin metadata: by=%q ts=%d", by, ts)
	}

	// Removing the fault must let the same authorized request persist and
	// broadcast success, proving the failure was caused by the trigger.
	if _, err := db.Exec(`DROP TRIGGER reject_pin_delete`); err != nil {
		t.Fatal(err)
	}
	e.origin.buf.Reset()
	e.peer.buf.Reset()
	e.logs.Reset()
	e.invoke(t, "unpin")
	e.assertSuccess(t, "unpinned")
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pins WHERE message_id=?`, e.message).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("unpin after removing the fault was not persisted")
	}
}

func TestPinPersistence_OpenFailure(t *testing.T) {
	for _, verb := range []string{"pin", "unpin"} {
		t.Run(verb, func(t *testing.T) {
			e := newPinPersistenceEnv(t, false)
			e.blockRoomDBOpen(t)
			before := logicalIDState(t, e.s)
			e.invoke(t, verb)
			e.assertError(t, protocol.CodeInternal, "Failed to "+verb+" message")
			e.assertFailureLog(t)
			if !reflect.DeepEqual(before, logicalIDState(t, e.s)) {
				t.Fatal("failed open changed application state")
			}
		})
	}
}

func TestPinPersistence_MissingMessage(t *testing.T) {
	e := newPinPersistenceEnv(t, false)
	db := e.roomDB(t)
	var enabled int
	if err := db.QueryRow(`PRAGMA foreign_keys`).Scan(&enabled); err != nil || enabled != 1 {
		t.Fatalf("foreign keys=%d err=%v", enabled, err)
	}
	before := logicalIDState(t, e.s)
	e.invoke(t, "pin")
	e.assertError(t, protocol.CodeInternal, "Failed to pin message")
	e.assertFailureLog(t)
	if !reflect.DeepEqual(before, logicalIDState(t, e.s)) {
		t.Fatal("missing-message pin changed application state")
	}
}

func (e pinPersistenceEnv) assertSuccess(t *testing.T, kind string) {
	t.Helper()
	for _, c := range []*captureClient{e.origin, e.peer} {
		frames := c.messages()
		if len(frames) != 1 {
			t.Fatalf("%s received %d frames: %s", c.DeviceID, len(frames), c.buf.Bytes())
		}
		var event struct{ Type, Room, ID string }
		if err := json.Unmarshal(frames[0], &event); err != nil {
			t.Fatal(err)
		}
		if event.Type != kind || event.Room != e.room || event.ID != e.message {
			t.Fatalf("wrong success: %s", frames[0])
		}
	}
	if e.logs.Len() != 0 {
		t.Fatalf("success logged failure: %s", e.logs.Bytes())
	}
	if e.s.counters.Get(counters.SignalInvalidNanoID, e.origin.DeviceID) != 0 {
		t.Fatal("success counted as invalid ID")
	}
}

func TestPinPersistence_Success(t *testing.T) {
	e := newPinPersistenceEnv(t, true)
	e.invoke(t, "pin")
	e.assertSuccess(t, "pinned")
	var by string
	var ts int64
	if err := e.roomDB(t).QueryRow(`SELECT pinned_by,ts FROM pins WHERE message_id=?`, e.message).Scan(&by, &ts); err != nil {
		t.Fatal(err)
	}
	if by != e.origin.UserID || ts <= 0 {
		t.Fatalf("persisted pin by=%q ts=%d", by, ts)
	}
	e.origin.buf.Reset()
	e.peer.buf.Reset()
	e.invoke(t, "unpin")
	e.assertSuccess(t, "unpinned")
	var count int
	if err := e.roomDB(t).QueryRow(`SELECT COUNT(*) FROM pins WHERE message_id=?`, e.message).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("successful unpin was not persisted")
	}
}

func TestPinPersistence_NoOps(t *testing.T) {
	t.Run("duplicate pin", func(t *testing.T) {
		e := newPinPersistenceEnv(t, true)
		if _, err := e.roomDB(t).Exec(`INSERT INTO pins(message_id,pinned_by,ts) VALUES(?,?,?)`, e.message, e.peer.UserID, 42); err != nil {
			t.Fatal(err)
		}
		before := logicalIDState(t, e.s)
		e.invoke(t, "pin")
		e.assertSuccess(t, "pinned")
		if !reflect.DeepEqual(before, logicalIDState(t, e.s)) {
			t.Fatal("duplicate pin overwrote original metadata")
		}
	})
	t.Run("absent unpin", func(t *testing.T) {
		e := newPinPersistenceEnv(t, true)
		before := logicalIDState(t, e.s)
		for i := 0; i < 2; i++ {
			e.origin.buf.Reset()
			e.peer.buf.Reset()
			e.invoke(t, "unpin")
			e.assertSuccess(t, "unpinned")
		}
		if !reflect.DeepEqual(before, logicalIDState(t, e.s)) {
			t.Fatal("absent unpin changed application state")
		}
	})
}

func TestPinPersistence_AuthorizationPrecedesStorage(t *testing.T) {
	for _, verb := range []string{"pin", "unpin"} {
		for _, state := range []string{"non-member", "retired"} {
			t.Run(verb+"/"+state, func(t *testing.T) {
				e := newPinPersistenceEnv(t, false)
				e.blockRoomDBOpen(t)
				code, message := protocol.ErrUnknownRoom, "You are not a member of this room"
				if state == "non-member" {
					if err := e.s.store.RemoveRoomMember(e.room, e.origin.UserID); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := e.s.store.SetRoomRetired(e.room, "os:1000", "operator"); err != nil {
						t.Fatal(err)
					}
					code, message = protocol.ErrRoomRetired, "This room has been archived and is read-only"
				}
				before := logicalIDState(t, e.s)
				e.invoke(t, verb)
				e.assertError(t, code, message)
				if e.logs.Len() != 0 {
					t.Fatalf("authorization rejection reached storage: %s", e.logs.Bytes())
				}
				if !reflect.DeepEqual(before, logicalIDState(t, e.s)) {
					t.Fatal("authorization rejection changed state")
				}
			})
		}
	}
}

func TestPinPersistence_ErrorResponseLimit(t *testing.T) {
	e := newPinPersistenceEnv(t, true)
	if _, err := e.roomDB(t).Exec(`DROP TABLE pins`); err != nil {
		t.Fatal(err)
	}
	e.s.cfg.Lock()
	e.s.cfg.Server.RateLimits.PinsPerMinute = 600
	e.s.cfg.Server.RateLimits.ErrorResponsesPerMinute = 1
	e.s.cfg.Unlock()
	for i := 0; i < 6; i++ {
		e.invoke(t, []string{"pin", "unpin"}[i%2])
	}
	frames := e.origin.messages()
	if len(frames) != 5 || e.peer.buf.Len() != 0 {
		t.Fatalf("error limiter/broadcast: frames=%d peer=%s", len(frames), e.peer.buf.Bytes())
	}
	for _, raw := range frames {
		var event protocol.Error
		if err := json.Unmarshal(raw, &event); err != nil {
			t.Fatal(err)
		}
		if event.Type != "error" || event.Code != protocol.CodeInternal || event.CorrID != "corr_AAAAAAAAAAAAAAAAAAAAA" {
			t.Fatalf("wrong limited error: %s", raw)
		}
	}
	if e.s.counters.Get(counters.SignalErrorFlood, e.origin.DeviceID) != 1 || e.s.counters.Get(counters.SignalInvalidNanoID, e.origin.DeviceID) != 0 || e.s.counters.Get(counters.SignalRateLimited, e.origin.DeviceID) != 0 {
		t.Fatal("storage failure/flood signal contract changed")
	}
}
