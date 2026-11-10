package server

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
	"github.com/brushtailmedia/sshkey-chat/internal/testutil"
)

type idShapeCase struct{ verb, field, kind, prefix string }
type idShapeEnv struct {
	s                        *Server
	origin, peer             *captureClient
	room, group, dm, message string
}

func newIDShapeEnv(t *testing.T) idShapeEnv {
	t.Helper()
	s := newTestServer(t)
	alice, bob := testutil.UserID("alice"), testutil.UserID("bob")
	room := s.store.RoomDisplayNameToID("general")
	group := testutil.GroupID("id-shape")
	if err := s.store.CreateGroup(group, alice, []string{alice, bob}, "ID shape"); err != nil {
		t.Fatal(err)
	}
	dm, err := s.store.CreateOrGetDirectMessage(testutil.DMID("id-shape"), alice, bob)
	if err != nil {
		t.Fatal(err)
	}
	message := testutil.MsgID("id-shape")
	row := store.StoredMessage{ID: message, Sender: alice, TS: time.Now().Unix(), Epoch: 1, Payload: testutil.Payload("opaque", 32), Signature: testutil.Signature("opaque")}
	if _, err := s.store.InsertRoomMessage(room, row); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.InsertGroupMessage(group, row); err != nil {
		t.Fatal(err)
	}
	if _, err := s.store.InsertDMMessage(dm.ID, row); err != nil {
		t.Fatal(err)
	}
	origin := testClientFor(alice, "dev_s3_origin")
	peer := testClientFor(bob, "dev_s3_peer")
	s.clients[origin.DeviceID] = origin.Client
	s.clients[peer.DeviceID] = peer.Client
	t.Cleanup(func() {
		s.typing.Remove(alice, room, "")
		s.typing.Remove(alice, "", group)
		s.typing.Remove(alice, "", dm.ID)
	})
	return idShapeEnv{s, origin, peer, room, group, dm.ID, message}
}

func (e idShapeEnv) context(kind string) string {
	switch kind {
	case "room":
		return e.room
	case "group":
		return e.group
	case "dm":
		return e.dm
	}
	return ""
}
func (e idShapeEnv) frame(tc idShapeCase) map[string]any {
	f := map[string]any{"type": tc.verb, "epoch": 1, "payload": testutil.Payload("opaque", 32), "signature": testutil.Signature("opaque"), "id": e.message, "reaction_id": testutil.ReactionID("missing"), "user": testutil.UserID("bob"), "other": testutil.UserID("bob"), "members": []string{testutil.UserID("bob")}, "before": e.message, "last_read": e.message, "corr_id": "corr_AAAAAAAAAAAAAAAAAAAAA", "upload_id": testutil.UploadID("id-shape"), "size": 1, "content_hash": validHash(), "wrapped_keys": map[string]string{testutil.UserID("alice"): testutil.WrappedKey("alice"), testutil.UserID("bob"): testutil.WrappedKey("bob")}}
	if tc.kind != "" {
		f[tc.kind] = e.context(tc.kind)
	}
	return f
}

// logicalIDState snapshots all application rows and the database-file set.
// Read-only connections avoid relying on WAL file bytes or timing-sensitive
// filesystem mtimes. Cursors close before another query uses the handle.
func logicalIDState(t *testing.T, s *Server) map[string][]string {
	t.Helper()
	state := map[string][]string{}
	err := filepath.WalkDir(s.dataDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".db") {
			return nil
		}
		rel, err := filepath.Rel(s.dataDir, path)
		if err != nil {
			return err
		}
		state[rel] = nil
		return func() error {
			u := url.URL{Scheme: "file", Path: path}
			db, err := sql.Open("sqlite", u.String()+"?mode=ro")
			if err != nil {
				return err
			}
			defer db.Close()
			rows, err := db.Query(`SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
			if err != nil {
				return err
			}
			var tables []string
			for rows.Next() {
				var name string
				if err := rows.Scan(&name); err != nil {
					rows.Close()
					return err
				}
				tables = append(tables, name)
			}
			if err := rows.Err(); err != nil {
				rows.Close()
				return err
			}
			rows.Close()
			for _, table := range tables {
				// Identifiers come only from sqlite_schema; escape SQL identifier quotes.
				query := fmt.Sprintf(`SELECT * FROM "%s"`, strings.ReplaceAll(table, `"`, `""`))
				rows, err := db.Query(query)
				if err != nil {
					return err
				}
				columns, err := rows.Columns()
				if err != nil {
					rows.Close()
					return err
				}
				key := rel + ":" + table
				state[key] = nil
				for rows.Next() {
					values := make([]any, len(columns))
					dest := make([]any, len(columns))
					for i := range values {
						dest[i] = &values[i]
					}
					if err := rows.Scan(dest...); err != nil {
						rows.Close()
						return err
					}
					encoded, err := json.Marshal(values)
					if err != nil {
						rows.Close()
						return err
					}
					state[key] = append(state[key], string(encoded))
				}
				if err := rows.Err(); err != nil {
					rows.Close()
					return err
				}
				rows.Close()
				sort.Strings(state[key])
			}
			return nil
		}()
	})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func checkIDShapeCases(t *testing.T, cases []idShapeCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.verb+"/"+tc.field+"/"+tc.kind, func(t *testing.T) {
			for _, malformed := range []bool{true, false} {
				name := "valid-shape"
				if malformed {
					name = "malformed"
				}
				t.Run(name, func(t *testing.T) {
					e := newIDShapeEnv(t)
					frame := e.frame(tc)
					if malformed {
						bad := tc.prefix + "short" // malformed: the selected field must reject a short ID.
						if tc.field == "members" {
							frame[tc.field] = []string{bad}
						} else {
							frame[tc.field] = bad
						}
					}
					// Delete's positive control resolves a well-shaped missing row instead
					// of relying on an artificial cryptographic signature to verify.
					if !malformed && tc.verb == "delete" {
						frame["id"] = testutil.MsgID("missing")
					}
					before := logicalIDState(t, e.s)
					raw, err := json.Marshal(frame)
					if err != nil {
						t.Fatal(err)
					}
					e.s.handleMessage(e.origin.Client, tc.verb, raw)
					count := e.s.counters.Get(counters.SignalInvalidNanoID, e.origin.DeviceID)
					want := int64(0)
					if malformed {
						want = 1
					}
					if int64(count) != want {
						t.Fatalf("invalid-ID count=%d want %d; frames=%s", count, want, e.origin.buf.String())
					}
					if e.s.counters.Get(counters.SignalInvalidNanoID, e.peer.DeviceID) != 0 {
						t.Fatal("counter attributed to another device")
					}
					if !malformed {
						return
					}
					e.s.typing.mu.Lock()
					pendingTyping := len(e.s.typing.timers)
					e.s.typing.mu.Unlock()
					e.s.files.mu.RLock()
					pendingUploads := len(e.s.files.uploads)
					e.s.files.mu.RUnlock()
					if pendingUploads != 0 {
						t.Fatal("malformed ID queued a pending upload")
					}
					if pendingTyping != 0 {
						t.Fatal("malformed ID queued typing expiry work")
					}
					after := logicalIDState(t, e.s)
					if !reflect.DeepEqual(before, after) {
						t.Fatal("malformed ID changed rows or database-file set")
					}
					if len(e.peer.messages()) != 0 {
						t.Fatalf("peer received a broadcast: %s", e.peer.buf.String())
					}
					for _, raw := range e.origin.messages() {
						var response protocol.Error
						if err := json.Unmarshal(raw, &response); err != nil {
							t.Fatal(err)
						}
						wantType := "error"
						if tc.verb == "upload_start" {
							wantType = "upload_error"
						}
						if response.Type != wantType {
							t.Fatalf("success event on rejection: %s", raw)
						}
					}
					if tc.verb == "typing" || tc.verb == "read" || tc.verb == "unreact" {
						if len(e.origin.messages()) != 0 {
							t.Fatalf("silent verb emitted a response: %s", e.origin.buf.String())
						}
					}
				})
			}
		})
	}
}

func TestIDShape_RoomContexts(t *testing.T) {
	checkIDShapeCases(t, []idShapeCase{
		{"send", "room", "room", "room_"},
		{"edit", "room", "room", "room_"},
		{"pin", "room", "room", "room_"},
		{"unpin", "room", "room", "room_"},
		{"leave_room", "room", "room", "room_"},
		{"delete_room", "room", "room", "room_"},
		{"room_update", "room", "room", "room_"},
		{"room_members", "room", "room", "room_"},
		{"epoch_rotate", "room", "room", "room_"},
	})
}

func TestIDShape_GroupContexts(t *testing.T) {
	checkIDShapeCases(t, []idShapeCase{
		{"send_group", "group", "group", "group_"},
		{"edit_group", "group", "group", "group_"},
		{"leave_group", "group", "group", "group_"},
		{"delete_group", "group", "group", "group_"},
		{"rename_group", "group", "group", "group_"},
		{"add_to_group", "group", "group", "group_"},
		{"remove_from_group", "group", "group", "group_"},
		{"promote_group_admin", "group", "group", "group_"},
		{"demote_group_admin", "group", "group", "group_"},
	})
}

func TestIDShape_DmContexts(t *testing.T) {
	checkIDShapeCases(t, []idShapeCase{
		{"send_dm", "dm", "dm", "dm_"},
		{"edit_dm", "dm", "dm", "dm_"},
		{"leave_dm", "dm", "dm", "dm_"},
	})
}

func TestIDShape_RoutedContexts(t *testing.T) {
	checkIDShapeCases(t, []idShapeCase{
		{"typing", "room", "room", "room_"},
		{"typing", "group", "group", "group_"},
		{"typing", "dm", "dm", "dm_"},
		{"read", "room", "room", "room_"},
		{"read", "group", "group", "group_"},
		{"read", "dm", "dm", "dm_"},
		{"history", "room", "room", "room_"},
		{"history", "group", "group", "group_"},
		{"history", "dm", "dm", "dm_"},
		{"react", "room", "room", "room_"},
		{"react", "group", "group", "group_"},
		{"react", "dm", "dm", "dm_"},
		{"unreact", "room", "room", "room_"},
		{"unreact", "group", "group", "group_"},
		{"unreact", "dm", "dm", "dm_"},
		{"delete", "room", "room", "room_"},
		{"delete", "group", "group", "group_"},
		{"delete", "dm", "dm", "dm_"},
	})
}

func TestIDShape_UploadContexts(t *testing.T) {
	checkIDShapeCases(t, []idShapeCase{
		{"upload_start", "room", "room", "room_"},
		{"upload_start", "group", "group", "group_"},
		{"upload_start", "dm", "dm", "dm_"},
	})
}

func TestIDShape_MutationTargets(t *testing.T) {
	checkIDShapeCases(t, []idShapeCase{
		{"edit", "id", "room", "msg_"},
		{"edit_group", "id", "group", "msg_"},
		{"edit_dm", "id", "dm", "msg_"},
		{"react", "id", "room", "msg_"},
		{"react", "id", "group", "msg_"},
		{"react", "id", "dm", "msg_"},
		{"pin", "id", "room", "msg_"},
		{"unpin", "id", "room", "msg_"},
		{"delete", "id", "room", "msg_"},
		{"unreact", "reaction_id", "room", "react_"},
		{"delete", "id", "group", "msg_"},
		{"unreact", "reaction_id", "group", "react_"},
		{"delete", "id", "dm", "msg_"},
		{"unreact", "reaction_id", "dm", "react_"},
	})
}

func TestIDShape_MemberTargets(t *testing.T) {
	checkIDShapeCases(t, []idShapeCase{
		{"add_to_group", "user", "group", "usr_"},
		{"remove_from_group", "user", "group", "usr_"},
		{"promote_group_admin", "user", "group", "usr_"},
		{"demote_group_admin", "user", "group", "usr_"},
		{"create_group", "members", "", "usr_"},
		{"create_dm", "other", "", "usr_"},
	})
}

func TestIDShape_MarkersAndCursors(t *testing.T) {
	checkIDShapeCases(t, []idShapeCase{
		{"read", "last_read", "room", "msg_"},
		{"read", "last_read", "group", "msg_"},
		{"read", "last_read", "dm", "msg_"},
		{"history", "before", "room", "msg_"},
		{"history", "before", "group", "msg_"},
		{"history", "before", "dm", "msg_"},
	})
}

func TestIDShapeHelper_MalformedClasses(t *testing.T) {
	for _, bad := range []string{"", "room_short", "usr_AAAAAAAAAAAAAAAAAAAAA", "room_AAAAAAAAAAAAAAAAAAAA.", "room_" + strings.Repeat("A", 22), "room_" + strings.Repeat("A", 20) + "雪"} { // malformed: empty, length, prefix, alphabet and UTF-8 boundaries.
		t.Run(fmt.Sprintf("%q", bad), func(t *testing.T) {
			e := newIDShapeEnv(t)
			called := 0
			if e.s.validateIDOrReject(e.origin.Client, "send", bad, "room_", func() { called++ }) {
				t.Fatal("malformed ID accepted")
			}
			if called != 1 || e.s.counters.Get(counters.SignalInvalidNanoID, e.origin.DeviceID) != 1 {
				t.Fatal("rejection action/counter must occur once")
			}
		})
	}
}

func TestIDShape_MultiInvalidAndResponseFlood(t *testing.T) {
	e := newIDShapeEnv(t)
	e.s.cfg.Server.RateLimits.ErrorResponsesPerMinute = 1
	raw := []byte(`{"type":"pin","room":"room_short","id":"msg_short","corr_id":"corr_AAAAAAAAAAAAAAAAAAAAA"}`) // malformed: both context and target are short; one count per request.
	// The existing limiter allows a minimum burst of five errors. Alternate
	// verbs to fill it without exhausting either verb's separate bucket.
	sendRaw := bytes.Replace(raw, []byte(`"type":"pin"`), []byte(`"type":"send"`), 1)
	for i := 0; i < 6; i++ {
		if i%2 == 0 {
			e.s.handlePin(e.origin.Client, raw)
		} else {
			e.s.handleSend(e.origin.Client, sendRaw)
		}
	}
	if got := e.s.counters.Get(counters.SignalInvalidNanoID, e.origin.DeviceID); got != 6 {
		t.Fatalf("count=%d want 6", got)
	}
	if len(e.origin.messages()) != 5 || e.s.counters.Get(counters.SignalErrorFlood, e.origin.DeviceID) != 1 {
		t.Fatal("error limiter/counter contract changed")
	}
}

// Both an invalid later element and several invalid elements must stop at
// one rejection; the configured list cap must win before either shape walk.
func TestIDShape_MemberListPrecedence(t *testing.T) {
	for _, capped := range []bool{false, true} {
		t.Run(fmt.Sprintf("capped=%t", capped), func(t *testing.T) {
			e := newIDShapeEnv(t)
			frame := e.frame(idShapeCase{verb: "create_group"})
			frame["members"] = []string{testutil.UserID("bob"), "usr_short", "usr_other_short"} // malformed: valid first element must not hide later malformed members.
			if capped {
				e.s.cfg.Lock()
				e.s.cfg.Server.Groups.MaxMembers = 2
				e.s.cfg.Unlock()
			}
			before := logicalIDState(t, e.s)
			raw, err := json.Marshal(frame)
			if err != nil {
				t.Fatal(err)
			}
			e.s.handleCreateGroup(e.origin.Client, raw)
			wantCount, wantCode := int64(1), protocol.CodeDenied
			if capped {
				wantCount, wantCode = 0, "too_many_members"
			}
			if got := e.s.counters.Get(counters.SignalInvalidNanoID, e.origin.DeviceID); got != wantCount {
				t.Fatalf("invalid-ID count=%d, want %d", got, wantCount)
			}
			messages := e.origin.messages()
			if len(messages) != 1 {
				t.Fatalf("rejection count=%d, want 1", len(messages))
			}
			var response protocol.Error
			if err := json.Unmarshal(messages[0], &response); err != nil {
				t.Fatal(err)
			}
			if response.Type != "error" || response.Code != wantCode {
				t.Fatalf("wrong rejection: %s", messages[0])
			}
			if !reflect.DeepEqual(before, logicalIDState(t, e.s)) || len(e.peer.messages()) != 0 {
				t.Fatal("rejected member list mutated application state or broadcast")
			}
		})
	}
}

func TestIDShape_EarlierGuardsAndUnknownControls(t *testing.T) {
	e := newIDShapeEnv(t)
	raw := []byte(`{"type":"pin","room":"room_short","id":"msg_short","corr_id":"bad"}`) // malformed: invalid correlation precedes ID validation.
	e.s.handlePin(e.origin.Client, raw)
	if e.s.counters.Get(counters.SignalInvalidNanoID, e.origin.DeviceID) != 0 || e.s.counters.Get(counters.SignalMalformedFrame, e.origin.DeviceID) != 1 {
		t.Fatal("corr_id precedence changed")
	}
	frame := e.frame(idShapeCase{verb: "add_to_group", kind: "group"})
	frame["user"] = "usr_short" // malformed: target shape must not bypass group-admin authorization.
	raw, _ = json.Marshal(frame)
	e.s.handleAddToGroup(e.peer.Client, raw)
	if e.s.counters.Get(counters.SignalInvalidNanoID, e.peer.DeviceID) != 0 {
		t.Fatal("unauthorized caller reached target validation")
	}
	frame = e.frame(idShapeCase{verb: "history", kind: "room"})
	frame["before"] = testutil.MsgID("unknown")
	raw, _ = json.Marshal(frame)
	e.s.handleHistory(e.origin.Client, raw)
	if e.s.counters.Get(counters.SignalInvalidNanoID, e.origin.DeviceID) != 0 {
		t.Fatal("well-shaped unknown cursor counted as malformed ID")
	}
}

func TestIDShape_HistoryAndReadEmptyValues(t *testing.T) {
	e := newIDShapeEnv(t)
	for _, kind := range []string{"room", "group", "dm"} {
		f := e.frame(idShapeCase{verb: "history", kind: kind})
		f["before"] = "" // malformed: an empty history cursor remains invalid_cursor.
		raw, _ := json.Marshal(f)
		e.origin.buf.Reset()
		e.s.handleHistory(e.origin.Client, raw)
		messages := e.origin.messages()
		if len(messages) != 1 {
			t.Fatalf("history reply count=%d", len(messages))
		}
		var response protocol.Error
		json.Unmarshal(messages[0], &response)
		if response.Code != protocol.CodeInvalidCursor || response.CorrID != "corr_AAAAAAAAAAAAAAAAAAAAA" {
			t.Fatalf("history empty cursor: %s", messages[0])
		}
		f = e.frame(idShapeCase{verb: "read", kind: kind})
		f["last_read"] = "" // Empty read markers retain their existing accepted meaning.
		before := e.s.counters.Get(counters.SignalInvalidNanoID, e.origin.DeviceID)
		raw, _ = json.Marshal(f)
		e.s.handleRead(e.origin.Client, raw)
		if e.s.counters.Get(counters.SignalInvalidNanoID, e.origin.DeviceID) != before {
			t.Fatal("empty read marker was rejected")
		}
	}
}

// These comparisons use the production encoder bytes, including corr_id
// omission/echo, so syntax checks cannot create an existence/membership oracle.
func TestIDShape_EncodedPrivacyContracts(t *testing.T) {
	cases := []idShapeCase{
		{"send", "room", "room", "room_"}, {"edit", "room", "room", "room_"}, {"pin", "room", "room", "room_"}, {"unpin", "room", "room", "room_"}, {"leave_room", "room", "room", "room_"}, {"delete_room", "room", "room", "room_"}, {"room_update", "room", "room", "room_"}, {"room_members", "room", "room", "room_"},
		{"send_group", "group", "group", "group_"}, {"edit_group", "group", "group", "group_"}, {"leave_group", "group", "group", "group_"}, {"rename_group", "group", "group", "group_"}, {"add_to_group", "group", "group", "group_"}, {"remove_from_group", "group", "group", "group_"}, {"promote_group_admin", "group", "group", "group_"}, {"demote_group_admin", "group", "group", "group_"},
		{"send_dm", "dm", "dm", "dm_"}, {"edit_dm", "dm", "dm", "dm_"}, {"leave_dm", "dm", "dm", "dm_"},
		{"delete", "room", "room", "room_"}, {"delete", "group", "group", "group_"}, {"delete", "dm", "dm", "dm_"},
		{"react", "id", "room", "msg_"}, {"react", "id", "group", "msg_"}, {"react", "id", "dm", "msg_"},
		{"unreact", "reaction_id", "room", "react_"}, {"unreact", "reaction_id", "group", "react_"}, {"unreact", "reaction_id", "dm", "react_"},
		{"edit", "id", "room", "msg_"}, {"edit_group", "id", "group", "msg_"}, {"edit_dm", "id", "dm", "msg_"},
		{"delete", "id", "room", "msg_"}, {"delete", "id", "group", "msg_"}, {"delete", "id", "dm", "msg_"},
		{"history", "before", "room", "msg_"}, {"history", "before", "group", "msg_"}, {"history", "before", "dm", "msg_"},
		{"add_to_group", "user", "group", "usr_"}, {"remove_from_group", "user", "group", "usr_"}, {"promote_group_admin", "user", "group", "usr_"}, {"demote_group_admin", "user", "group", "usr_"},
		{"typing", "room", "room", "room_"}, {"typing", "group", "group", "group_"}, {"typing", "dm", "dm", "dm_"},
		{"read", "room", "room", "room_"}, {"read", "group", "group", "group_"}, {"read", "dm", "dm", "dm_"},
		{"react", "room", "room", "room_"}, {"react", "group", "group", "group_"}, {"react", "dm", "dm", "dm_"},
		{"unreact", "room", "room", "room_"}, {"unreact", "group", "group", "group_"}, {"unreact", "dm", "dm", "dm_"},
		{"epoch_rotate", "room", "room", "room_"},
		{"upload_start", "room", "room", "room_"}, {"upload_start", "group", "group", "group_"}, {"upload_start", "dm", "dm", "dm_"},
	}
	for _, tc := range cases {
		t.Run(tc.verb+"/"+tc.field+"/"+tc.kind, func(t *testing.T) {
			var results [][]byte
			for _, bad := range []bool{true, false} {
				e := newIDShapeEnv(t)
				frame := e.frame(tc)
				value := testutil.ID(tc.prefix, "unknown")
				if bad {
					value = tc.prefix + "short"
				} // malformed: compare the syntax rejection with the existing missing-target class.
				frame[tc.field] = value
				raw, err := json.Marshal(frame)
				if err != nil {
					t.Fatal(err)
				}
				e.s.handleMessage(e.origin.Client, tc.verb, raw)
				results = append(results, append([]byte(nil), e.origin.buf.Bytes()...))
			}
			if !bytes.Equal(results[0], results[1]) {
				t.Fatalf("privacy response differs:\nmalformed %s\nunknown %s", results[0], results[1])
			}
		})
	}
}

func TestIDShape_HistoryRoomEchoesOnlyRequestData(t *testing.T) {
	e := newIDShapeEnv(t)
	frame := e.frame(idShapeCase{verb: "history", kind: "room"})
	bad := "room_short" // malformed: room history's legacy response echoes this already-known request value.
	frame["room"] = bad
	raw, _ := json.Marshal(frame)
	e.s.handleHistory(e.origin.Client, raw)
	messages := e.origin.messages()
	if len(messages) != 1 {
		t.Fatalf("reply count %d", len(messages))
	}
	var response protocol.Error
	if err := json.Unmarshal(messages[0], &response); err != nil {
		t.Fatal(err)
	}
	if response.Code != protocol.ErrNotAuthorized || response.Message != "You don't have access to room: "+bad || response.CorrID != "corr_AAAAAAAAAAAAAAAAAAAAA" {
		t.Fatalf("legacy history contract changed: %s", messages[0])
	}
}
