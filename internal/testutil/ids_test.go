package testutil_test

import (
	"encoding/base64"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/store"
	"github.com/brushtailmedia/sshkey-chat/internal/testutil"
)

func TestIDFixedVectors(t *testing.T) {
	vectors := []struct{ label, body string }{
		{"alice", "hO69-E0lQV3oFdZfcNZ8R"},
		{"bob", "1stOyI6QZPcMnJXNDdLat"},
		{"", "Zm42OySKQxq8Plvadk1aa"},
		{"雪", "J5FYWy0PyBfsO9TrfNNvd"},
	}
	for _, tt := range []struct {
		prefix string
		build  func(string) string
	}{
		{"dev_", testutil.DeviceID}, {"usr_", testutil.UserID}, {"msg_", testutil.MsgID}, {"react_", testutil.ReactionID}, {"room_", testutil.RoomID}, {"group_", testutil.GroupID}, {"dm_", testutil.DMID}, {"file_", testutil.FileID}, {"up_", testutil.UploadID},
	} {
		for _, v := range vectors {
			t.Run(tt.prefix+v.label, func(t *testing.T) {
				got := tt.build(v.label)
				if got != tt.prefix+v.body || got != tt.build(v.label) {
					t.Fatalf("fixture %q = %q, want %q", v.label, got, tt.prefix+v.body)
				}
				if err := store.ValidateNanoID(got, tt.prefix); err != nil {
					t.Fatal(err)
				}
			})
		}
		if tt.build("alice") == tt.build("bob") {
			t.Fatal("distinct labels collided")
		}
	}
}
func TestSizedEnvelopes(t *testing.T) {
	signature, err := base64.StdEncoding.DecodeString(testutil.Signature("opaque"))
	if err != nil || len(signature) != 64 {
		t.Fatalf("signature size=%d err=%v", len(signature), err)
	}
	payload, err := base64.StdEncoding.DecodeString(testutil.Payload("opaque", 513))
	if err != nil || len(payload) != 513 {
		t.Fatalf("payload size=%d err=%v", len(payload), err)
	}
}
