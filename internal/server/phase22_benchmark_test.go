package server

import (
	"io"
	"log/slog"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
	"github.com/brushtailmedia/sshkey-chat/internal/testutil"
)

// Phase 22 C.5: broadcast fanout hot-path benchmark.
func BenchmarkFanOut_100Recipients(b *testing.B) {
	cfg := &config.Config{Server: config.DefaultServerConfig()}
	s := &Server{
		cfg:      cfg,
		counters: counters.New(),
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	recipients := make([]*Client, 100)
	for i := range recipients {
		recipients[i] = &Client{
			UserID:   testutil.UserID("bench"),
			DeviceID: "dev_bench",
			Encoder:  newSafeEncoder(protocol.NewEncoder(io.Discard)),
			// Nil sendCh forces sync test path in fanOutOne.
		}
	}

	msg := protocol.Message{
		Type:    "message",
		ID:      testutil.MsgID("bench"),
		Room:    testutil.RoomID("bench"),
		From:    testutil.UserID("sender"),
		Payload: "payload",
		TS:      1,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.fanOut("message", msg, recipients)
	}
}

// Phase 22 C.5: sync-batch assembly benchmark (message/event conversion).
func BenchmarkSyncBatchAssembly_200Messages(b *testing.B) {
	msgs := make([]store.StoredMessage, 200)
	for i := range msgs {
		msgs[i] = store.StoredMessage{
			ID:        testutil.MsgID("bench"),
			Sender:    testutil.UserID("sender"),
			TS:        int64(i + 1),
			Epoch:     1,
			Payload:   "ciphertext",
			Signature: "sig",
		}
	}
	events := make([]store.GroupEventRow, 50)
	for i := range events {
		events[i] = store.GroupEventRow{
			ID:    int64(i + 1),
			Event: "rename",
			User:  testutil.UserID("sender"),
			Name:  "bench",
			TS:    int64(i + 1),
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = storedToRawMessages(msgs, testutil.RoomID("bench"), "")
		_ = roomEventsToRaw(events, testutil.RoomID("bench"))
	}
}
