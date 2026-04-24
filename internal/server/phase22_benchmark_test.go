package server

import (
	"io"
	"log/slog"
	"testing"

	"github.com/brushtailmedia/sshkey-chat/internal/config"
	"github.com/brushtailmedia/sshkey-chat/internal/counters"
	"github.com/brushtailmedia/sshkey-chat/internal/protocol"
	"github.com/brushtailmedia/sshkey-chat/internal/store"
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
			UserID:   "usr_bench",
			DeviceID: "dev_bench",
			Encoder:  newSafeEncoder(protocol.NewEncoder(io.Discard)),
			// Nil sendCh forces sync test path in fanOutOne.
		}
	}

	msg := protocol.Message{
		Type:    "message",
		ID:      "msg_bench",
		Room:    "room_bench",
		From:    "usr_sender",
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
			ID:        "msg_bench",
			Sender:    "usr_sender",
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
			User:  "usr_sender",
			Name:  "bench",
			TS:    int64(i + 1),
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = storedToRawMessages(msgs, "room_bench", "")
		_ = roomEventsToRaw(events, "room_bench")
	}
}
