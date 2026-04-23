package store

import (
	"strings"
	"sync"
	"testing"
)

func TestRoomDBCache_ConcurrentOpenDelete(t *testing.T) {
	t.Parallel()

	s, roomID := newCacheRaceStoreWithRoom(t)
	defer s.Close()

	runConcurrentOpenDelete(t, func() error {
		db, err := s.RoomDB(roomID)
		if err != nil {
			return err
		}
		_, _ = db.Exec(`SELECT 1`)
		return nil
	}, func() error {
		return s.DeleteRoomRecord(roomID)
	})
}

func TestGroupDBCache_ConcurrentOpenDelete(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	groupID := GenerateID("group_")

	runConcurrentOpenDelete(t, func() error {
		db, err := s.GroupDB(groupID)
		if err != nil {
			return err
		}
		_, _ = db.Exec(`SELECT 1`)
		return nil
	}, func() error {
		return s.DeleteGroupConversation(groupID)
	})

}

func TestDMDBCache_ConcurrentOpenDelete(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer s.Close()
	dmID := GenerateID("dm_")

	runConcurrentOpenDelete(t, func() error {
		db, err := s.DMDB(dmID)
		if err != nil {
			return err
		}
		_, _ = db.Exec(`SELECT 1`)
		return nil
	}, func() error {
		return s.DeleteDirectMessage(dmID)
	})

}

func runConcurrentOpenDelete(t *testing.T, opener func() error, deleter func() error) {
	t.Helper()

	const iterations = 300
	errCh := make(chan error, iterations*2)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			if err := opener(); err != nil {
				if isExpectedOpenDeleteRaceErr(err) {
					continue
				}
				errCh <- err
				return
			}
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			if err := deleter(); err != nil {
				if isExpectedOpenDeleteRaceErr(err) {
					continue
				}
				errCh <- err
				return
			}
		}
	}()

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			t.Fatalf("concurrent open/delete failed: %v", err)
		}
	}
}

func isExpectedOpenDeleteRaceErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "disk i/o error") ||
		strings.Contains(msg, "database is locked") ||
		strings.Contains(msg, "unable to open database file")
}

func newCacheRaceStoreWithRoom(t *testing.T) (*Store, string) {
	t.Helper()

	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if _, err := s.roomsDB.Exec(`INSERT INTO rooms (id, display_name, topic) VALUES (?, ?, ?)`,
		GenerateID("room_"), "cache-race", ""); err != nil {
		t.Fatalf("insert room: %v", err)
	}
	var roomID string
	if err := s.roomsDB.QueryRow(`SELECT id FROM rooms WHERE display_name = ?`, "cache-race").Scan(&roomID); err != nil {
		t.Fatalf("select room id: %v", err)
	}
	return s, roomID
}
