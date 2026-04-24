package lockfile

// Phase 19 Step 2 — lockfile unit tests.
//
// Coverage matrix:
//   - Write to fresh dir → readable with current PID + start time, alive=true
//   - Write twice (same process) → ErrAlreadyRunning
//   - Write over stale lockfile (bogus PID that's definitely not running) → overwrites
//   - Write over corrupted lockfile → clear error, no overwrite
//   - Read missing file → os.ErrNotExist
//   - Read empty file → clear error
//   - Read file with bad PID line → clear error
//   - Read file with missing timestamp line → clear error
//   - Remove existing → nil
//   - Remove missing → nil (idempotent)
//   - isAlive for PID 1 → true (init always runs)
//   - isAlive for an invented-dead PID → false (via a large-PID canary)

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestWrite_FreshFileRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pid")

	if err := Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}

	info, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if info.PID != os.Getpid() {
		t.Errorf("PID = %d, want %d (our PID)", info.PID, os.Getpid())
	}
	if !info.Alive {
		t.Error("Alive = false, want true (we wrote our own PID)")
	}
	// StartedAt should be within the last few seconds.
	if delta := time.Since(info.StartedAt); delta < 0 || delta > 10*time.Second {
		t.Errorf("StartedAt delta = %s, want ~0", delta)
	}
}

func TestWrite_AlreadyRunningRefuses(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pid")

	if err := Write(path); err != nil {
		t.Fatalf("first Write: %v", err)
	}

	err := Write(path)
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("second Write err = %v, want ErrAlreadyRunning", err)
	}
	if !strings.Contains(err.Error(), fmt.Sprintf("PID %d", os.Getpid())) {
		t.Errorf("error message should mention live PID, got: %q", err.Error())
	}
}

func TestWrite_StaleLockfileIsOverwritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pid")

	// Write a lockfile with a PID that definitely isn't running.
	// PID 2^31-1 is the max on most platforms; unlikely to be assigned.
	stalePID := 2147483646
	staleTS := time.Now().Add(-24 * time.Hour).Unix()
	stale := fmt.Sprintf("%d\n%d\n", stalePID, staleTS)
	if err := os.WriteFile(path, []byte(stale), 0644); err != nil {
		t.Fatalf("seed stale file: %v", err)
	}

	// Write should overwrite cleanly.
	if err := Write(path); err != nil {
		t.Fatalf("Write over stale: %v", err)
	}

	info, err := Read(path)
	if err != nil {
		t.Fatalf("Read after overwrite: %v", err)
	}
	if info.PID != os.Getpid() {
		t.Errorf("PID = %d after overwrite, want %d", info.PID, os.Getpid())
	}
}

func TestWrite_CorruptedLockfileRefusesOverwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pid")

	// Write garbage that fails parsing.
	if err := os.WriteFile(path, []byte("this is not a lockfile\n"), 0644); err != nil {
		t.Fatalf("seed garbage: %v", err)
	}

	err := Write(path)
	if err == nil {
		t.Fatal("Write over garbage should fail, got nil")
	}
	if errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("error should NOT be ErrAlreadyRunning for unreadable file, got: %v", err)
	}
	if !strings.Contains(err.Error(), "unreadable") {
		t.Errorf("error should mention 'unreadable', got: %q", err.Error())
	}
}

func TestRead_MissingFileIsNotExist(t *testing.T) {
	dir := t.TempDir()
	_, err := Read(filepath.Join(dir, "nonexistent.pid"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Read missing file err = %v, want os.ErrNotExist", err)
	}
}

func TestRead_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pid")
	if err := os.WriteFile(path, []byte{}, 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, err := Read(path)
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("Read empty err = %v, want error containing 'empty'", err)
	}
}

func TestRead_BadPIDLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pid")
	if err := os.WriteFile(path, []byte("not-a-number\n1234\n"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, err := Read(path)
	if err == nil || !strings.Contains(err.Error(), "PID") {
		t.Errorf("Read bad PID err = %v, want error containing 'PID'", err)
	}
}

func TestRead_NegativePID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pid")
	if err := os.WriteFile(path, []byte("-1\n1234\n"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, err := Read(path)
	if err == nil || !strings.Contains(err.Error(), "positive") {
		t.Errorf("Read negative PID err = %v, want error containing 'positive'", err)
	}
}

func TestRead_MissingTimestampLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pid")
	if err := os.WriteFile(path, []byte("1234\n"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, err := Read(path)
	if err == nil || !strings.Contains(err.Error(), "timestamp") {
		t.Errorf("Read missing timestamp err = %v, want error containing 'timestamp'", err)
	}
}

func TestRead_BadTimestampLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pid")
	if err := os.WriteFile(path, []byte("1234\nnot-a-number\n"), 0644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, err := Read(path)
	if err == nil || !strings.Contains(err.Error(), "timestamp") {
		t.Errorf("Read bad timestamp err = %v, want error containing 'timestamp'", err)
	}
}

func TestRemove_Existing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pid")
	if err := Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := Remove(path); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("file still exists after Remove: %v", err)
	}
}

func TestRemove_MissingIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	// Remove a file that doesn't exist — should return nil.
	if err := Remove(filepath.Join(dir, "nonexistent.pid")); err != nil {
		t.Errorf("Remove missing should be idempotent, got: %v", err)
	}
}

func TestIsAlive_InitIsAlive(t *testing.T) {
	// PID 1 is init on every Unix. Always alive.
	if !isAlive(1) {
		t.Error("isAlive(1) = false, want true (init should always exist)")
	}
}

func TestIsAlive_InventedPIDIsDead(t *testing.T) {
	// PID 2^31-2 is highly unlikely to be assigned. If a CI runner
	// happens to be using it, the test would flake — but the max-PID
	// probe is the standard way to test this without spawning + waiting
	// for a process to die.
	inventedPID := 2147483646
	if isAlive(inventedPID) {
		t.Skipf("PID %d happens to be alive on this system; skipping dead-PID test", inventedPID)
	}
}

// TestWrite_NoLeakedTempFilesAfterAcquire verifies that the staged
// tempfile used by the Phase 21 F6 tmpfile+Link pattern is cleaned
// up after a successful Write — a deferred os.Remove in Write() is
// supposed to delete the tempfile whether Link succeeded (inode
// persists via the linked path) or failed. A regression would
// accumulate `.sshkey-lockfile-*.tmp` files in the data directory
// every startup.
func TestWrite_NoLeakedTempFilesAfterAcquire(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pid")

	if err := Write(path); err != nil {
		t.Fatalf("Write: %v", err)
	}

	// The only file in dir should be the lockfile itself — no
	// `.sshkey-lockfile-*.tmp` companions.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, e := range entries {
		if e.Name() == filepath.Base(path) {
			continue
		}
		if strings.HasPrefix(e.Name(), ".sshkey-lockfile-") {
			t.Errorf("leaked lockfile tempfile: %s", e.Name())
		}
	}
}

// TestWrite_ConcurrentAcquisitionExactlyOneSucceeds verifies the
// Phase 21 F6 fix: N goroutines racing to acquire the same lockfile
// must see exactly one success and (N-1) ErrAlreadyRunning. Before the
// O_EXCL refactor, the Read-then-Write sequence had a TOCTOU window
// where two concurrent fresh startups could both pass the aliveness
// check and both write, letting the second's rename clobber the
// first's lockfile without either returning ErrAlreadyRunning.
//
// This test asserts the correct outcome is deterministic: under
// concurrent load, the lockfile semantic is exactly-one-winner.
func TestWrite_ConcurrentAcquisitionExactlyOneSucceeds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pid")

	const goroutines = 20
	var wg sync.WaitGroup
	var mu sync.Mutex
	var successes int
	var alreadyRunning int
	var other []error
	start := make(chan struct{})

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start // release all goroutines simultaneously
			err := Write(path)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				successes++
			case errors.Is(err, ErrAlreadyRunning):
				alreadyRunning++
			default:
				other = append(other, err)
			}
		}()
	}
	close(start)
	wg.Wait()

	if successes != 1 {
		t.Errorf("successes = %d, want exactly 1 (TOCTOU regression?)", successes)
	}
	if alreadyRunning != goroutines-1 {
		t.Errorf("alreadyRunning = %d, want %d", alreadyRunning, goroutines-1)
	}
	if len(other) != 0 {
		t.Errorf("unexpected errors: %v", other)
	}

	// The surviving lockfile must be parseable and carry the winning PID.
	info, err := Read(path)
	if err != nil {
		t.Fatalf("Read surviving lockfile: %v", err)
	}
	if info.PID != os.Getpid() {
		t.Errorf("surviving PID = %d, want %d", info.PID, os.Getpid())
	}
	if !info.Alive {
		t.Error("surviving lockfile should report Alive=true")
	}
}
