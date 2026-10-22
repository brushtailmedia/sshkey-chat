package store

// Write-burst benchmark for the SQLite WAL store — answers "where are the
// write ceilings?" with the PRODUCTION statements (insertMessage via a real
// room file's schema, SetReadPosition via a real Store) against a fresh file
// per scenario, on whichever disk SSHKEY_BENCH_DIR points at (default: the OS
// temp dir, which is LOCAL disk — never benchmark on a network volume).
//
// Env-gated so the normal suite never pays for it:
//
//	SSHKEY_WRITE_BENCH=1 $GO test ./internal/store -run TestWriteBurstReport -v -count=1 -timeout 30m
//	SSHKEY_BENCH_N=5000        # ops per scenario (default 2000)
//	SSHKEY_BENCH_DIR=/var/tmp  # disk to measure (default: os temp dir)
//
// Scenarios compare synchronous=FULL (today's default: an fsync per commit)
// against synchronous=NORMAL (fsync only at checkpoint), single-transaction
// batching, same-file writer contention, cross-file parallelism (the per-room
// sharding), and the read-receipt amplification into the shared data.db.
//
// macOS caveat: plain fsync does not flush the drive's write cache, so FULL
// looks cheap here; the fullfsync(ON) scenario forces F_FULLFSYNC and
// approximates a Linux ext4/xfs barrier-honoring fsync on the same hardware.

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brushtailmedia/sshkey-chat/internal/sqlitedsn"
)

// benchInsertSQL mirrors insertMessage's statement for the single-transaction
// batch scenario (insertMessage takes a *sql.DB, so it cannot run inside a
// tx). KEEP IN SYNC with messages.go insertMessage.
const benchInsertSQL = `
		INSERT INTO messages (id, sender, ts, epoch, payload, file_ids, signature, wrapped_keys)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`

// ~600 bytes of base64-looking payload: a realistic encrypted chat line.
var benchPayload = strings.Repeat("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo", 20)

type benchResult struct {
	name  string
	ops   int
	total time.Duration
	lats  []time.Duration
}

func (r benchResult) pct(p float64) time.Duration {
	if len(r.lats) == 0 {
		return 0
	}
	sorted := make([]time.Duration, len(r.lats))
	copy(sorted, r.lats)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

func (r benchResult) line() string {
	ops := float64(r.ops) / r.total.Seconds()
	return fmt.Sprintf("%-44s %6d ops  %9s  %9.0f ops/s  p50 %-9s p99 %-9s max %-9s",
		r.name, r.ops, r.total.Round(time.Millisecond), ops,
		r.pct(0.50).Round(time.Microsecond), r.pct(0.99).Round(time.Microsecond), r.pct(1.0).Round(time.Microsecond))
}

func benchN(t *testing.T) int {
	t.Helper()
	if v := os.Getenv("SSHKEY_BENCH_N"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 100 {
			t.Fatalf("SSHKEY_BENCH_N=%q: want an integer >= 100", v)
		}
		return n
	}
	return 2000
}

func benchDir(t *testing.T) string {
	t.Helper()
	base := os.Getenv("SSHKEY_BENCH_DIR")
	dir, err := os.MkdirTemp(base, "sshkey-writeburst-")
	if err != nil {
		t.Fatalf("mkdtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func benchRoomID(k int) string { return fmt.Sprintf("room_bench%016d", k) }

func benchMsg(i int) StoredMessage {
	return StoredMessage{
		ID:        fmt.Sprintf("msg_bench%016d", i),
		Sender:    "usr_bench_sender",
		TS:        time.Now().Unix(),
		Epoch:     1,
		Payload:   benchPayload,
		Signature: "c2lnbmF0dXJlLWJlbmNo",
	}
}

// openBenchDB opens path exactly as the store does (sqlitedsn.Writable +
// WAL + foreign_keys) plus any extra `_pragma=` settings applied to every
// pooled connection — the only correct way to change synchronous or fullfsync.
func openBenchDB(t *testing.T, path string, pragmas ...string) *sql.DB {
	t.Helper()
	dsn, err := sqlitedsn.Writable(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(pragmas) > 0 {
		u, err := url.Parse(dsn)
		if err != nil {
			t.Fatal(err)
		}
		q := u.Query()
		for _, p := range pragmas {
			q.Add("_pragma", p)
		}
		u.RawQuery = q.Encode()
		dsn = u.String()
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"PRAGMA journal_mode=WAL", "PRAGMA foreign_keys=ON"} {
		if _, err := db.Exec(p); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
	return db
}

// newRoomFiles creates k room DBs with the PRODUCTION schema (via a real
// Store's RoomDB), closes the store, and returns their paths so scenarios can
// reopen them with controlled pragmas.
func newRoomFiles(t *testing.T, dir string, k int) []string {
	t.Helper()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	paths := make([]string, 0, k)
	for i := 0; i < k; i++ {
		id := benchRoomID(i)
		if _, err := s.RoomDB(id); err != nil {
			t.Fatalf("RoomDB: %v", err)
		}
		paths = append(paths, filepath.Join(s.dir, fmt.Sprintf("room-%s.db", id)))
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return paths
}

func runSeq(name string, n int, op func(i int) error) (benchResult, error) {
	r := benchResult{name: name, ops: n, lats: make([]time.Duration, 0, n)}
	start := time.Now()
	for i := 0; i < n; i++ {
		t0 := time.Now()
		if err := op(i); err != nil {
			return r, fmt.Errorf("%s op %d: %w", name, i, err)
		}
		r.lats = append(r.lats, time.Since(t0))
	}
	r.total = time.Since(start)
	return r, nil
}

// runConc partitions n ops across g goroutines (op receives a global index).
func runConc(name string, n, g int, op func(i int) error) (benchResult, error) {
	r := benchResult{name: name, ops: n}
	per := n / g
	lats := make([][]time.Duration, g)
	errs := make([]error, g)
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < g; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			mine := make([]time.Duration, 0, per)
			for j := 0; j < per; j++ {
				i := w*per + j
				t0 := time.Now()
				if err := op(i); err != nil {
					errs[w] = fmt.Errorf("%s worker %d op %d: %w", name, w, i, err)
					return
				}
				mine = append(mine, time.Since(t0))
			}
			lats[w] = mine
		}(w)
	}
	wg.Wait()
	r.total = time.Since(start)
	for _, e := range errs {
		if e != nil {
			return r, e
		}
	}
	for _, l := range lats {
		r.lats = append(r.lats, l...)
	}
	r.ops = len(r.lats)
	return r, nil
}

func TestWriteBurstReport(t *testing.T) {
	if os.Getenv("SSHKEY_WRITE_BENCH") == "" {
		t.Skip("write-burst benchmark: set SSHKEY_WRITE_BENCH=1 to run")
	}
	n := benchN(t)
	dir := benchDir(t)
	const writers = 16
	const readers = 50

	var results []benchResult
	record := func(r benchResult, err error) {
		if err != nil {
			t.Fatal(err)
		}
		results = append(results, r)
		t.Log(r.line())
	}

	t.Logf("write-burst benchmark: %s/%s %s | dir=%s | N=%d | %d concurrent writers | %d readers",
		runtime.GOOS, runtime.GOARCH, runtime.Version(), dir, n, writers, readers)

	// ---- A. one room file: synchronous mode + batching + contention ----
	rooms := newRoomFiles(t, filepath.Join(dir, "a"), 6)
	{
		db := openBenchDB(t, rooms[0])
		defer db.Close()
		record(runSeq("A1 room insert | FULL (today) | 1 writer", n, func(i int) error {
			_, err := insertMessage(db, benchMsg(i))
			return err
		}))
	}
	{
		db := openBenchDB(t, rooms[1], "fullfsync(ON)")
		defer db.Close()
		ff := n / 4 // true-durability fsync is slow by design; keep the run short
		record(runSeq("A2 room insert | FULL+fullfsync | 1 writer", ff, func(i int) error {
			_, err := insertMessage(db, benchMsg(i))
			return err
		}))
	}
	{
		db := openBenchDB(t, rooms[2], "synchronous(NORMAL)")
		defer db.Close()
		record(runSeq("A3 room insert | NORMAL | 1 writer", n, func(i int) error {
			_, err := insertMessage(db, benchMsg(i))
			return err
		}))
	}
	{
		db := openBenchDB(t, rooms[3])
		defer db.Close()
		r := benchResult{name: "A4 room insert | FULL | 1 tx batch of N", ops: n}
		start := time.Now()
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < n; i++ {
			m := benchMsg(i)
			if _, err := tx.Exec(benchInsertSQL, m.ID, m.Sender, m.TS, m.Epoch, m.Payload,
				encodeStringSlice(m.FileIDs), m.Signature, encodeMap(m.WrappedKeys)); err != nil {
				t.Fatal(err)
			}
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		r.total = time.Since(start)
		r.lats = []time.Duration{r.total / time.Duration(n)} // amortized per-op cost
		record(r, nil)
	}
	{
		db := openBenchDB(t, rooms[4])
		defer db.Close()
		record(runConc(fmt.Sprintf("A5 room insert | FULL | %d writers same file", writers), n, writers, func(i int) error {
			_, err := insertMessage(db, benchMsg(i))
			return err
		}))
	}
	{
		db := openBenchDB(t, rooms[5], "synchronous(NORMAL)")
		defer db.Close()
		record(runConc(fmt.Sprintf("A6 room insert | NORMAL | %d writers same file", writers), n, writers, func(i int) error {
			_, err := insertMessage(db, benchMsg(i))
			return err
		}))
	}

	// A7/A8: the simplest candidate fix — serialize writers to one file in Go
	// (one mutex per file) so contention becomes a fair FIFO wait instead of
	// SQLite's busy-handler sleep ladder. Same ops, same files, same pool.
	for _, v := range []struct {
		name    string
		pragmas []string
	}{
		{"A7 room insert | FULL | 16 writers + Go write mutex", nil},
		{"A8 room insert | NORMAL | 16 writers + Go write mutex", []string{"synchronous(NORMAL)"}},
	} {
		extra := newRoomFiles(t, filepath.Join(dir, "a-"+v.name[:2]), 1)
		db := openBenchDB(t, extra[0], v.pragmas...)
		defer db.Close()
		var mu sync.Mutex
		record(runConc(v.name, n, writers, func(i int) error {
			mu.Lock()
			defer mu.Unlock()
			_, err := insertMessage(db, benchMsg(i))
			return err
		}))
	}

	// ---- B. the per-room sharding: 8 files, one writer each ----
	{
		const k = 8
		shards := newRoomFiles(t, filepath.Join(dir, "b"), k)
		dbs := make([]*sql.DB, k)
		for i := range shards {
			dbs[i] = openBenchDB(t, shards[i])
			defer dbs[i].Close()
		}
		per := n / k
		record(runConc(fmt.Sprintf("B1 %d rooms | FULL | 1 writer each (aggregate)", k), n, k, func(i int) error {
			_, err := insertMessage(dbs[i/per], benchMsg(i))
			return err
		}))
	}

	// ---- C. read receipts into the SHARED data.db (production SetReadPosition) ----
	roomForReceipts := benchRoomID(0)
	msgID := func(m int) string { return fmt.Sprintf("msg_bench%016d", m) }
	perReader := n / readers
	{
		s, err := Open(filepath.Join(dir, "c1"))
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		record(runSeq(fmt.Sprintf("C1 read_positions | FULL | %d readers sequential", readers), perReader*readers, func(i int) error {
			m, r := i/readers, i%readers
			return s.SetReadPosition(fmt.Sprintf("usr_reader%02d", r), fmt.Sprintf("dev_reader%02d", r), roomForReceipts, "", "", msgID(m))
		}))
	}
	{
		s, err := Open(filepath.Join(dir, "c2"))
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		// Swap data.db's handle for one whose every connection runs NORMAL.
		nd := openBenchDB(t, filepath.Join(s.dir, "data.db"), "synchronous(NORMAL)")
		old := s.dataDB
		s.dataDB = nd
		_ = old.Close()
		record(runSeq(fmt.Sprintf("C2 read_positions | NORMAL | %d readers sequential", readers), perReader*readers, func(i int) error {
			m, r := i/readers, i%readers
			return s.SetReadPosition(fmt.Sprintf("usr_reader%02d", r), fmt.Sprintf("dev_reader%02d", r), roomForReceipts, "", "", msgID(m))
		}))
	}
	{
		s, err := Open(filepath.Join(dir, "c3"))
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		record(runConc(fmt.Sprintf("C3 read_positions | FULL | %d reader goroutines", readers), perReader*readers, readers, func(i int) error {
			r, m := i/perReader, i%perReader
			return s.SetReadPosition(fmt.Sprintf("usr_reader%02d", r), fmt.Sprintf("dev_reader%02d", r), roomForReceipts, "", "", msgID(m))
		}))
	}
	{
		s, err := Open(filepath.Join(dir, "c4"))
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		nd := openBenchDB(t, filepath.Join(s.dir, "data.db"), "synchronous(NORMAL)")
		old := s.dataDB
		s.dataDB = nd
		_ = old.Close()
		record(runConc(fmt.Sprintf("C4 read_positions | NORMAL | %d reader goroutines", readers), perReader*readers, readers, func(i int) error {
			r, m := i/perReader, i%perReader
			return s.SetReadPosition(fmt.Sprintf("usr_reader%02d", r), fmt.Sprintf("dev_reader%02d", r), roomForReceipts, "", "", msgID(m))
		}))
	}

	// C5/C6: the same Go write mutex applied to the shared data.db.
	for _, v := range []struct {
		name   string
		normal bool
	}{
		{"C5 read_positions | FULL | 50 goroutines + Go write mutex", false},
		{"C6 read_positions | NORMAL | 50 goroutines + Go write mutex", true},
	} {
		s, err := Open(filepath.Join(dir, "c-"+v.name[:2]))
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if v.normal {
			nd := openBenchDB(t, filepath.Join(s.dir, "data.db"), "synchronous(NORMAL)")
			old := s.dataDB
			s.dataDB = nd
			_ = old.Close()
		}
		var mu sync.Mutex
		record(runConc(v.name, perReader*readers, readers, func(i int) error {
			r, m := i/perReader, i%perReader
			mu.Lock()
			defer mu.Unlock()
			return s.SetReadPosition(fmt.Sprintf("usr_reader%02d", r), fmt.Sprintf("dev_reader%02d", r), roomForReceipts, "", "", msgID(m))
		}))
	}

	t.Log("---- summary ----")
	for _, r := range results {
		t.Log(r.line())
	}
}
