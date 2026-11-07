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
//	SSHKEY_BENCH_UNCAPPED=1    # open every handle with an uncapped pool (the
//	                           # pre-Part-1 behaviour) to reproduce the baseline
//
// Scenarios compare synchronous=FULL (today's default: an fsync per commit)
// against synchronous=NORMAL (fsync only at checkpoint), single-transaction
// batching, same-file writer contention, cross-file parallelism (the per-room
// sharding), the read-receipt amplification into the shared data.db, and
// (D1) writers and history readers sharing one file — the cost of the
// one-connection cap, which serialises reads behind writes that WAL would
// otherwise let overlap.
//
// Since store-write Part 1 every handle the store opens is capped at one
// connection (store.go openDB). openBenchDB applies the same cap so the
// matrix measures production behaviour; SSHKEY_BENCH_UNCAPPED=1 removes it
// everywhere (and the C scenarios swap the Store's data.db handle for a
// bench-opened one so the knob reaches them too).
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
// batch scenario (insertMessage takes a *DB, so it cannot run inside a
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

// benchCapped reports whether handles get the production one-connection cap
// (default) or an uncapped pool (SSHKEY_BENCH_UNCAPPED=1, the pre-Part-1
// behaviour, for reproducing the baseline).
func benchCapped() bool { return os.Getenv("SSHKEY_BENCH_UNCAPPED") == "" }

// openBenchDB opens path exactly as the store does (sqlitedsn.Writable +
// WAL + foreign_keys + the Part 1 handle: a one-connection pool and the
// write mutex, unless SSHKEY_BENCH_UNCAPPED=1) plus any extra `_pragma=`
// settings applied to every pooled connection — the only correct way to
// change synchronous or fullfsync.
func openBenchDB(t *testing.T, path string, pragmas ...string) *DB {
	t.Helper()
	return openBenchDBWith(t, path, benchCapped(), pragmas...)
}

// openBenchDBWith is openBenchDB with the Part 1 handle chosen explicitly
// (capped pool + serialised writes, or the raw pre-Part-1 pool), for the
// scenarios that compare the two in one run.
func openBenchDBWith(t *testing.T, path string, capped bool, pragmas ...string) *DB {
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
	if capped {
		db.SetMaxOpenConns(handleConns)
		db.SetMaxIdleConns(handleConns)
	}
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		t.Fatalf("assert WAL: %v", err)
	}
	var fk int
	if err := db.QueryRow("PRAGMA foreign_keys").Scan(&fk); err != nil || fk != 1 {
		t.Fatalf("foreign keys not enabled by the DSN: fk=%d err=%v", fk, err)
	}
	return newDB(db, capped)
}

// swapDataDB replaces a Store's data.db handle with a bench-opened one, so
// the C scenarios honour the cap knob (the Store's own handle is always
// capped since Part 1) and can carry extra pragmas.
func swapDataDB(t *testing.T, s *Store, pragmas ...string) {
	t.Helper()
	nd := openBenchDB(t, filepath.Join(s.dir, "data.db"), pragmas...)
	old := s.dataDB
	s.dataDB = nd
	_ = old.Close()
}

// capLabel names the pool mode in scenario titles and the header line.
func capLabel(capped bool) string {
	if capped {
		return "capped"
	}
	return "uncapped"
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

	t.Logf("write-burst benchmark: %s/%s %s | dir=%s | N=%d | %d concurrent writers | %d readers | pool %s",
		runtime.GOOS, runtime.GOARCH, runtime.Version(), dir, n, writers, readers, capLabel(benchCapped()))

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

	// (A9, the cap plus an outer Go write mutex, was measured on 2026-11-08
	// while choosing the handle's shape — 2.7 ms worst case against 8–12 ms
	// for the cap alone — and is now what every capped handle is, so A5
	// capped IS that shape and A9 is retired. See the results doc.)

	// ---- B. the per-room sharding: 8 files, one writer each ----
	{
		const k = 8
		shards := newRoomFiles(t, filepath.Join(dir, "b"), k)
		dbs := make([]*DB, k)
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
		swapDataDB(t, s)
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
		swapDataDB(t, s, "synchronous(NORMAL)")
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
		swapDataDB(t, s)
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
		swapDataDB(t, s, "synchronous(NORMAL)")
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
			swapDataDB(t, s, "synchronous(NORMAL)")
		} else {
			swapDataDB(t, s)
		}
		var mu sync.Mutex
		record(runConc(v.name, perReader*readers, readers, func(i int) error {
			r, m := i/perReader, i%perReader
			mu.Lock()
			defer mu.Unlock()
			return s.SetReadPosition(fmt.Sprintf("usr_reader%02d", r), fmt.Sprintf("dev_reader%02d", r), roomForReceipts, "", "", msgID(m))
		}))
	}

	// (C7, the cap plus an outer Go write mutex on data.db, was likewise
	// measured on 2026-11-08 and retired: C3 capped is now that shape.)

	// ---- D. mixed: writers and history readers on ONE room file ----
	// The cost of the one-connection handle is that a read waits behind
	// writes to the same file (WAL would let them overlap). D1 measures it:
	// 16 writers insert N messages while 4 readers page history through the
	// production pager (getHistoryBefore, a 100-row page below a cursor) as
	// fast as they can, with the two populations reported separately. Each
	// file is seeded with 300 rows so the cursor resolves and a full page
	// exists before the first write. Four handle shapes: the production one
	// (a pool of handleConns, serialised writes), the same with a single
	// connection, the raw pre-Part-1 pool, and a pool of 4 with serialised
	// writes — the measurement that chose handleConns.
	for _, mode := range []struct {
		label     string
		serialize bool
		pool      int // 0 = leave as openBenchDBWith set it
	}{
		{"capped (production)", true, 0},
		{"pool 1 + write mutex", true, 1},
		{"uncapped", false, 0},
		{"pool 4 + write mutex", true, 4},
	} {
		files := newRoomFiles(t, filepath.Join(dir, "d-"+strings.NewReplacer(" ", "_", "(", "", ")", "").Replace(mode.label)), 1)
		db := openBenchDBWith(t, files[0], mode.serialize)
		if mode.pool > 0 {
			db.SetMaxOpenConns(mode.pool)
			db.SetMaxIdleConns(mode.pool)
		}
		defer db.Close()
		capLabelFor := func() string { return mode.label }
		const seed = 300
		for i := 0; i < seed; i++ {
			if _, err := insertMessage(db, benchMsg(1_000_000+i)); err != nil {
				t.Fatal(err)
			}
		}
		cursor := benchMsg(1_000_000 + seed - 50).ID // 250 rows below it: a full page
		const historyReaders = 4
		stop := make(chan struct{})
		readerLats := make([][]time.Duration, historyReaders)
		readerErrs := make([]error, historyReaders)
		var rwg sync.WaitGroup
		for r := 0; r < historyReaders; r++ {
			rwg.Add(1)
			go func(r int) {
				defer rwg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					t0 := time.Now()
					msgs, _, ok, err := getHistoryBefore(db, cursor, "", nil, 100)
					if err != nil || !ok || len(msgs) != 100 {
						readerErrs[r] = fmt.Errorf("history reader %d: err=%v ok=%v rows=%d", r, err, ok, len(msgs))
						return
					}
					readerLats[r] = append(readerLats[r], time.Since(t0))
				}
			}(r)
		}
		w, err := runConc(fmt.Sprintf("D1w room insert | FULL | %d writers + %d history readers | %s", writers, historyReaders, capLabelFor()), n, writers, func(i int) error {
			_, err := insertMessage(db, benchMsg(i))
			return err
		})
		close(stop)
		rwg.Wait()
		record(w, err)
		for _, e := range readerErrs {
			if e != nil {
				t.Fatal(e)
			}
		}
		rr := benchResult{name: fmt.Sprintf("D1r history page(100) | %d readers while %d write | %s", historyReaders, writers, capLabelFor()), total: w.total}
		for _, l := range readerLats {
			rr.lats = append(rr.lats, l...)
		}
		rr.ops = len(rr.lats)
		record(rr, nil)
	}

	t.Log("---- summary ----")
	for _, r := range results {
		t.Log(r.line())
	}
}
