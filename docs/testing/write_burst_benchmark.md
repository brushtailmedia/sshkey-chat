# Write-burst benchmark (SQLite WAL store)

`internal/store/writeburst_bench_test.go` — an env-gated test that drives the
**production** write statements (`insertMessage` against a real room file's
schema, `SetReadPosition` against a real `Store`) through a fixed scenario
matrix, a fresh database file per scenario, and reports throughput plus
p50/p99/max latency. It is skipped unless `SSHKEY_WRITE_BENCH` is set, so the
normal suite and the coverage guard never pay for it.

```bash
GO=/path/to/go
SSHKEY_WRITE_BENCH=1 $GO test ./internal/store -run TestWriteBurstReport -v -count=1 -timeout 30m
# knobs
SSHKEY_BENCH_N=5000          # ops per scenario (default 2000)
SSHKEY_BENCH_DIR=/var/tmp    # disk to measure (default: OS temp dir — LOCAL disk; never a network volume)
```

Run it on the **deployment disk** before drawing conclusions about fsync cost:
on macOS a plain `fsync` does not flush the drive cache, so `synchronous=FULL`
looks almost free there. The `fullfsync(ON)` scenario forces `F_FULLFSYNC` and
approximates a Linux barrier-honoring fsync on the same hardware.

## Baseline — 2026-10-19, macOS 15.7 / Apple M1 / local APFS SSD, Go 1.26.2, N=2000, ~600-byte payloads

| Scenario | ops/s | p50 | p99 | max |
|---|---|---|---|---|
| A1 room insert, FULL (today's config), 1 writer | 11,800 | 73 µs | 168 µs | 5 ms |
| A2 room insert, FULL + fullfsync (true-durable fsync proxy), 1 writer | **207** | **5.0 ms** | 10 ms | 21 ms |
| A3 room insert, NORMAL, 1 writer | 13,900 | 52 µs | 250 µs | 5 ms |
| A4 room insert, FULL, all N in one transaction | 83,600 | 12 µs (amortized) | — | — |
| A5 room insert, FULL, 16 writers same file | **3,070** | 82 µs | 3.1 ms | **640 ms** |
| A6 room insert, NORMAL, 16 writers same file | **2,350** | 47 µs | 2.2 ms | **843 ms** |
| A7 room insert, FULL, 16 writers + Go write mutex | 11,500 | 1.3 ms | 2.2 ms | **2.7 ms** |
| A8 room insert, NORMAL, 16 writers + Go write mutex | 17,200 | 1.0 ms | 2.7 ms | 3.0 ms |
| B1 8 room files, FULL, 1 writer each (aggregate) | 15,000 | 452 µs | 2.4 ms | 3.8 ms |
| C1 read_positions (data.db), FULL, 50 readers sequential | 11,700 | 52 µs | 137 µs | 16 ms |
| C2 read_positions, NORMAL, 50 readers sequential | 12,000 | 19 µs | 54 µs | 124 ms |
| C3 read_positions, FULL, 50 reader goroutines | **695** | 98 µs | **838 ms** | **2.86 s** |
| C4 read_positions, NORMAL, 50 reader goroutines | 3,650 | 21 µs | 43 ms | 547 ms |
| C5 read_positions, FULL, 50 goroutines + Go write mutex | 13,600 | 2.5 ms | 13 ms | **13.5 ms** |
| C6 read_positions, NORMAL, 50 goroutines + Go write mutex | 39,400 | 1.1 ms | 3.4 ms | 3.4 ms |

(A first run minutes earlier agreed within normal variance: A5 max 741 ms, C3 max 1.76 s.)

## Store-write Part 1 — 2026-11-08, same machine, N=2000

Part 1 changed every handle the store opens (`internal/store/db.go`): the
pool is capped at `handleConns` = 2 connections, and `Exec`/`Begin` take a
per-handle write mutex, so one writer runs at a time and one read can overlap
it. `openBenchDB` opens the same shape; `SSHKEY_BENCH_UNCAPPED=1` opens the
raw pre-Part-1 pool everywhere to reproduce the baseline. Scenario **D1** was
added — 16 writers inserting while 4 readers page history through the
production pager on the same file, reported per population, in four handle
shapes — and the choice of shape was made from its numbers in ten runs.

### The exploration (runs 1–8): cap alone, then cap plus mutex, then pool size

| Shape under test | A5 16 writers, worst op | D1 writers ops/s · worst | D1 readers p99 · worst |
|---|---|---|---|
| uncapped (baseline) | 640 ms | 1,700–3,900 · 430 ms–1.13 s | 1.1 ms · 3–383 ms |
| 1 connection, no mutex | 7.6–11.8 ms | 9,200–9,600 · 11–16 ms (one run 389 ms) | 10–12 ms · 13–14 ms (one run 387 ms) |
| 1 connection + write mutex | 4.7–7.0 ms | 1,700–2,100 · 13–47 ms | 2.6–7.4 ms · 4–32 ms |
| **2 connections + write mutex (chosen)** | 4.7–6.1 ms | **3,400–3,550 · 6.7–8.3 ms** | **1.3–1.4 ms · 1.8–2.7 ms** |
| 4 connections + write mutex | — | 3,300–4,200 · 7.1–11.3 ms | 1.0–1.3 ms · 1.4–2.2 ms |

### As applied (runs 9–10, the chosen shape)

| Scenario | ops/s | p99 | max |
|---|---|---|---|
| A5 room insert, 16 writers same file (was 3,070 / 640 ms) | 11,630–12,420 | 3.3–4.1 ms | **4.7–6.1 ms** |
| A7 room insert, 16 writers + an outer Go mutex (reference) | 12,420–12,430 | 1.8–1.9 ms | 2.7–2.8 ms |
| B1 8 rooms, 1 writer each, aggregate | 19,200–21,350 | 0.9–1.9 ms | 2.2–2.9 ms |
| C3 read_positions, 50 goroutines, FULL (was 695 / 2.86 s) | 5,900–6,000 | 228–234 ms | 228–234 ms |
| C4 read_positions, 50 goroutines, NORMAL | 42,700–43,100 | 2.6–2.7 ms | 2.7–3.2 ms |
| D1 writers, 16 + 4 history readers | 3,400–3,410 | 6.3–6.4 ms | 6.8–7.3 ms |
| D1 readers, 100-row page while 16 write | 6,600–6,670 pages/s | 1.3–1.4 ms | 1.8–2.7 ms |

7. **The cap removes the pathology.** No busy-ladder sleep is left in the
   process: the sixteen-writer worst case fell from 640 ms to about 5 ms at
   the same throughput, and D1's writers from half a second or more to
   7 ms.
8. **The mutex buys the tail.** With the cap alone the worst op was 8–12 ms,
   because `database/sql` hands a freed connection to a *random* waiter;
   `sync.Mutex` goes first-in-first-out after a millisecond, and the
   combination lands within 2 ms of the outer-mutex reference.
9. **Two connections, not one, once reads are in the picture.** With one
   connection and the mutex, the single admitted writer queued behind
   every reader at the pool and writers fell to ~2,000 ops/s with 13–47 ms
   worst waits. A second connection lets a read overlap the writer, as
   WAL allows: writers 3,400 ops/s at 7 ms worst, reads at 2 ms worst,
   nearly the four-connection numbers for half the descriptors. Under a
   continuous read hammer writers get about a quarter of A7's throughput
   — a fairness split that favours reads, which is the right way round for
   a chat server — while both populations' tails stay in single-digit
   milliseconds.
10. **The ~230–300 ms stalls in the C shape are fsync, not scheduling.**
    They appear only under `synchronous=FULL`, never in the NORMAL twins
    (C4, C6, A6, A8 — tight in every run), and they hit every serialisation
    shape, including an outer mutex alone (C5, 413 ms in one run). One op
    pays a long flush and everyone queued behind it pays with it. The C
    shape is the per-viewer receipt upsert into `data.db`, which Part 2
    removes from `data.db`; the NORMAL decision (§ Recommended order, 3) is
    the other lever, to be taken on the deployment disk.

## What it shows

1. **The pure-Go SQLite driver is not a bottleneck.** A4 puts the CPU floor at
   ~12–40 µs per insert — tens of thousands per second per file.
2. **On a disk that honors fsync, `synchronous=FULL` costs ~5 ms per commit
   (A2)** — roughly 200 messages/s per room file on this hardware, likely
   300–1,000/s on Linux SSDs with 1–3 ms fsyncs. `NORMAL` (A3) removes the
   per-commit fsync and is bounded by CPU instead. The A1-vs-A3 gap understates
   this on macOS; measure A2-vs-A3 (or run on Linux) for the real ratio.
3. **Concurrent writers to one file collapse under SQLite's busy handler —
   regardless of sync mode.** 16 goroutines on one room file lose 75% of
   throughput and produce **600–850 ms** worst-case waits (A5/A6); 50 reader
   goroutines on `data.db` lose 94% and produce **multi-second** waits (C3).
   The busy handler retries on a coarse sleep ladder, so contention is unfair
   and spiky. `NORMAL` barely helps (A6, C4): this is lock-wait, not fsync.
4. **A Go-side write mutex per file cures it** (A7, C5): throughput returns to
   the single-writer rate and the worst case drops from seconds to
   `queue depth × op cost` — 2.7 ms for 16 writers, 13 ms for 50. ~250× tail
   reduction for a few lines of code, zero semantic change.
5. **`read_positions` in the shared `data.db` is the worst hot spot in the
   schema.** Every reader's `read` frame is an upsert there, so one message in
   a 50-person room is 1 room-file write plus 50 contending `data.db` writes
   (the C3 pattern) — and each blocked write stalls that reader's session
   goroutine, delaying everything else that session does.
6. **The per-room sharding works** (B1 aggregates across files); `data.db`
   undoes it for receipts.

## Recommended order (pre-launch)

1. Per-file write mutex in `Store` (restores throughput, kills the tail).
2. Coalesce read positions in memory and flush on a short timer / disconnect
   (removes the N× amplification), or shard `read_positions` into the
   per-context files like messages.
3. Decide `synchronous=NORMAL` after running this benchmark on the target
   Linux disk — the trade is that a power loss can drop the last transactions
   since the previous checkpoint (the send queue acks after insert, so an
   acked message could be lost in that window). Durable-fsync throughput is
   the number that decides it.
4. Pool hygiene: cap connections per file and evict idle context handles
   (file-descriptor cliff; not measured here).
5. A batching writer goroutine only if bursts exceed what 1 + 3 deliver —
   A4 shows the ceiling.
