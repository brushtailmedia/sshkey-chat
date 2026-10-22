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
