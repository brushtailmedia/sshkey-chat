# Auto-revoke operations runbook

Phase 17b shipped an auto-revoke breaker that watches per-device
misbehavior counters and revokes devices that sustain threshold
crossings. This runbook covers what operators need to know.

## What auto-revoke does

When a client device produces too many misbehavior signals within a
configured time window, the server:

1. Enqueues a row in `pending_device_revocations` with
   `revoked_by = "server:auto_revoke"` and a human-readable reason.
2. The existing device-revocation processor drains the queue on its
   next 5-second tick: marks the device revoked in `revoked_devices`,
   sends a `device_revoked` event to any active session, closes the
   SSH channel.
3. Emits a structured `auto_revoke` log line at `Warn` level with
   device ID, user, signal name, count, window, and reason.
4. Writes an audit-log row tagged `auto-revoke-device` so
   `sshkey-ctl audit-log` output includes the revocation.

The revoked device cannot reconnect until an admin restores it.
Other devices belonging to the same user are **unaffected** — only
the specific `device_id` is blocked.

## The signal categories

Every counter signal falls into one of three categories:

**Misbehavior** (auto-revoke-eligible, zero legitimate baseline):
- `malformed_frame` — JSON parse failures
- `oversized_body` — payload exceeds `messages.max_body_size`
- `unknown_verb` — unrecognized protocol verb
- `invalid_nanoid` — malformed room/group/dm ID shape
- `invalid_content_hash` — `upload_start` hash doesn't match `blake2b-256:` format
- `oversized_upload_frame` — Channel 3 frame exceeds limits
- `wrapped_keys_over_cap` — per-message key envelope too large
- `file_ids_over_cap` — attachment list exceeds `files.max_file_ids_per_message`
- `non_member_context` — request to a room/group/dm the device isn't in
- `download_not_found` — download ACL-deny / cascade race / server I/O error (privacy-identical response)
- `download_no_channel` — `download` verb before Channel 2 open
- `reconnect_flood` — session-setup thrashing

**Load** (counted for observability; NEVER auto-revoke inputs — legitimate clients produce these under normal bursty usage):
- `rate_limited`

**Observational** (server-internal; NEVER auto-revoke inputs — slow
clients can produce these through no misbehavior of their own):
- `broadcast_dropped`

The config loader rejects any attempt to put a load or observational
signal in the `[server.auto_revoke.thresholds]` table with a
category-tagged error at startup.

## Configuration

See `docker/config/server.toml` for the full reference. Minimal example:

```toml
[server.auto_revoke]
enabled = true
prune_after_hours = 168

[server.auto_revoke.thresholds]
malformed_frame      = "3:60"
invalid_nanoid       = "5:60"
reconnect_flood      = "10:60"
```

**Threshold format:** `"count:window_seconds"`. Device crosses the
threshold when it produces `count` events within the last
`window_seconds` seconds (sliding window).

**Omit a signal** to disable checking for it. An empty thresholds
table with `enabled = true` produces a startup warning ("breaker is
on but has no triggers configured") but is otherwise valid — useful
for incrementally tuning.

**prune_after_hours** is the TTL for stale counter entries. Must be
strictly greater than the largest configured window, converted to
hours (rounded up). `0` disables TTL-based pruning entirely
(entries persist until server restart).

## Monitoring

Every auto-revoke firing emits:

```
level=WARN msg=auto_revoke device=dev_xxx user=usr_xxx
  signal=malformed_frame count=3 window=60
  reason="Automatic revocation: too many malformed frames (3 events in 60s)"
```

Observer-mode (enabled=false) firings emit at `Info`:

```
level=INFO msg=auto_revoke_would_fire device=dev_xxx ...
```

And audit log:

```
sshkey-ctl audit-log --limit 20
# ... server:auto_revoke   auto-revoke-device   user=usr_xxx device=dev_xxx signal=... reason=...
```

Programmatic snapshot of current counter state:

```go
snap := server.counters.Snapshot()
// map[string]map[string]int64 — signal → device → count
```

(Exposed via `Snapshot()` method on the counters package; the
pre-launch dev-tooling CLI that wraps this is not yet shipped.)

## Disabling auto-revoke

Set `enabled = false` in `[server.auto_revoke]` and restart the
server. The goroutine keeps running and keeps evaluating — every
would-fire now logs at `Info` with the `auto_revoke_would_fire`
message name. Operator sees exactly what the breaker would do
without any devices actually being revoked.

**Already-revoked devices stay revoked.** Flipping `enabled = false`
only stops future auto-revocations; historical ones are not undone.

**When to reach for this switch:**
- Multiple legitimate users auto-revoked in a short window (suggests
  a client bug surfacing; disable while diagnosing)
- A known-bad client version is in the wild (disable while waiting
  for client update to roll out)
- Initial investigation of a new signal's behavior in production

## Restoring a revoked device

```bash
sshkey-ctl restore-device --user USER --device DEV
```

This:
1. Deletes the row from `revoked_devices`, unblocking future logins.
2. Writes an audit-log row tagged `restore-device`.

The in-memory counters for the device are **not** cleared — they
will age out via the TTL (`prune_after_hours`). If you want to reset
immediately, restart the server (counters are in-memory only).

## Admin recovery — structural, not configured

If an admin's device is auto-revoked (client bug, legitimate bulk
operation that tripped a threshold, operator misconfiguration), they
lose chat access from that device but **retain OS-level SSH access
to the server host**. From there they run `sshkey-ctl` directly
against the SQLite files:

```bash
ssh server-host
sudo -u sshkey-chat sshkey-ctl restore-device --user alice --device dev_self_abc
```

No whitelist code in the server binary, no admin threshold
multipliers in the config. Flat thresholds apply to everyone;
structural OS-SSH access is the admin escape hatch.

## Tuning thresholds post-launch

Initial thresholds in the reference TOML are conservative placeholders.
During the first weeks after launch:

1. **Watch the auto-revoke log lines.** Any firing on a known-legit
   user is actionable — either the client has a bug or the signal
   was miscategorized.
2. **Most likely cause for a false positive: client bug** producing
   the signal accidentally. Fix the client. Thresholds are tight on
   purpose; tolerating legit firings means the signal isn't actually
   zero-baseline.
3. **Stopgap if a client bug is in production**: raise the affected
   threshold temporarily OR set `enabled = false` while a client
   update rolls out.
4. **Once weeks of real traffic confirm zero false positives,
   thresholds may be tightened further** (lower count, shorter
   window).

The underlying assumption — that every auto-revoke signal has a zero
legitimate baseline — is a structural property of the code, but
real-world validation still matters. If observation shows legitimate
users producing a signal repeatedly, the signal needs to move out of
`AutoRevokeSignals` (into observational or load).

## Cascade-failure safety

The earlier Phase 17b design proposed an automatic "global cap" that
would disable the breaker if more than 5% of devices were revoked in
a 60s window. The simplified design drops this in favor of
observability-first operator-manual control:

- Every auto-revoke emits a structured log line
- Operator monitors via log aggregation + `counters.Snapshot()`
- If the breaker misbehaves, operator flips `enabled = false` in
  `server.toml` and restarts

At pre-launch and early post-launch scale this is fine — operators
are hands-on. Revisit if scale grows beyond hands-on ops.

## Related knobs

Two separate Phase 17b knobs also sit under `[rate_limits]` but are
NOT auto-revoke-adjacent. They're connection-hardening primitives:

- `idle_timeout_seconds` — NDJSON-layer idle timeout. If >0, the
  server closes connections that send no protocol frames within the
  window. Disabled by default. Slow-loris defense at the application
  layer (SSH-layer keepalive at 30s already kills dead TCP).
- `per_client_write_buffer_size` (default 256) +
  `consecutive_drop_disconnect_threshold` (default 10) — bounded
  per-client outbound queue + slow-reader disconnect. A device that
  fills its 256-message queue and then accumulates 10 consecutive
  fanOut drops gets its SSH channel closed. Recovery: reconnect +
  sync-catchup (no auto-revoke; the client gets a clean slate).

These three knobs are disconnect-only. They do **not** trigger
auto-revoke. Only `SignalReconnectFlood` (which fires on successful
session setup) plumbs into the auto-revoke pipeline.
