# Security Audit — v0.2.0 Launch

**Date:** 2026-04-19
**Scope:** Phase 21 of the refactor_plan.md. All 13 items executed as
an audit-only pass (no code changes during the audit; findings triaged
here for fix-now / defer / accept decisions).

**Companion docs:**
- `handler_auth_audit.md` — per-handler authentication matrix (Item 1)
- `sql_audit.md` — SQL parameterisation sweep (Item 2)

This is the canonical security-review artefact referenced by the
v0.2.0 launch tag.

---

## Executive summary

**Initial audit surfaced 26 findings across 13 items; follow-up
deep-scans (F3 TOFU investigation + F5 staticcheck triage) added
6 more findings (F27-F32), for a total of 32 active findings.**

Three pre-launch-blocking items are now closed:
- **F1** handleRoomMembers privacy leak (fixed 2026-04-19).
- **F2** Go 1.26.2 toolchain upgrade (fixed 2026-04-19).
- **F5** staticcheck tooling blocker + 28 triaged findings (fixed
  2026-04-19).

Severity distribution (post-close):

| Severity | Count | Status |
|---|---|---|
| Critical | 1 | **Closed** (F1) |
| High | 4 | **All 4 closed** (F2, F3, F4, F5) |
| Medium | 8 | F8, F10, F12 deferred to Phase 22; F27 accepted with documented scope (verification-is-voluntary); F6 + F7 + F9 + F13 closed 2026-04-19; F11 closed 2026-04-19 (documentation) |
| Low | 17 | F14, F15, F17, F18, F23, F31 accepted with documented scope / hygiene; F16, F20, F21, F24, F25 tracked as Phase 22 items; F22, F28, F29, F30 closed 2026-04-19 |
| Info | 1 | F32 (redundant-but-harmless `ClearVerified`) |
| Clean | 5 categories | SQL parameterisation, CLI log leaks, concurrency at target scale, 4/6 pen-test scenarios covered, drift-guard tests |

**Pre-launch blockers:** all three closed. Remaining items are
deferrable to v0.2.1 with documented rationale, or accepted as
documented limitations.

---

## Findings

### Critical

#### F1 — handleRoomMembers breaks byte-identical privacy invariant

- **Location:** `internal/server/session.go:3431-3433` (pre-fix).
- **Detail:** Returned `ErrNotAuthorized` with message
  `"You are not a member of room: " + req.Room` for non-member probes.
  Every other room verb (send/edit/react/pin/unpin) returns
  byte-identical `ErrUnknownRoom` to preserve the Phase 14 invariant.
- **Impact:** Client could enumerate room existence by diffing the
  response byte-for-byte against the unknown-room path.
- **Fix applied 2026-04-19:** Replaced the `ErrNotAuthorized` +
  room-ID-echoing branch with `s.sendUnknownRoom(c)`, matching the
  helper used by `handleEdit` / `handleSend`. The `s.store == nil`
  defensive branch was collapsed into the same path so nil-store and
  non-member produce byte-identical wire bytes.
- **Test:** Added `TestHandleRoomMembers_PrivacyResponsesIdentical`
  in new file `internal/server/room_members_test.go`, modelled on
  `TestHandleEdit_PrivacyResponsesIdentical`. Asserts `bytes.Equal`
  across {unknown room, non-member probe}. Also added
  `TestHandleRoomMembers_MemberHappyPath` as a non-regression guard
  so the privacy fix doesn't accidentally break the normal flow.
- **Post-fix verification:**
  - Both new tests pass.
  - All 5 `TestHandleRoomMembers_*` tests green (3 pre-existing + 2
    new).
  - `go build ./...` + `go vet ./...` clean.
  - Full `-race` suite green.
- **Status:** **Fixed 2026-04-19.**

### High

#### F2 — Go 1.26.1 stdlib CVEs (5 distinct, all fixed in 1.26.2)

- **Tool:** `govulncheck` (installed via `go install
  golang.org/x/vuln/cmd/govulncheck@latest`).
- **Vulnerabilities present in the binary:**
  - `GO-2026-4869` — `archive/tar` unbounded allocation. Reached by
    `validateTarball` at `cmd/sshkey-ctl/restore.go:225`. An attacker
    with filesystem access to the backup directory could craft a tarball
    to OOM the restore process.
  - `GO-2026-4870` — `crypto/tls` unauthenticated KeyUpdate → DoS /
    persistent connection retention. Reached by push paths
    (`internal/push/apns.go`, `internal/push/fcm.go`).
  - `GO-2026-4946` — `crypto/x509` inefficient policy validation.
    Reached by APNs cert chain validation.
  - `GO-2026-4866` — `crypto/x509` case-sensitive excludedSubtrees name
    constraints → auth bypass. Reached by APNs cert chain validation.
  - 1 additional CVE reachable via the same APNs/FCM TLS paths (see
    raw `govulncheck` output for reproduction).
- **Fix applied 2026-04-19:** Both `sshkey-chat` and `sshkey-term`
  upgraded to Go 1.26.2:
  - `go.mod` directive bumped `go 1.25.0` → `go 1.26.2` in both repos.
  - `.github/workflows/ci.yml` + `release.yml` pinned to
    `go-version: "1.26.2"` on both repos.
  - `go mod tidy` applied to `sshkey-term` (pre-existing drift:
    `zxcvbn` moved to direct, `test-go/testify` added transitively).
- **Post-fix verification:**
  - `govulncheck ./...` on `sshkey-chat` → "No vulnerabilities found."
  - `govulncheck ./...` on `sshkey-term` → "No vulnerabilities found."
  - `go build ./...` and `go vet ./...` clean on both.
  - Full `-race` suite green on both (see CHANGELOG entries dated
    2026-04-19).
- **Reproduction:** `cd sshkey-chat && govulncheck ./...` (now clean).
- **Status:** **Fixed 2026-04-19.**

#### F3 — TOFU key-change warning is logs-only, not UI-surfaced

- **Location:** `sshkey-term/internal/client/persist.go:461-478`
  (`StoreProfile`).
- **Detail:** When a peer's long-term key changes, the client detects
  the change, emits a structured `slog.Warn("KEY CHANGE DETECTED", ...)`
  log, and calls `ClearVerified`. **But the TUI never shows the user a
  banner or modal.** The user has no visible signal that their contact's
  key changed — the warning only lands in the client log file.
- **Impact:** Violates the TOFU user-experience contract. A
  man-in-the-middle substituting a key would not be noticed by a user
  who doesn't actively inspect logs.

##### Protocol framing: no-rotation design (clarified 2026-04-19)

Before the scope discussion below, an important architectural
invariant that the initial audit did not surface: **user keys do
not rotate in sshkey-chat.** A user's SSH key IS their identity,
not a credential attached to an identity. There is no rotation
protocol, no "add a new key" flow, no expiry. When a user needs a
new key (device loss, suspected compromise, etc.) the workflow is:

1. Admin runs `sshkey-ctl retire-user <old_user_id>` — retired
   account stays visible in history; display name is suffixed with
   a nanoid (e.g., `alice` → `alice_a1b2`) so the original name
   can be reclaimed.
2. Admin runs `sshkey-ctl approve` to create a NEW user record
   with a new user ID, new key, and the reclaimed display name.

The old and new users are cryptographically distinct — different
user IDs, different keys, different `pinned_keys` rows. **The two
never collide.** Because `pinned_keys` is keyed by user ID (not by
display name), the schema's ON-CONFLICT-CASE fingerprint-mismatch
auto-reset never fires on the retirement+new-account path.

The ON-CONFLICT-CASE clause (`WHEN fingerprint != excluded.fingerprint
THEN verified=0`) only fires when a `PinKey` call lands with a
different fingerprint for an EXISTING user ID. Under the no-rotation
design, that event has exactly three causes: (1) a compromised
server substituting a different key in a `profile` broadcast, (2)
a server bug emitting a corrupted `KeyFingerprint`, (3) local DB
tampering. All three are anomalous — there is no legitimate
"Alice got a new phone" scenario to benign-ify the event.

This reframes F3's modal: the warning is not "tell the user about
a routine change" — it's "tell the user about an anomalous event
that should never occur in normal operation."

##### Findings from the 2026-04-19 deep-scan

A full audit of sshkey-term's fingerprint behaviour was performed
after the initial F3 finding. Key discoveries the initial audit
missed:

- **`KeyWarningModel` already exists** in `sshkey-term/internal/tui/keywarning.go`.
  A complete bordered-dialog renderer with `Show(user, oldFP, newFP)`,
  `Hide`, `IsVisible`; a bubbletea `Update` that handles `a`/`enter` →
  `KeyWarningAcceptMsg` and `d`/`esc` → `KeyWarningDisconnectMsg`.
- **Full app integration** at `tui/app.go`: the model is a field on
  `App`; input routing blocks on `IsVisible` (line 463-467); accept
  handler writes a status-bar confirmation and the pinning-update has
  already happened via `StoreProfile`; disconnect handler calls
  `client.Close()`.
- **Complete verification dialog** (`tui/verify.go`, `VerifyModel`) for
  out-of-band safety-number comparison, already dispatched via the
  existing `/verify` / `/unverify` slash commands.
- **Store layer is complete** — `PinKey` / `GetPinnedKey` /
  `MarkVerified` / `IsVerified` / `ClearVerified` all implemented
  and tested (`TestPinnedKeys_ClearVerifiedOnKeyChange`).
- **`pinned_keys` schema auto-resets `verified = 0`** when the
  fingerprint changes, via an `ON CONFLICT ... CASE WHEN
  fingerprint != excluded.fingerprint THEN 0` clause. The explicit
  `ClearVerified` call in `StoreProfile` is redundant but harmless
  (see F32).
- **The only missing piece** is the dispatch: `StoreProfile` in the
  Client package never sends a `tea.Msg` back to the TUI to call
  `KeyWarningModel.Show`. The Client has no `tea.Program` reference;
  it uses callback-style event handoff (`OnMessage` / `OnError` on
  `client.Config`). Adding an `OnKeyWarning` callback follows the
  idiomatic pattern.

##### Scope options (decide before executing)

**F3.a — The wire-up (minimum viable fix).**
- Add `OnKeyWarning func(user, oldFP, newFP string)` callback to
  `client.Config`. Fire from `StoreProfile` after the existing
  detection+log+`ClearVerified` sequence.
- TUI wires the callback to a `KeyWarningMsg` on the message
  channel. `App.Update` handles `KeyWarningMsg` by calling
  `a.keyWarning.Show(user, oldFP, newFP)` unless another blocking
  modal is visible (in which case defer or queue).
- New test: `TestStoreProfile_KeyChangeFiresWarning` — asserts the
  callback fires with correct arguments on a second `StoreProfile`
  with a different fingerprint.
- Estimated effort: 30-45 minutes.

**F3.b — Safety-number augmentation of the modal.** ~~Originally
proposed alongside F3.a/F3.c.~~ **Dropped 2026-04-19** after
discussion with project owner and re-grounding on the no-rotation
protocol framing. Reasoning:
- Verification is voluntary (F27 rejected). Users who'll verify can
  launch `/verify` after the modal (F29 + F30 provide the surfaces);
  the modal doesn't need to duplicate that workflow.
- Users who won't verify would see safety-number clutter in the
  modal and skip past it. Including the data helps nobody.
- The modal's narrower job under F28 (persistent trust state
  carried by the sidebar badge) is "in-the-moment notification of
  an anomalous event" — not "provide verification UX."

**F3.c — Accept-confirmation nudge.**
- `KeyWarningAcceptMsg` handler currently writes `"New key accepted
  for <displayname>"` to the status bar. Change to `"New key
  accepted for <displayname>. Run /verify <name> to compare safety
  numbers out-of-band."`
- Tiny text change; material UX improvement — users who accept to
  dismiss the modal now have a clear follow-up.
- Estimated effort: ~5 minutes.

**F3.d — Modal copy fix (NEW, added 2026-04-19).** The existing
`KeyWarningModel.View()` reads:

> `<user>'s key has changed since you last communicated. This could
> indicate the server has been compromised or the user's key was
> rotated.`

The "or the user's key was rotated" clause is **false by protocol
design** — keys do not rotate in this app (see "Protocol framing"
above). The current text misleads users into treating the event as
potentially-routine. Fix: replace the second sentence with something
like:

> `Keys do not rotate in this app. A change here indicates a server
> bug, a compromised server, or local DB tampering. If <user> is
> getting a new account (e.g., device loss), the admin retires the
> old account and approves a new one with a different user ID —
> that flow does NOT trigger this warning.`

~10 minutes of text rewriting in `keywarning.go:View()`. No
structural UI changes.

**Revised combined scope: F3.a + F3.c + F3.d.** ~50 minutes total.
F3.b dropped. Pairs with F28 (sidebar badge for verified peers) in
the same sshkey-term release.

##### What remains out of scope for F3

Five adjacent findings surfaced by the deep-scan but NOT part of
F3's minimum closure:

- **F27** — `verified` flag has no send-path teeth. New finding;
  MEDIUM severity.
- **F28** — No sidebar badge for unverified peers. New finding;
  LOW.
- **F29** — `/verify` doesn't use display-name completion like
  `/add`. New finding; LOW.
- **F30** — No `/whois` or `/key` command for peer fingerprint
  display on demand. New finding; LOW.
- **F31** — No `pinned_keys` cleanup for retired users. New
  finding; LOW.
- **F32** — Redundant `ClearVerified` call in `StoreProfile` (schema
  auto-resets on conflict). New finding; INFO.

##### Recommendation

Ship F3.a + F3.c + F3.d as the F3 closure in a coordinated
sshkey-term release, paired with F28 (verified-badge on sidebar).
Total client-side effort: F3 ~50 min + F28 ~1h = ~1.5-2 hours in
one PR. F3.b dropped per the 2026-04-19 scope revision.

- **Fix applied 2026-04-19.** All three scope pieces shipped in one
  sshkey-term PR alongside F28 closure:
  - **F3.a wire-up** — New `OnKeyWarning func(user, oldFP, newFP
    string)` callback on `client.Config` (alongside existing
    `OnMessage` / `OnError`). `StoreProfile` fires the callback on
    detected fingerprint mismatch after `ClearVerified`. The App
    wires a buffered `keyWarnCh chan KeyChangeEvent` (cap 10) in
    `connect()`; the callback does a non-blocking send so the
    client readLoop never stalls on a slow TUI. `waitForMsg`
    extended to select on the new channel alongside `msgCh` /
    `errCh`. `App.Update` dispatches `KeyChangeEvent` to
    `keyWarning.Show(user, oldFP, newFP)` — but defers if another
    modal is visible (verify, quitConfirm, passphrase) since the
    schema-level `ClearVerified` + F28 badge-disappearance already
    carry the state in that case.
  - **F3.c accept nudge** — `KeyWarningAcceptMsg` handler's status
    bar message now includes `"Run /verify <name> to compare
    safety numbers out-of-band."` appended to the confirmation.
  - **F3.d modal copy fix** — `KeyWarningModel.View()` rewritten to
    remove the "or the user's key was rotated" line (false by
    design) and replace with explicit no-rotation framing: "Keys
    do not rotate in this app. A change here indicates a
    compromised server, a server bug, or local DB tampering. If
    <user> is getting a new account (e.g., after device loss), the
    admin retires the old account and approves a new one with a
    different user ID — that flow does NOT trigger this warning."
- **Post-fix verification:** `go build ./...` + `go vet ./...` +
  `staticcheck ./...` clean. Full `-race` suite green on
  sshkey-term (7 packages). 5 new client-package tests cover
  StoreProfile dispatch paths (first-encounter no-fire, same-
  fingerprint no-fire, mismatch fires + state, nil-callback
  no-panic, verified-flag survives repeat). 5 new TUI-package tests
  cover modal copy (`NoRotationFraming` + `HiddenRendersEmpty`),
  accept nudge (`StatusBarIncludesVerifyNudge`), and F28 render
  drift guards (sidebar + infopanel).
- **Status:** **Fixed 2026-04-19.**

#### F4 — Replay / idempotency semantics undocumented

- **Location:** Server has no `seq` counter, no `(device, context, seq)`
  unique constraint. Fresh `msg_<nanoid>` is generated server-side per
  request (`session.go:953`). A client retransmitting an identical
  `Send{Room, Payload, Signature}` produces two distinct server-assigned
  IDs and two broadcasts.
- **Detail:** The original agent audit flagged this as HIGH ("no replay
  protection"), but on review the scoping is more nuanced: duplicate
  sends produce **visibly new rows** (different IDs), not silent
  history mutations. This is the same trade-off as the accepted
  send-path-signature limitation (see F11). Clients dedup by server-
  assigned `id`; the defence against send-spam is the `MessagesPerSecond`
  rate limit, not idempotency.
- **Impact:** A misbehaving client or network-retry storm can pollute
  message history with visible duplicates, but cannot forge silent
  history rewrites. The actually-dangerous variant (edit-path
  substitution) was closed by Phase 21 item 3 (edit-sig msgID binding).
- **Fix applied 2026-04-19.** Added pitfall 9 to the `## Common
  Pitfalls` section of `PROTOCOL.md` covering all five points:
  (a) server assigns a fresh `msg_<nanoid>` per request (no store-
  level dedup); (b) client dedup is by server-assigned `id`;
  (c) retransmits produce visible duplicates (distinct IDs); (d)
  `corr_id` is a client-private correlation tag, explicitly NOT an
  idempotency key; (e) the spam defence is
  `[rate_limits] messages_per_second`, not idempotency. The
  paragraph also documents the design trade-off (visible
  duplicates vs. silent rewrites) and cross-references the send-
  path-signature pitfall (F11 — still pending) and the edit-path
  msgID binding closed by Phase 21 item 3.
- **Test gap:** A drift-guard test asserting that two identical
  sends produce distinct server-assigned IDs would lock in the
  documented contract. Deferred to Phase 22 because a single test
  can cover both this documented claim AND F11's "send creates
  visibly-new rows" claim — the test is natural to land with the
  F11 doc (next up).
- **Original estimate:** ~30 minutes (doc addition + one test
  confirming duplicate-on-retransmit is visibly distinct).
- **Status:** **Fixed 2026-04-19 (documentation).** Drift-guard
  test deferred to Phase 22 (co-located with F11's drift guard).

#### F5 — staticcheck tooling blocker

- **Tool:** `staticcheck` installed at
  `~/.gvm/pkgsets/go1.22.5/global/bin/staticcheck`, version 2025.1.1,
  **built with Go 1.23.7.**
- **Detail:** The project depends on `modernc.org/sqlite` which
  requires Go 1.24+. staticcheck built against an older Go version
  reported "module requires at least go1.24.0" and refused to run.
  This blocked the static-analysis portion of Item 9.
- **Impact:** No staticcheck findings were reported because
  staticcheck didn't run — a tooling gap, not a code gap.
- **Fix applied 2026-04-19.**
  - Rebuilt staticcheck against Go 1.26.2:
    `go install honnef.co/go/tools/cmd/staticcheck@latest`.
    New version: **2026.1 (v0.7.0)**.
  - Reran `staticcheck ./...` on both repos.
  - **28 findings triaged inline:**
    - **2 real bugs fixed:**
      - `sshkey-term/internal/tui/app.go:3900` — useless assignment
        `from := m.From` immediately overwritten on the next line;
        collapsed to a single assignment.
      - `sshkey-chat/cmd/sshkey-server/main_test.go:707` — dead `raw`
        variable from a past refactor; replaced with `_`.
    - **10 dead-code sites removed:**
      - 7 unused SSH-key helpers in `sshkey-chat/internal/config/config.go`
        (`isEd25519Key`, `keyType`, `validateSSHKey`, `parseSSHKey`,
        `splitFields`, `base64Decode`, `base64Std`) — leftover from
        Phase 16 Gap 4 when `users.toml` support was removed. Also
        dropped the now-unused `encoding/base64` import.
      - `itoa` helper in `sshkey-chat/cmd/sshkey-server/main_test.go`.
      - `emojiPickerOverlay` in `sshkey-term/internal/tui/emojipicker.go`.
    - **1 deprecated API fixed:**
      - `sshkey-chat/cmd/sshkey-ctl/restore.go:232` — dropped
        `|| header.Typeflag != tar.TypeRegA` disjunct; Go's tar
        reader normalises TypeRegA to TypeReg on read (SA1019
        deprecated since Go 1.11).
    - **15 stylistic lints fixed:**
      - 9 ST1005 trailing-punctuation sites in `sshkey-chat/cmd/sshkey-ctl/`
        (block.go, bootstrap_admin.go, default_rooms.go, main.go) —
        stripped trailing periods/newlines from error strings.
      - 5 ST1005 capitalised-error sites in
        `sshkey-term/internal/tui/displayname.go`.
      - 1 ST1005 capitalised-error site in
        `sshkey-chat/internal/backup/db.go:95`.
      - 1 S1017 in `sshkey-chat/internal/store/users.go:295` —
        replaced `if strings.HasSuffix { TrimSuffix }` with
        unconditional `TrimSuffix` (same semantics; `TrimSuffix`
        is a no-op when the suffix isn't present).
- **Post-fix verification:**
  - `staticcheck ./...` on both repos → **zero findings**.
  - `go build ./...` + `go vet ./...` clean on both.
  - `go test -count=1 -race ./...` green on both.
- **Reproduction:** `staticcheck ./...` from each repo root.
- **Status:** **Fixed 2026-04-19.**

### Medium

#### F6 — Lockfile TOCTOU race

- **Location:** `internal/lockfile/lockfile.go:71-149` (pre-fix).
- **Detail:** `lockfile.Read()` checked if the existing lockfile's
  PID was alive; if not, the caller proceeded to `lockfile.Write()`
  (atomic temp+rename). Two `Server.New` calls racing could both pass
  the aliveness check before either wrote. The second's rename
  clobbered the first's lockfile; both processes continued running;
  the status command only saw the second PID.
- **Window (pre-fix):** microseconds-to-milliseconds on local
  filesystem; longer over NFS. Required deliberate concurrent startup
  or a narrow orchestration-race to manifest.
- **Impact (pre-fix):** Silent coexistence of two server processes
  against the same data directory. SQLite MVCC prevented corruption
  but per-process caches diverged; one process's writes could be
  invisible to the other's clients until WAL refresh.
- **Severity reassessment 2026-04-19.** On walk-through, this finding
  was closer to LOW than MEDIUM — the realistic scenarios require
  deliberate operator misconfiguration (two `systemctl start` races,
  a `ReadWriteMany` orchestration mount, concurrent admin actions)
  and the blast radius is "brief split-brain until ops notices," not
  data loss or privacy leak. Upgraded to fix-now anyway because the
  primitive swap is cheap.
- **Fix applied 2026-04-19.** Replaced the Read-then-temp-write-then-
  Rename sequence with a tmpfile+Link pattern:
  1. Stage the complete PID + timestamp payload in a
     `.sshkey-lockfile-*.tmp` file in the same directory as `path`
     (same directory ensures `link(2)` stays within one filesystem).
  2. Call `os.Link(tmpName, path)` — POSIX link(2) is atomic and
     returns EEXIST if the target exists. Exactly one of N racing
     processes wins.
  3. The tempfile carries the complete payload BEFORE the Link
     attempt, so readers always see complete content on the linked
     path — no empty-file or partial-content race that a naive
     O_EXCL-on-final-path approach would expose.
  4. Stale-recovery: if Link fails with EEXIST and the existing
     file's PID is dead, remove it and retry Link once. Concurrent
     stale-recovery collisions return `ErrAlreadyRunning` against
     the winning PID rather than looping.
  5. `defer os.Remove(tmpName)` cleans the staging file whether Link
     succeeded (inode persists via the linked path) or failed.
- **New drift-guard test:**
  `TestWrite_ConcurrentAcquisitionExactlyOneSucceeds` —
  20 goroutines race to acquire the same lockfile, asserting exactly
  one returns nil and 19 return `ErrAlreadyRunning`. Pre-fix this test
  would have been flaky or failed silently; post-fix it's
  deterministic via the atomic link(2) primitive. Companion
  `TestWrite_NoLeakedTempFilesAfterAcquire` drift-guards the `defer
  os.Remove(tmpName)` cleanup.
- **Post-fix verification:** All 16 lockfile unit tests pass (14
  existing + 2 new). `go build ./...` + `go vet ./...` +
  `staticcheck ./...` clean. Full `-race` suite green on sshkey-chat
  (12 packages).
- **Status:** **Fixed 2026-04-19.**

#### F7 — handleDownload guard-order inconsistency

- **Location:** `internal/server/filetransfer.go:529+` (pre-fix).
- **Detail:** Peer handlers (`devicemgmt.go:74-91`,
  `edit.go:74-76`) check `s.store == nil` before any store
  dereference. `handleDownload` dereferenced the store via
  `authorizeDownload` without a preceding nil-check. Not a bug in
  production (the server never runs with a nil store), but
  drift-prone.
- **Fix applied 2026-04-19.** Added explicit `s.store == nil`
  guard immediately before the `authorizeDownload` call in
  `handleDownload`. On the nil branch the handler calls
  `respondDownloadError(c, corrID, fileID, "not_found", ...)` —
  identical wire shape to the ACL-deny and file-missing paths,
  preserving the privacy-uniform response invariant documented at
  lines 525-528. Inline comment references this finding.
- **Post-fix verification:** `go build ./... && go vet ./... && go
  test -count=1 -race ./...` all green.
- **Status:** **Fixed 2026-04-19.**

#### F8 — Missing privacy-regression tests

Three handlers lack the `PrivacyResponsesIdentical` test pattern:
- ~~`handleRoomMembers`~~ — **done** as part of F1 fix; see
  `internal/server/room_members_test.go`.
- `handleListDevices`
- `handleSetStatus` (no test at all)

- **Recommendation:** Add three tests modelled on
  `TestHandleEdit_PrivacyResponsesIdentical` at `edit_test.go:26-90`.
  `bytes.Equal` assertions across {no match, non-owner, wrong
  context}.
- **Estimated effort:** ~1 hour.
- **Status:** **Deferred to Phase 22 item 13** of `refactor_plan.md`.
  Drift-guard tests; gates themselves are correct.

#### F9 — purge command silently ignores DB errors

- **Location:** `cmd/sshkey-ctl/main.go:1657, 1674, 1679-1681,
  1688-1690` (pre-fix).
- **Detail:** The `purge` CLI command issued `db.Exec("DELETE ...")`,
  `VACUUM`, `os.Remove`, `file_hashes/file_contexts DELETE`, and `Scan`
  calls whose errors were never checked. Operator saw
  `"deleted N messages, vacuumed"` output even if the DELETE silently
  failed.
- **Impact:** Operator confidence in `purge` was undermined. Data
  intended to be purged could remain silently.
- **Fix applied 2026-04-19.** All 9 sites now check their errors and
  report to stderr:
  - `db.QueryRow(SELECT COUNT).Scan(&count)` — on error, skip this DB
    with a stderr warning. Prevents a transient DB blip from being
    silently treated as "zero messages to purge."
  - `db.Query(SELECT file_ids)` — on error, log + skip file cleanup
    but continue to the message-delete phase; documents the
    orphan-file risk explicitly in the error message.
  - `fileRows.Scan(&fids)` — on error, log + skip that row + continue.
  - `os.Remove(file blob)` — uses `errors.Is(err, os.ErrNotExist)` to
    treat "already gone" as benign (common for prior-purge/cascade
    cleanup); logs any other error.
  - `DELETE FROM file_hashes` / `DELETE FROM file_contexts` — each
    logs on error; non-fatal.
  - **`DELETE FROM messages`** — the critical operation. On error,
    prints a loud stderr message ("DB left unchanged") AND
    `continue`s the loop, skipping the success line AND the
    `totalDeleted += count` increment. Summary now cannot claim work
    that didn't happen.
  - `DELETE FROM reactions` — log on error; documents "messages
    deleted; reactions may orphan" so operators know the state.
  - `VACUUM` — log on error; success-line text changes from
    `"deleted N messages, vacuumed"` to `"deleted N messages (vacuum
    failed — see stderr)"` when VACUUM fails but the DELETE
    succeeded, so the output matches reality.
- **Test impact:** The three existing `TestPurge_*` tests
  (`TestPurge_MissingFlag`, `TestPurge_InvalidDuration`,
  `TestPurge_DryRunNoCrash`) all pass unchanged — the fix is confined
  to the non-dry-run delete path and doesn't alter argument parsing
  or the dry-run flow.
- **Post-fix verification:** `go build ./...` + `go vet ./...` +
  `staticcheck ./cmd/sshkey-ctl/...` clean. `go test -count=1 -race
  ./cmd/sshkey-ctl/` green.
- **Status:** **Fixed 2026-04-19.**

#### F10 — Type-confusion test coverage gap

- **Detail:** Go's `json.Unmarshal` silently coerces
  `{"room": 12345}` to `room = ""` (zero value) when the struct field
  is typed as `string`. Downstream protection is the DB membership
  check (empty ID → ErrUnknownRoom). But there's no explicit test
  asserting the rejection path fires for all coercion inputs.
- **Missing tests:**
  - `TestSend_RoomFieldIntegerCoercesToEmpty`
  - `TestSend_RoomFieldNullCoercesToEmpty`
  - `TestSendGroup_WrappedKeysNonNanoIDKeys`
  - `TestSendDM_WrappedKeysOutOfAlphabet`
- **Impact:** Low — the catch-net (DB lookup) works. Tests are
  defensive. Missing coverage risks a future refactor regressing this
  without detection.
- **Recommendation:** Write the four tests. ~2 hours.
- **Status:** **Deferred to Phase 22 item 19** of `refactor_plan.md`.
  Also see the related accepted-scope finding F23 (wrapped_keys
  element-shape validation) — the `TestSendGroup_WrappedKeysNonNanoIDKeys`
  and `TestSendDM_WrappedKeysOutOfAlphabet` tests lock in whatever
  behaviour is the current intended path, which may double as F23's
  drift guard if tightening never happens.

#### F11 — Send-path signature pitfall not documented in PROTOCOL.md

- **Location:** `sshkey-term/internal/crypto/crypto.go:187-216`
  (`SignRoom`, `SignDM` omit `msg.ID` by design); Phase 21 item 3
  closed the dangerous variant (edit-path) earlier today.
- **Detail:** Code comments explain the trade-off
  (`sshkey-term/internal/crypto/crypto.go:227-234, 258-267`), but
  `PROTOCOL.md`'s "Common Pitfalls" section (line 1715) has no entry.
  A future maintainer auditing signature shapes would re-discover and
  possibly "fix" this, breaking compatibility.
- **Fix applied 2026-04-19.** Added pitfall 10 to the `## Common
  Pitfalls` section of `PROTOCOL.md`. The entry:
  - Shows the exact canonical forms for both paths (`SignRoom` /
    `SignDM` without msgID, `SignRoomEdit` / `SignDMEdit` with
    `"edit_room:"` / `"edit_dm:"` domain-separation + length-
    prefixed msgID field), with file:line references.
  - Explains the asymmetry: send-path replay produces visibly-new
    rows (same shape as pitfall 9); edit-path replay (pre-Phase-21)
    would have allowed silent mutation of existing history; the
    edit-path fix was necessary, the send-path fix was not.
  - Documents why send-path closure was NOT pursued (two-phase
    commit cost doubles the round-trip for every message; protection
    gain is zero beyond visibly-new-row property).
  - Gives four actionable consequences for client builders:
    (1) send-path sigs = authenticity + payload-integrity, not
    authorization-to-edit; (2) always `VerifyRoomEdit` /
    `VerifyDMEdit` on receipt of edit broadcasts; (3) domain
    separation prevents cross-verification so keep sets distinct;
    (4) offline-composed sends carry amplified replay exposure —
    prompt-before-transmit mitigates.
  - Cross-references pitfall 9 (retransmit duplicates), the Phase
    21 item 3 closure (edit-path fix), and the client-side
    verify-or-drop contract in `storeEditedRoomMessage` /
    `storeEditedGroupMessage` / `storeEditedDMMessage`.
  - Points at Phase 22 item 15 for the drift-guard test that
    covers this pitfall AND pitfall 9's contract in one go.
- **Original estimate:** ~20 minutes; actual execution ~25 minutes
  (polish + canonical-form verification against live code).
- **Status:** **Fixed 2026-04-19 (documentation).** Drift-guard
  test tracked as Phase 22 item 15 (co-located with F4's drift
  guard).

#### F12 — Retired-user-reconnect policy gate has no explicit test

- **Detail:** The device-revocation gate (cryptographic) is well
  tested. The policy gate (`users.retired = 1` flag rejects reconnect)
  is not explicitly tested — coverage is implicit via retirement tests
  that exercise the server-initiated path.
- **Recommendation:** Add a `TestReconnect_RetiredUserRejected` test
  that simulates a retired user's reconnect attempt and asserts SSH-
  layer rejection before `handleSession` runs.
- **Estimated effort:** ~30 minutes.
- **Status:** **Deferred to Phase 22 item 16** of `refactor_plan.md`.

### Low

#### F13 — handleDelete rooms-vs-groups admin asymmetry undocumented

- **Detail:** Rooms allow admin to delete any message; groups/DMs
  are strictly owner-only. By design, explained in inline code
  comments (`session.go:1860-1863`) but previously not in
  PROTOCOL.md.
- **Fix applied 2026-04-19.** Added a "Why the asymmetry" paragraph
  to the `### Message Deletion` section in PROTOCOL.md explaining
  the rationale: rooms are the moderation surface (public-by-
  membership, admin-managed) so admin-override of delete follows
  the same moderation model as topic/rename/retire; groups use a
  flat peer-admin model with no moderation role; DMs are strictly
  two-party. Rare operator interventions in groups/DMs
  (abuse-investigation, legal-hold) use the `sshkey-ctl` CLI
  escape hatch outside the protocol surface. Paragraph cross-
  references `handler_auth_audit.md#handledelete` and this finding.
- **Status:** **Fixed 2026-04-19** (documentation-only; no code
  change).

#### F14 — Display name confusable / homoglyph detection deferred

- **Location:** `internal/config/displayname.go:1-66`.
- **Detail:** Current coverage is solid — length (2-32), non-printable,
  zero-width (U+200B-F, FEFF, 2060-2064, 2066-2069), bidi overrides
  (U+202A-E), BOM. This blocks the actually-dangerous invisible-char
  attacks (RTL override, homoglyph-via-zero-width-insertion). But it
  does **not** detect confusables (Cyrillic `а` vs Latin `a`) or
  restricted-script mixing (TR #39 Security Mechanisms).
- **Recommendation:** Document as adequate for v0.2.0; post-launch
  consider `golang.org/x/text/secure/precis` for confusable detection
  if impersonation becomes a real threat vector. Add a doc comment in
  `displayname.go` listing "covered" and "deferred" per TR #39.
- **Status:** Accepted for v0.2.0 with documented scope.

#### F15 — Cache bounding unbounded but acceptable at target scale

- **Location:** `internal/store/store.go:33-35`
  (`roomDBs`/`groupDBs`/`dmDBs` maps).
- **Detail:** Each active context holds a permanent `*sql.DB` handle
  until the context is deleted or the server shuts down. At target
  deployment scale (≤500 contexts), ~500 file descriptors is well
  within default `ulimit -n`. At 5000+ contexts operators need
  `ulimit` tuning or LRU eviction.
- **Recommendation:** Accept for v0.2.0. Document the trigger for
  future LRU implementation: "if a deployment grows to 5000+ active
  contexts without manual cleanup." Add a comment block in `store.go`
  explaining the decision and the documented trigger. ~15 minutes.
- **Status:** Accepted for v0.2.0 with documented trigger.

#### F16 — SQL drift-guard test missing

- **Detail:** The SQL sweep (item 2) found the codebase clean. To
  catch future regressions mechanically, a drift-guard test using
  `go/ast` would flag new `fmt.Sprintf` + SQL-shaped format strings
  outside the two audited exceptions.
- **Recommendation:** Implement as a nice-to-have. Details in
  `sql_audit.md` "Recommendations" section.
- **Status:** **Deferred to Phase 22 item 17** of `refactor_plan.md`.

#### F17 — gosec G104 unhandled-error cluster (benign majority)

- **Tool:** `gosec -quiet ./...` reported 194 issues, all G104
  (CWE-703: unhandled errors).
- **Triage:** ~150 are benign by design — `c.Encoder.Encode` on
  already-erroring paths, `Close()` on cleanup, `os.Remove` on
  rollback, deferred fire-and-forget patterns. These match the write-
  discipline policy from Phase 17c (error paths log-and-continue).
- **Non-benign findings:** see F9 (purge command) and the related
  cluster at `cmd/sshkey-ctl/main.go:1657-1690`.
- **Recommendation:** Fix F9; accept the benign cluster as documented
  in Phase 17c's write-discipline audit. Consider a `// #nosec G104`
  comment sweep if we want gosec to produce a clean baseline.
- **Status:** **Triaged and closed 2026-04-19.** F9 fixed (all 9
  ignored-error sites in `cmdPurge` now checked + reported to
  stderr). The remaining ~185 benign G104 findings accepted as the
  Phase 17c write-discipline policy (audit/history writes
  log-and-continue; state-mutation writes abort + return
  `internal_error`). Optional `// #nosec G104` sweep to produce a
  gosec-clean baseline remains available as v0.2.x hygiene work but
  is not tracked — every remaining G104 is documented as by-design.

#### F18 — Tarball path-length and case-collision unvalidated

- **Location:** `cmd/sshkey-ctl/restore.go:209-260` (`validateTarball`).
- **Detail:** No explicit path-length cap (>4096 bytes passes
  validation; OS may EINVAL or succeed depending on FS). No case-
  collision check (`data/File.db` + `data/file.db` both pass; second
  overwrites first on case-insensitive FS).
- **Impact:** Low. Backup tarballs are operator-supplied; malicious-
  operator scenario is out of threat model (they already have
  filesystem access).
- **Recommendation:** Defer to v0.3.0. Add tests documenting current
  behaviour at that time.
- **Status:** Accepted with documented scope.

#### F19 — Concurrent stress test for DB-handle cache missing

- **Detail:** Sequential tests cover cache-fault + cache-evict races.
  No test exercises two goroutines racing `RoomDB(x)` vs.
  `DeleteRoomRecord(x)` under `-race`.
- **Recommendation:** Add a stress test using `t.Parallel()` + the
  race detector. ~1 hour.
- **Status:** **Deferred to Phase 22 item 18** of `refactor_plan.md`.

#### F20 — handleListPendingKeys lacks explicit test

- **Detail:** Gate is correct (global-admin check), but no test
  exercises the rejection path.
- **Recommendation:** ~30 minutes to add
  `TestHandleListPendingKeys_NonAdminRejected` +
  `TestHandleListPendingKeys_AdminHappyPath`.
- **Status:** **Deferred to Phase 22 item 14** of `refactor_plan.md`.

#### F21 — handleSetStatus lacks any test

- **Detail:** Gate is correct (owner-only, implicit via
  authenticated-user context), but no test at all.
- **Recommendation:** ~30 minutes to add basic happy-path + non-owner-
  rejection tests.
- **Status:** **Deferred to Phase 22 item 13.b** of `refactor_plan.md`
  (already tracked there as part of the Phase 21 handler-auth-audit
  spin-off covering `handleListDevices` + `handleSetStatus`). Same
  gap, cross-referenced rather than duplicated.

#### F22 — fuzz harness not yet written

- **Detail (pre-fix):** Item 9b called for a short fuzz run against
  the NDJSON protocol decoder. The harness did not exist.
- **Fix applied 2026-04-19.** New file
  `internal/protocol/decode_fuzz_test.go` with two fuzz entry points:
  - **`FuzzDecodeDispatch`** — exercises the full decode path:
    `NewDecoder(bytes.NewReader) → DecodeRaw → TypeOf → dispatch into
    one of 32 client-to-server verb structs via typed
    json.Unmarshal`. Uses a `clientVerbs` map (`map[string]func()
    any`) registering all 32 verbs; adding a new verb to the map
    extends fuzz coverage with no other changes needed.
  - **`FuzzTypeOf`** — narrower target, fuzzes the `TypeOf` helper
    alone. Worth a separate target because every handler entry point
    calls it.
  - **Seed corpus** (47 entries): minimal-valid happy-path frame for
    each of the 32 verbs + 15 adversarial shapes (empty input,
    whitespace-only, malformed JSON, unbalanced braces, truncated
    frames, unknown-verb types, integer-where-string, null-where-
    string, array-where-object, deeply-nested payloads, multi-line
    NDJSON, trailing-partial-frame).
  - **Bounded per-input loop** (1000 frame iterations max) so
    pathological many-short-lines inputs can't make a single fuzz
    iteration run unbounded.
- **Gate run results 2026-04-19:**
  - `FuzzTypeOf -fuzztime=30s`: **6.3M executions**, 0 crashers, 359
    interesting inputs.
  - `FuzzDecodeDispatch -fuzztime=120s`: **12.5M executions**, 0
    crashers, 447 interesting inputs.
  - No `testdata/fuzz/FuzzDecodeDispatch/` corpus entries written
    (Go's fuzz engine would save minimal reproducers there if
    panics were found; empty directory means clean run).
- **Reproduction:**
  ```
  go test -run='^$' -fuzz=FuzzTypeOf -fuzztime=30s ./internal/protocol/
  go test -run='^$' -fuzz=FuzzDecodeDispatch -fuzztime=5m ./internal/protocol/
  ```
  Recommended pre-launch gate: 5 minutes of `FuzzDecodeDispatch`
  locally on the release branch before tagging. The 2-minute gate
  run for this audit pass is the minimum viable baseline.
- **Status:** **Fixed 2026-04-19.** Harness lands permanently; gate
  runs are cheap enough (2-5 min) to run before every release tag.

#### F23 — wrapped_keys key/value shape not validated at protocol layer

- **Location:** `session.go` envelope checks use
  `checkWrappedKeysCap` (size) but not element shape.
- **Detail:** Attacker can inject arbitrary unicode/spaces as keys;
  value base64 shape not checked at protocol layer (caught later by
  crypto unwrap). Not a security issue but a defence-in-depth gap.
- **Recommendation:** Accept for v0.2.0. Document as known scope.
- **Status:** Accepted with documented scope.

#### F24 — Upload quota failure-injection at upload_complete TOCTOU missing

- **Detail:** Phase 21 item 13.a second sub-item. The code path is
  correct (rejects + unlinks + skips hash/binding), but no test forces
  the post-bytes recheck to trip via failure injection.
- **Recommendation:** ~30 minutes to add via the existing
  `failingStore` pattern. Can land together with F26.
- **Status:** **Deferred to Phase 22 item 12.c** of `refactor_plan.md`
  ("Parallel-upload TOCTOU race") — already tracked there as part of
  the upload-quota integration test suite. Same test target (the
  `upload_complete` TOCTOU re-check), approached from the
  integration-harness angle rather than the `failingStore` unit-
  injection angle; either implementation satisfies the contract.
  Same gap, cross-referenced rather than duplicated. Parallels the
  F25 → 12.d cross-reference.

#### F25 — Upload quota admin_notify burst-idempotence test missing

- **Detail:** Phase 21 item 13.b. `warn_notified` sticky flag enforces
  idempotence at the store level, but no burst test exercises
  concurrent uploads from the same user crossing warn simultaneously.
- **Recommendation:** ~30 minutes.
- **Status:** **Deferred to Phase 22 item 12.d** of `refactor_plan.md`
  ("Burst admin_notify firing exactly once") — already tracked there
  as part of the upload quota integration test suite. Same gap,
  cross-referenced rather than duplicated.

#### F26 — DM retention / GC deferred

- **Location:** Design pre-written at `refactor_plan.md:601-612`.
- **Detail:** The single deferred hardening item. No live users
  pre-launch; disk concerns are post-launch operational.
- **Recommendation:** Stays deferred for v0.2.0. Post-launch Phase
  21.x can pick it up when real-world disk-growth data informs the
  `dm_retention_days` default.
- **Status:** Formally deferred.

### Medium (additional — surfaced by the F3 deep-scan 2026-04-19)

#### F27 — `verified` flag has no send-path teeth

- **Location:** `sshkey-term/internal/client/sendqueue_dispatch.go`,
  `send.go`, and the `verified` column on `pinned_keys`.
- **Detail:** The `pinned_keys.verified` flag is computed and
  persisted, but nothing on the send path consults `IsVerified` before
  encrypting a message to a peer. A user with `verified = 0` for Alice
  (either because they never ran `/verify alice`, or because Alice's
  key just changed and the flag was auto-reset) can still send
  messages encrypted to Alice's possibly-MITM'd key with no prompt.
- **Original framing:** F27 was proposed as the enforcement
  complement to F3 (key-change warning). The idea was to block or
  warn on sends to unverified peers so a compromised server couldn't
  silently harvest plaintext from users who hadn't completed
  verification.
- **Decision 2026-04-19: REJECT the enforcement feature.** Treat
  verification as strictly voluntary. The rationale, worked out with
  the project owner:
  1. **TOFU's job is detection, not enforcement.** The design value
     is *the user knows a key changed* — not *the system prevents
     them from using the chat*. Enforcement-on-send turns the client
     into a compliance tool for a policy most users never opted into;
     detection-plus-warning preserves user agency.
  2. **Industry convention is detection-only for consumer
     messaging.** Signal, WhatsApp, iMessage all ship TOFU without
     mandatory verification gates on send. Enterprise systems that
     add enforcement also ship mandatory training + provisioning
     channels + IT helpdesks to absorb the UX cost; sshkey-chat's
     deployment shape (small-to-medium self-hosted communities) is
     at the consumer-UX end of that spectrum.
  3. **Users who never engage with verification still need to chat.**
     Any enforcement flavour (block-on-send, warn-on-every-send,
     modal-on-first-unverified-send, opt-in strict mode) creates a
     class of users who can't use the product without doing work
     they didn't sign up for. That's a worse failure mode than the
     narrow MITM window the feature closes.
  4. **F1 + F3 + F30 cover the detection story completely.** F1 is
     the attack-detection primitive (byte-identical privacy
     responses so probes don't leak). F3's modal surfaces key
     changes visibly at the moment they happen. F30's `/whois`
     gives on-demand fingerprint lookup. A user who WANTS to verify
     has three different surfaces to do so; a user who doesn't
     engage isn't nagged.
- **Residual risk (accepted):** narrower than it first appeared
  once the no-rotation protocol invariant is accounted for (see the
  "Protocol framing" block in F3). Under no-rotation, the only way
  for a compromised server to substitute a key is an active MITM
  during a `profile` broadcast for an EXISTING user ID. That event
  is exactly what F3's modal fires on — *always*, not only for
  users the victim had previously verified — because the client's
  pinned fingerprint no longer matches the server's new assertion.
  So the "unverified user who gets silently MITM'd" class that
  enforcement-on-send would have closed **is already detected by
  F3's modal**, which fires independent of verified state. The
  only residual gap is a user who sees F3's modal and dismisses it
  without reading — a voluntary trust decision the client respects.
  A user who cares about verification has F29 + F30 available
  after the modal.
- **Status:** **Accepted with documented scope 2026-04-19.**
  Verification is voluntary; send-path enforcement is not a goal of
  this project. Revisit only if a concrete deployment shape (e.g.,
  regulated-industry chat) demands it, at which point it becomes a
  feature request, not a bug fix.

### Low (additional — surfaced by the F3 deep-scan)

#### F28 — Sidebar badge for verified peers

- **Location:** `sshkey-term/internal/tui/sidebar.go` +
  `internal/tui/memberpanel.go` / `infopanel.go` (no verification
  indicator currently rendered in any of them).
- **Original proposal:** show a warning glyph (⚠) next to every
  unverified peer so users would be reminded to come back and run
  `/verify`.
- **Design inversion 2026-04-19.** The original proposal was rejected
  in favour of the opposite semantic: show a positive verification
  glyph (e.g., ✓) ONLY for users with `verified = 1`, and render
  nothing for unverified users. Rationale (worked out with the
  project owner alongside F27's rejection):
  1. **Symmetric with F27.** If verification is voluntary (F27), the
     UI should not nag users who chose not to engage. A warning
     glyph on every unverified peer is ambient nag; it communicates
     "you're doing it wrong" to the majority of users most of the
     time.
  2. **"Unverified" is the default state, not a danger state.**
     Flagging every default-state peer with a warning glyph misleads
     the user about risk level — a newly-added peer and a peer
     whose key has been stable for months both render identically
     under "unverified". That's not useful data.
  3. **Positive affirmation rewards the feature's users.** A user
     who runs `/verify alice` and completes the safety-number
     comparison sees a subtle ✓ next to Alice's name **for the
     lifetime of Alice's account.** Under the no-rotation protocol
     design (keys are identities; a "new key" means a new account
     under a different user ID, not a mutation of the existing
     pinning row), the `verified` flag never clears in normal
     operation — the schema's ON-CONFLICT-CASE only fires on
     anomalous fingerprint mismatches (server bug, compromised
     server, or local DB tampering; see F3's "Protocol framing"
     block). So a disappearing ✓ is always attack-adjacent, which
     makes the feature's signal precise: the presence of the badge
     means "you verified them and the key is still what you
     verified"; the absence-after-presence means "something went
     wrong that deserves investigation."
- **Revised implementation.**
  - **Glyph:** Unicode `✓` in a dim green / subdued colour for colour
    terminals; ASCII fallback `[v]` for monochrome. The glyph
    appears before or after the display name in the sidebar and
    member lists (TBD during implementation — prefix is less
    truncation-prone in narrow terminals).
  - **Surfaces:** sidebar DM list + info-panel member list. Inline
    in the messages pane header is probably overkill — the user
    already knows who they're talking to when they're reading
    messages.
  - **State watch:** render reads `store.IsVerified(user)`. The
    `pinned_keys` schema's ON CONFLICT CASE clause auto-clears
    `verified = 0` when the fingerprint changes. Under no-rotation
    that only happens on anomalous events (server bug, compromised
    server, or local DB tampering); F3's modal fires at the same
    moment to surface the event. The two surfaces agree: badge
    disappears ↔ modal fires, and both trigger off the same
    underlying `PinKey(..., differentFingerprint)` call.
  - **No glyph is not an error.** A peer with no pinned entry,
    `verified = 0`, or no profile all render identically (no
    badge). That's the correct semantic: "you haven't done the
    verification work; we don't know the trust level; no claim
    made."
- **Estimated effort:** ~1-1.5 hours including tests. Natural pairing
  with F3's TOFU UI wire-up since both surfaces share the same
  pinned_keys reads and sidebar/memberpanel render paths.
- **Discovered 2026-04-19 during F3 implementation: ALREADY SHIPPED.**
  The verified-badge render path was already wired in five TUI
  surfaces prior to Phase 21's audit: `sidebar.go`
  (`verifiedMarker = green ✓`, gated on `resolveVerified` callback),
  `infopanel.go` (`memberInfo.Verified` populated from
  `store.GetPinnedKey` in `ShowRoom` / `ShowGroup` / `ShowDM`;
  rendered via `checkStyle.Render(" ✓")` in `renderMember`),
  `memberpanel.go` (line 204-206), `newconv.go` (line 232, 254),
  and `verify.go` (line 152). The audit entry was stale — someone
  built the feature before Phase 21 started but the audit doc
  hadn't caught up. Drift-guard tests added (`F28_SidebarRenders
  VerifiedBadge` + `F28_InfoPanelCarriesVerifiedFlag`) so a future
  refactor doesn't strip the render paths without noticing.
- **Status:** **Fixed (already shipped; drift-guarded 2026-04-19).**

#### F29 — `/verify` lacks display-name completion parity with `/add`

- **Detail (pre-fix):** `/add @alice` uses display-name-to-userID
  resolution via `FindUserByName`. `/verify alice` took a raw
  argument and passed it directly to `VerifyModel.Show()`, which did
  NOT call `FindUserByName`. Users could add via display name but had
  to remember nanoid or exact-match for verify. Inconsistent
  affordance.
- **Fix applied 2026-04-19.** Both `/verify` and `/unverify`
  (previously siblings with the same raw-arg limitation) now route
  through a new `App.resolveUserByName` helper that strips "@"
  prefix, trims surrounding whitespace, and delegates to
  `client.FindUserByName`. The existing `App.resolveNonMemberByName`
  used by `/add` was re-pointed at the new helper so all three verbs
  share the same resolution semantics (the two names are retained as
  self-documenting wrappers indicating where each is used).
  - The trim order was `TrimPrefix("@") → TrimSpace` pre-fix
    (inherited from `resolveNonMemberByName`). `"  @Alice  "` didn't
    resolve because the "@" wasn't at index 0 after padding. New
    order is `TrimSpace → TrimPrefix("@") → TrimSpace` so all four
    shapes work: `"Alice"`, `"@Alice"`, `"  Alice  "`,
    `"  @Alice  "`. The fix incidentally improves `/add`'s parsing
    tolerance too since it uses the same helper.
  - Unknown input (`/verify dave` where dave isn't a known user)
    now surfaces `"unknown user: dave"` in the status bar instead
    of silently opening an empty VerifyModel.
  - New test helper `client.SetProfileForTesting` added alongside
    the existing `SetStoreForTesting` so tui-package tests can
    populate `c.profiles` without a full SSH connection.
- **New drift-guard tests:** `internal/tui/verify_resolve_test.go`
  with 11 tests covering: display-name match, case-insensitive match,
  `@`-prefix strip, whitespace trim, combined `@`-and-whitespace,
  raw user-ID passthrough (backward compatibility), unknown user,
  empty input, only-`@`-or-whitespace, nil client, and
  resolveNonMemberByName / resolveUserByName equivalence drift guard.
- **Post-fix verification:** `go build ./...` + `go vet ./...` +
  `staticcheck ./...` clean on sshkey-term. Full `-race` suite green
  (7 packages).
- **Status:** **Fixed 2026-04-19.**

#### F30 — No `/whois` or `/key` command for peer fingerprint display

- **Detail (pre-fix):** `/mykey` displayed the local user's own key
  fingerprint. There was no equivalent command for displaying another
  user's fingerprint on demand — the only way to see a peer's
  fingerprint was through the `KeyWarningModel` (triggered only on
  change) or the `VerifyModel` safety-number comparison
  (`/verify <name>`). An operator investigating "did Alice's key
  actually rotate?" had no quick-lookup command.
- **Fix applied 2026-04-19.** New `/whois <user>` slash command in
  sshkey-term renders all locally-known identity state on one status-
  bar line and copies the fingerprint to the clipboard (matching
  `/mykey`'s ergonomic):

  ```
  Alice (usr_abc12345) — SHA256:abcdef... — verified — first seen
    2026-03-15 — key updated 2026-04-10 — fingerprint copied to clipboard
  ```

  - **Resolution** routes through the F29 helper
    `App.resolveUserByName` — accepts display names, `@alice`
    syntax, or raw user IDs.
  - **Retired-user fallback**: if the resolver fails (user not in
    live profile cache), handler attempts a direct `pinned_keys`
    lookup by user ID. This covers the exact scenario the original
    recommendation cited — "investigating Alice's rotation after
    she's been retired and her profile broadcast is gone from our
    cache."
  - **Data-source precedence**: live profile's `KeyFingerprint` wins
    over pinned (more current during the window between server push
    and `StoreProfile` update). Timestamps and verified state come
    from `pinned_keys`.
  - **Flag rendering**: `admin`, `retired`, and `unverified`/`verified`
    markers appear inline when the profile / pinned state carries
    them.
  - **Smart timestamp rendering**: `key updated` is omitted when
    equal to `first seen` (i.e., the key has never rotated) to keep
    the status bar concise.
  - **New store helper**: `store.GetPinnedKeyInfo(user) PinnedKeyInfo`
    returns the full pinned-keys row (fingerprint, pubkey, verified,
    first_seen, updated_at) in a struct. Added alongside the existing
    `GetPinnedKey` / `GetPinnedKeyFull` helpers.
  - **Completion + help**: `/whois` added to the tab-completion list
    (`completion.go`) and the help screen (`help.go`) so it's
    discoverable.
- **New drift-guard tests**: `internal/tui/whois_test.go` with 14
  tests covering happy path, unverified rendering, `@`-prefix
  resolution, raw-user-ID resolution, unknown user, empty arg, nil
  client, live-profile-without-pinned fallback, retired-user /
  pinned-only fallback (this one caught a real gap in the initial
  implementation — the resolver only searched the live profile
  cache, so retired users were invisible), retired flag rendering,
  admin flag rendering, first-seen-only rendering, key-updated
  rendering after rotation, and no-fingerprint-anywhere edge case.
- **Post-fix verification:** `go build ./...` + `go vet ./...` +
  `staticcheck ./...` clean on sshkey-term. Full `-race` suite green
  (7 packages).
- **Status:** **Fixed 2026-04-19.**

#### F31 — No `pinned_keys` cleanup on user retirement

- **Location:** `sshkey-term/internal/store/keys.go` `pinned_keys`
  table.
- **Detail:** When a user is retired server-side, the client's
  `pinned_keys` row for that user persists indefinitely. Low-impact
  (retired users are not contacted; their rows just take up DB
  space), but untidy.
- **Decision 2026-04-19: ACCEPT AS HYGIENE.** Reasoning:
  1. **No functional impact.** Retired users are not contactable
     (server-side membership gates + Phase 9 retirement propagation
     exclude them from every write path). The lingering
     `pinned_keys` row is never consulted at runtime for a retired
     user because no send/edit/verify code path resolves a retired
     user ID.
  2. **F30 `/whois` explicitly depends on this residual data.** The
     retired-user fallback in `handleWhoisCommand` looks up pinned
     data directly when the live profile is gone. Cleanup on
     retirement would BREAK that path — an operator investigating
     "did Alice's key ever rotate before she was retired?" would
     find the record missing. Keeping the row preserves the
     forensic trail.
  3. **Storage cost is negligible.** A `pinned_keys` row is
     ~150 bytes (fingerprint + pubkey + 3 ints + user ID). At
     1,000 retired users per client lifetime (absurdly high for a
     small-to-medium community) that's ~150 KB in the sqlcipher
     DB. Operator-side cleanup is trivial if needed: `DELETE FROM
     pinned_keys WHERE user NOT IN (SELECT user FROM profiles)` or
     similar, run manually from `sqlite3` against the client DB.
  4. **Privacy-of-retirement is not compromised.** `pinned_keys`
     is local to the client; the server doesn't see it. A client
     that retains a retired user's fingerprint is holding data it
     already observed during the user's active lifetime — no new
     information is retained post-retirement.
- **Status:** **Accepted as hygiene 2026-04-19.** The residual data
  is intentional (F30 fallback) and the cost is negligible. No
  cleanup code planned. Operators who want aggressive cleanup for
  storage or privacy reasons have the one-line SQL above.

### Info (cleanup candidates — surfaced by the F3 deep-scan)

#### F32 — Redundant `ClearVerified` call in `StoreProfile`

- **Location:** `sshkey-term/internal/client/persist.go:474`.
- **Detail:** `StoreProfile` calls `ClearVerified(user)` on detected
  key change. This is redundant because the `pinned_keys` schema's
  `ON CONFLICT ... CASE WHEN fingerprint != excluded.fingerprint
  THEN 0 ELSE verified END` clause already resets `verified = 0`
  when the subsequent `PinKey(user, newFingerprint, ...)` runs.
  The explicit `ClearVerified` is belt-and-braces but harmless.
- **Important framing (added 2026-04-19):** both the schema ON-
  CONFLICT clause AND the explicit `ClearVerified` call are
  **attack-path code**, not ordinary-state-management code. Under
  the no-rotation protocol design (see F3 "Protocol framing"),
  neither path fires during normal operation — they only trigger
  on anomalous fingerprint mismatch events (compromised server,
  server bug, or local DB tampering). The "redundancy" is the
  second lock on the front door, not an ordinary-state hygiene
  thing. A future maintainer stripping either path as "dead code"
  or "duplicated logic" would be removing defense-in-depth against
  the one class of event this code exists to catch.
- **Trade-off:** The explicit call makes the logic visible at the
  call site without requiring readers to know the schema trick.
  Keeping it is arguably cleaner. Removing it would tie behaviour
  entirely to the schema, which is drift-prone if schema changes.
- **Recommendation:** Accept the redundancy as defence-in-depth
  documentation. If either path is ever considered for removal,
  the PR description must cite why BOTH are safe to drop — the
  schema clause is the primary lock; the `ClearVerified` call is
  the secondary lock; strip one and you halve the attack-detection
  coverage for the one class of event this code is designed for.
- **Status:** Info-only; no action planned. Documented as
  attack-path code to prevent well-meaning future cleanup.

### Clean

- **SQL parameterisation** (Item 2) — see `sql_audit.md`. 2 matches,
  both safe by construction, no user input in format strings.
- **CLI logging no-leak** (Item 7) — zero slog/fmt.Print calls expose
  passphrase/key/token fields. `bootstrap_admin` uses `term.ReadPassword`
  (no echo); private-key-path prints reference encrypted files only.
- **Concurrency under target scale** (Item 6) — WAL mode correct,
  5s busy_timeout, cache-fault + cache-evict races covered by double-
  check pattern + atomic-close-under-lock.
- **DM forward secrecy** (Item 4.1) — every DM message generates fresh
  `K_msg`; past-key compromise does not affect future messages.
- **Send-path signature trade-off** (Item 4.3) — code-level design is
  correct; the doc gap is tracked as F11.
- **Pen-test scenarios A, B, E, F** (Item 10) — covered by existing
  tests. Scenarios C and D tracked as F12 and F22 respectively.
- **Upload quota correctness** (Item 13) — 13.c, 13.d, 13.e covered by
  existing tests. Gaps 13.a and 13.b tracked as F24 and F25.
- **`AutoRevokeSignals` drift guard** — `TestAutoRevokeSignals_ExactList`
  at `counters_test.go:221-260` locks the list; would fail if
  `SignalDailyQuotaExceeded` were mistakenly added.

---

## Reproduction

All tooling commands run from `sshkey-chat` repo root:

```
# Dependency audit (govulncheck)
govulncheck ./...

# Static analysis (staticcheck — BLOCKED, see F5)
staticcheck ./...

# Static analysis (gosec)
gosec -quiet ./...

# Module verification
go mod tidy -diff
go mod verify

# Full race suite
go test -count=1 -race ./...
```

Tooling versions at audit time:
- Go toolchain: 1.26.1 (via gvm)
- govulncheck: latest (installed fresh)
- staticcheck: 2025.1.1, built with Go 1.23.7 (see F5)
- gosec: dev build from Go 1.22.5 pkgset

---

## Pre-launch action plan

### Must fix before v0.2.0 tag

1. ~~**F1** — handleRoomMembers privacy leak.~~ **DONE 2026-04-19.**
   Replaced `ErrNotAuthorized` branch with `s.sendUnknownRoom(c)`;
   added `TestHandleRoomMembers_PrivacyResponsesIdentical` drift
   guard.
2. ~~**F2** — upgrade Go toolchain to 1.26.2 and rebuild.~~ **DONE
   2026-04-19.** Both repos bumped to Go 1.26.2 (go.mod + CI);
   govulncheck clean on both.
3. ~~**F5** — rebuild staticcheck against Go 1.26.~~ **DONE
   2026-04-19.** Installed `staticcheck@latest` (now 2026.1 /
   v0.7.0), reran on both repos. 28 findings triaged inline: 2 real
   bugs fixed, 10 dead-code sites removed, 1 deprecated API swapped,
   15 lint cleanups applied. Both repos staticcheck-clean.

### Should fix before v0.2.0 tag (trivial + high-value)

4. ~~**F4** — add the retransmit-duplicates entry to PROTOCOL.md
   Common Pitfalls.~~ **DONE 2026-04-19.** Pitfall 9 added covering
   all five points (no server dedup, client dedup by id, visible
   duplicates on retransmit, `corr_id` is not an idempotency token,
   rate-limit is the spam defence). Drift-guard test deferred to
   Phase 22 item 15.
5. ~~**F11** — add the send-path-signature entry to PROTOCOL.md
   Common Pitfalls.~~ **DONE 2026-04-19.** Pitfall 10 added showing
   both canonical forms, explaining the asymmetry, and giving four
   actionable consequences for client builders. Drift-guard test
   shares Phase 22 item 15 with F4 (one test covers both pitfalls'
   visibly-new-row contract).
6. ~~**F3** — TOFU UI wire-up.~~ **DONE 2026-04-19.** F3.a +
   F3.c + F3.d shipped in coordinated sshkey-term release (F3.b
   dropped per the no-rotation scope revision). F28 discovered
   to be already-shipped; drift guards added. All pre-launch-
   relevant audit findings are now closed.

### Can defer to v0.2.1 (no launch blocker)

6. **F3** — TOFU UI surfacing (cross-repo; ships with client update).
7. **F7**, **F8**, **F9**, **F10**, **F12**, **F13**, **F16**,
   **F19**, **F20**, **F21**, **F22**, **F24**, **F25** — test and
   documentation polish work.
8. **F17** — gosec G104 triage sweep (optional, clean-baseline
   hygiene).

### Accepted with documented limitation (no action)

9. **F6** — lockfile TOCTOU. Documented operator guidance.
   Structural fix in v0.3.0.
10. **F14** — display-name confusable detection. Post-launch if
    impersonation becomes a real threat.
11. **F15** — cache bounding. Target-scale-acceptable; documented
    trigger for future LRU.
12. **F18** — tarball path-length and case-collision. Low-impact.
13. **F23** — wrapped_keys element shape. Caught by downstream crypto
    unwrap; protocol-layer cap is sufficient.
14. **F26** — DM retention. Post-launch operational decision.

---

## Gate criteria review

Against the Phase 21 gate from `refactor_plan.md`:

- "All critical and high-severity findings fixed." — **F1 + F2** are
  must-fix. **F3 + F4 + F5** are high but deferrable with
  documentation. Pre-launch gate: fix F1 + F2; accept F3/F4/F5 with
  documented limitations. Post-launch gate: close all five.
- "Medium-severity findings triaged." — **F6 accepted, F7-F12 tracked
  for v0.2.1, F9 addressed inline, F10 tracked.** Triage complete.
- "Deferred hardening triaged." — **F26 (DM retention) formally
  deferred with pointer back to design sketch.** Complete.
- "`go vet` + `staticcheck` + `gosec` + `govulncheck` clean." —
  `go vet` clean, `staticcheck` clean (F5 fixed 2026-04-19),
  `gosec` triaged (F17), `govulncheck` clean (F2 fixed 2026-04-19).
- "Full test suite passes under `-race`." — green (confirmed during
  Phase 21 audit run; see race suite output).

---

## Change log

- **2026-04-19** — Initial audit pass. All 13 items executed. 26
  initial findings (F1-F26) documented. Zero code changes during
  the audit pass itself.
- **2026-04-19** — F1 fixed. `handleRoomMembers` privacy-invariant
  regression closed via single-line switch to `sendUnknownRoom` +
  `TestHandleRoomMembers_PrivacyResponsesIdentical` drift guard.
- **2026-04-19** — F2 fixed. Go toolchain bumped 1.25.0 → 1.26.2 on
  both `sshkey-chat` and `sshkey-term` (`go.mod` + CI workflows);
  `govulncheck` clean on both.
- **2026-04-19** — F3 investigated. Deep-scan of sshkey-term
  fingerprint behaviour surfaced that the warning UI is already
  built; F3 scope narrowed to a ~60-90 minute wire-up (F3.a/b/c).
  Six adjacent findings (F27-F32) documented as spin-offs.
  Implementation deferred pending scope decision.
- **2026-04-19** — F5 fixed. Installed `staticcheck` 2026.1 (built
  with Go 1.26.2); triaged 28 findings inline (2 real bugs, 10
  dead-code sites, 1 deprecated API, 15 stylistic). Both repos
  staticcheck-clean.
- **2026-04-19** — F4 fixed (documentation). Added pitfall 9 to
  `PROTOCOL.md` Common Pitfalls covering the replay / idempotency
  semantics (server assigns fresh IDs per request; client dedup by
  id; retransmits produce visible duplicates; `corr_id` is not an
  idempotency key; rate-limit is the spam defence). Drift-guard test
  deferred to Phase 22 (co-located with F11's drift guard).
- **2026-04-19** — F12, F16, F19 deferred to Phase 22 items 16, 17,
  18 respectively. F21 cross-referenced to existing Phase 22 item
  13.b (same gap as the handler-auth-audit spin-off already
  tracked). F25 cross-referenced to existing Phase 22 item 12.d
  (same gap as the upload-quota integration test already tracked).
  Five test-coverage drift guards now formally scheduled for the
  Phase 22 testing-overhaul pass.
- **2026-04-19** — `sql_audit.md` "Parameterization hygiene note"
  recommendation shipped. New `internal/store/STYLE.md` codifies the
  `?` placeholder rule + the one accepted exception (switch-selected
  column names from `direct_messages.go`) + a review-guidance
  checklist for PRs introducing new format-string SQL. Cross-
  referenced back to `sql_audit.md` and `audit_v0.2.0.md#F16`. The
  drift-guard test (F16) remains scheduled as Phase 22 item 17;
  STYLE.md is the canonical reference reviewers check in the
  meantime.
- **2026-04-19** — F10 deferred to Phase 22 item 19. Four adversarial-
  unmarshal tests (`TestSend_RoomFieldIntegerCoercesToEmpty`,
  `TestSend_RoomFieldNullCoercesToEmpty`,
  `TestSendGroup_WrappedKeysNonNanoIDKeys`,
  `TestSendDM_WrappedKeysOutOfAlphabet`) lock in the DB-membership
  catch-net behaviour against future refactors. Item 19 also notes
  that the wrapped_keys tests may double as the drift guard for the
  accepted-scope F23 (wrapped_keys element-shape validation gap)
  depending on whether future tightening lands.
- **2026-04-19** — F9 fixed. All 9 ignored-error sites in
  `cmdPurge` (`cmd/sshkey-ctl/main.go`) now check errors and report
  to stderr. The critical `DELETE FROM messages` now skips the
  success line + `totalDeleted` increment on failure so the summary
  can't claim work that didn't happen. VACUUM-failed path has a
  distinct success-line variant so output matches reality.
  `os.Remove` uses `errors.Is(err, os.ErrNotExist)` to suppress
  benign "already gone" warnings. Three existing purge tests still
  pass; full race suite on `cmd/sshkey-ctl` green.
- **2026-04-19** — Housekeeping cleanups. F24 flipped from "Open
  (deferred to v0.2.1)" to "Deferred to Phase 22 item 12.c"
  (parallels the F25 → 12.d cross-reference; same TOCTOU re-check
  target, integration-harness vs. `failingStore` unit-injection are
  equivalent test framings). F17 status updated to reflect F9's
  closure: was "Triaged. F9 open; rest accepted." — now "Triaged
  and closed 2026-04-19. F9 fixed; remaining benign G104 cluster
  accepted as Phase 17c write-discipline policy."
- **2026-04-19** — F6 fixed (not just accepted). Severity reassessed
  LOW on walk-through of realistic scenarios (the MEDIUM rating was
  pessimistic), but upgraded to fix-now because the primitive swap
  was cheap. Replaced Read-then-temp-write-then-Rename with a
  tmpfile+Link pattern using POSIX link(2) for atomic exclusive-
  create. `TestWrite_ConcurrentAcquisitionExactlyOneSucceeds` with
  20 racing goroutines deterministically passes. 16 lockfile tests
  all green; full sshkey-chat `-race` suite green.
- **2026-04-19** — F29 fixed. `/verify` and `/unverify` now route
  through a new `App.resolveUserByName` helper that accepts display
  names + "@alice" syntax in addition to raw user IDs, matching
  `/add`'s completion affordance. Incidentally improved `/add`'s
  parsing tolerance by switching the trim order (TrimSpace →
  TrimPrefix → TrimSpace) so `"  @Alice  "` resolves. Unknown input
  now surfaces `"unknown user: <name>"` instead of silently opening
  an empty VerifyModel. New helper
  `client.SetProfileForTesting` added to support the tui-package
  drift-guard test suite (11 new tests in
  `verify_resolve_test.go`).
- **2026-04-19** — F22 fixed (fuzz harness). New
  `internal/protocol/decode_fuzz_test.go` with two fuzz targets:
  `FuzzDecodeDispatch` (full NDJSON decode → dispatch into 32 verb
  structs) and `FuzzTypeOf` (narrower `TypeOf` helper). Gate runs
  (30s + 120s respectively) produced **18.8M total executions,
  zero crashers, 806 interesting inputs explored** across both
  targets. The 32-verb `clientVerbs` map is extensible — new verbs
  added to the dispatch automatically gain fuzz coverage. Pre-launch
  gate run recommendation codified at 5 minutes of
  `FuzzDecodeDispatch` before every release tag.
- **2026-04-19** — F30 fixed (`/whois` command). New sshkey-term
  slash command `/whois <user>` renders all locally-known identity
  state on one status-bar line + copies fingerprint to clipboard.
  Resolution routes through the F29 `resolveUserByName` helper;
  retired-user fallback attempts direct `pinned_keys` lookup by
  user ID when the live profile cache miss. Live profile's
  `KeyFingerprint` preferred over pinned (more current); timestamps
  + verified state come from pinned. Inline markers for `admin` /
  `retired` / `verified`|`unverified`. Smart timestamp rendering:
  `key updated` omitted when equal to `first seen`. New store
  helper `GetPinnedKeyInfo` returns the full pinned-keys row. 14
  new drift-guard tests in `internal/tui/whois_test.go`. Full
  sshkey-term `-race` suite green; staticcheck clean.
- **2026-04-19** — Identity-verb completion parity (`/whois`,
  `/verify`, `/unverify`). Extended the F29 resolution parity to
  tab-completion: all three identity verbs now complete against the
  merged `(groupMembers ∪ nonMemberPool)` pool in
  `CompleteWithContext`, so operators can tab-complete any known
  user regardless of current-group membership. Previously these
  verbs fell to the default case which only searched `groupMembers`,
  missing everyone outside the current group. 7 drift-guard tests in
  `identity_verb_completion_test.go` cover the group-member case,
  non-member case (the F30 critical path — without the merged pool
  this test fails), empty-pool-returns-nil, disjoint-pools-no-dup,
  and a regression guard that `/add` still filters to
  non-members-only.
- **2026-04-19** — F27 accepted with documented scope. The
  originally-MEDIUM "send-path gate on verified" feature rejected
  after discussion with project owner: verification is voluntary
  by design, enforcement-on-send would turn the client into a
  compliance tool for a policy most users never opted into, and the
  detection story (F1 + F3 + F30) is already comprehensive.
  Industry precedent for consumer messaging (Signal, WhatsApp,
  iMessage) is detection-only. Residual MITM-mid-conversation risk
  is accepted — F3's modal gives users a chance to stop, and the
  tradeoff is appropriate for the project's small-to-medium
  community deployment target.
- **2026-04-19** — F28 design inverted. The original proposal was
  a warning glyph (⚠) on unverified peers. Inverted to a positive
  affirmation glyph (✓) on VERIFIED peers only — rewards users who
  engaged with the verification feature without nagging users who
  didn't. Symmetric with F27's rejection of enforcement. Still
  Open (deferred to v0.2.1); natural pairing with F3's TOFU UI
  wire-up since both surfaces share pinned_keys reads and
  sidebar/memberpanel render paths.
- **2026-04-19** — F31 accepted as hygiene. Originally flagged as
  open polish (deferred to v0.2.1). On review, the residual
  `pinned_keys` row for a retired user is intentional: F30's
  `/whois` retired-user fallback depends on it ("did Alice's key
  ever rotate before she was retired?" forensic trail). Storage
  cost is negligible (~150 bytes/row), and the data is local to
  the client. No cleanup code planned; operator-side one-line
  SQL available if needed.
- **2026-04-19** — F3 + F28 closed in one coordinated sshkey-term
  release. **F3.a** wire-up: new `OnKeyWarning` callback on
  `client.Config`, fired from `StoreProfile` on detected
  fingerprint mismatch, routed via new `keyWarnCh chan
  KeyChangeEvent` channel through `waitForMsg` to `App.Update`
  which calls `keyWarning.Show`. Non-blocking send from client
  readLoop; 10-event buffer. **F3.c** accept nudge: status bar
  message now includes `"Run /verify <name> to compare safety
  numbers out-of-band."`. **F3.d** modal copy rewritten to remove
  the "or the user's key was rotated" line (false by design) and
  replace with explicit no-rotation framing pointing at the three
  real anomaly classes (compromised server, server bug, DB
  tampering) + the legitimate retirement + new-account flow. F3.b
  (safety-number augmentation) formally dropped per the
  2026-04-19 scope revision. **F28** discovered to be
  already-shipped across five TUI surfaces (sidebar, infopanel,
  memberpanel, newconv, verify); drift-guard tests added. 10 new
  tests (5 client-package, 5 tui-package). Full `-race` suite
  green on sshkey-term.
- **2026-04-19** — No-rotation protocol framing reinstated across
  the audit. F3, F27, F28, F32 entries updated to reflect that
  **user keys do not rotate in sshkey-chat by design** — a user's
  SSH key IS their identity; "new key" scenarios are handled via
  account retirement + a new account under a different user ID,
  not via key mutation on an existing ID. Consequences threaded
  through:
  - F3 scope trimmed to F3.a + F3.c + F3.d (F3.b dropped). F3.d
    added: fix the modal copy that currently says "the user's key
    was rotated" — false by design. Replace with explicit
    no-rotation framing.
  - F27 residual-risk paragraph tightened: the attack class is
    narrower than originally described because F3's modal fires
    on ANY fingerprint mismatch (not just for previously-verified
    users), so the "unverified-user-gets-silently-MITM'd" class
    is already covered by detection-only. Enforcement-on-send
    closes no additional attack class.
  - F28: disappearing ✓ now framed as unambiguous anomaly signal
    (there is no legitimate rotation to benign-ify a disappearance).
    Makes the feature's value clearer.
  - F32: the `ClearVerified` + schema ON-CONFLICT-CASE redundancy
    explicitly flagged as attack-path code (belt-and-braces for
    the one class of event the code is designed to catch), NOT
    ordinary-state-management duplication. Future maintainers
    MUST justify stripping either path with explicit reasoning,
    not "it looks redundant."
  - `PROTOCOL.md` — new `### Keys as Identities (no-rotation
    invariant)` section before Account Retirement, codifying the
    invariant for client-builders and explaining the three causes
    of a detected fingerprint mismatch (server bug, compromised
    server, local DB tampering).
- **2026-04-19** — F11 fixed (documentation). Added pitfall 10 to
  `PROTOCOL.md` Common Pitfalls showing both send-path and edit-path
  canonical forms with file:line refs, explaining the accepted-
  limitation / closed-dangerous-variant asymmetry, and giving four
  actionable consequences for client builders (send = authenticity
  not authorization-to-edit; verify-or-drop edit broadcasts; keep
  send/edit signature sets distinct via domain separation; prompt-
  before-transmit for offline-composed sends). Drift-guard test is
  Phase 22 item 15 — one test covers both pitfall 9 and pitfall 10's
  visibly-new-row contract.
- **2026-04-19** — F7 + F13 fixed; F8 + F20 deferred to Phase 22.
  F7: added `s.store == nil` guard to `handleDownload` with
  privacy-uniform `not_found` response. F13: added "Why the
  asymmetry" paragraph to PROTOCOL.md Message Deletion section
  explaining the rooms-moderation vs. peer-admin rationale. F8 and
  F20 (both test-coverage drift guards, not active vulnerabilities)
  formally tracked as Phase 22 items 13 and 14 in
  `refactor_plan.md`.
