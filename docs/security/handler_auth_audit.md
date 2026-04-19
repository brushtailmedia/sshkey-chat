# Handler Authentication & Authorization Audit

> **Produced during Phase 21 (2026-04-19) as audit-only output.**
> No code changes during the audit pass. Findings here are triaged in
> `audit_v0.2.0.md`. Status column reflects state at audit time.

## Scope

Every `handle*` function in `internal/server/*.go` that receives a client-
facing protocol verb. 44 handlers total. For each: the gate(s) it SHOULD
enforce, the gate(s) it DOES enforce in code, and the test that verifies
the gate (where one exists).

Out of scope: SSH-layer authentication (handled by `ssh.ServerConfig`
and documented separately), internal goroutine entry points
(`handleRetirement`, `handleAutoRevokeCrossing`) that are not verb
handlers.

## Gate categories

- **Admin-only** — global admin flag required. Checked via `IsAdmin`.
- **Group-admin-only** — must be an admin of the specific group.
  Checked via `checkGroupAdminAuth` / `IsGroupAdmin`.
- **Member-only** — must be a member of the specific room/group/DM.
  Checked via `IsRoomMemberByID` / `IsGroupMember` / DM party check.
- **Owner-only** — must own the thing. Checked via comparing
  `sender == c.UserID` or equivalent.
- **Any authenticated user** — gate is just "connection authenticated."

## Matrix

| Handler | Required gate | Enforced at | Test | Status |
|---|---|---|---|---|
| handleSend | Room member (byte-identical on non-member) | `session.go:890` | `send_test.go` | CLEAN |
| handleSendGroup | Group member | `session.go:1041` | (implicit) | CLEAN |
| handleSendDM | DM party | (store layer) | (implicit) | CLEAN |
| handleEdit | Room member + message author | `edit.go:81` | `edit_test.go` | CLEAN |
| handleEditGroup | Group member + author | `edit.go:203` | (implicit) | CLEAN |
| handleEditDM | DM party + author | `edit.go:315` | (implicit) | CLEAN |
| handleDelete | Own message (rooms: OR admin) | `session.go:1787, 1820, 1861, 1902` | (implicit) | CLEAN* |
| handleReact | Member + not-tombstoned | `session.go:1274` | `react_tombstone_test.go` | CLEAN |
| handleUnreact | Owner (via search loop) | `session.go:1461-1523` | (implicit) | CLEAN |
| handlePin | Room member + not-retired | `session.go:1587` | (implicit) | CLEAN |
| handleUnpin | Room member + not-retired | `session.go:1635` | (implicit) | CLEAN |
| handleHistory | Context member (via sync) | `sync.go:366` | (implicit) | CLEAN |
| handleRoomMembers | Room member (byte-identical via `sendUnknownRoom`) | `session.go:3431` | `room_members_test.go` (`TestHandleRoomMembers_PrivacyResponsesIdentical`) | CLEAN (fixed 2026-04-19, see F1) |
| handleAddToGroup | Group admin (byte-identical) | `group_admin.go:112` | `group_admin_test.go` | CLEAN |
| handleRemoveFromGroup | Group admin (byte-identical) | `group_admin.go:271` | `group_admin_test.go` | CLEAN |
| handlePromoteGroupAdmin | Group admin (byte-identical) | `group_admin.go:340` | `group_admin_test.go` | CLEAN |
| handleDemoteGroupAdmin | Group admin (byte-identical) | `group_admin.go:414` | `group_admin_test.go` | CLEAN |
| handleRenameGroup | Group admin (byte-identical) | `session.go:2789` (checkGroupAdminAuth) | `group_admin_test.go` | CLEAN |
| handleCreateGroup | Authenticated + non-retired members | `session.go:1689` | (implicit) | CLEAN |
| handleLeaveGroup | Group member | `session.go:2119` | (implicit) | CLEAN |
| handleDeleteGroup | Group member (soft-delete owner flag only) | `session.go:2325` | `deletegroup_test.go` | CLEAN |
| handleLeaveRoom | Room member | `session.go:2466` | `leaveroom_test.go` | CLEAN |
| handleDeleteRoom | Room member (soft-delete owner flag) | `session.go:2654` | `deleteroom_test.go` | CLEAN |
| handleCreateDM | Authenticated (+ 1:1 user existence) | `session.go:2862` | (implicit) | CLEAN |
| handleLeaveDM | DM party | `session.go:3049` | `leavedm_test.go` | CLEAN |
| handleSetProfile | Owner (own profile) | `session.go:3155` | (implicit) | CLEAN |
| handleSetStatus | Owner (own status) | `session.go:3242` | (none visible) | CLEAN (no test) |
| handleRetireMe | Owner (own account) | `retirement.go:281` | `retirement_test.go` | CLEAN |
| handleListDevices | Owner (own device list) | `devicemgmt.go:13` | `devicemgmt_test.go` | CLEAN (no privacy regression test) |
| handleRevokeDevice | Owner (device belongs to user) | `devicemgmt.go:104-136` | `device_revocations_test.go` | CLEAN |
| handleListPendingKeys | Global admin | `session.go:3371` | (none visible) | CLEAN (gate correct; no test) |
| handleUploadStart | Authenticated (+ per-user quota) | `filetransfer.go:240+` | `upload_auth_test.go` | CLEAN |
| handleDownload | Context member + ACL (+ nil-store guard) | `filetransfer.go:576` | `download_acl_test.go` | CLEAN (F2 fixed 2026-04-19) |
| handleTyping | Any authenticated | `session.go:1118` | (implicit) | CLEAN |
| handleRead | Any authenticated | `session.go:1174` | (implicit) | CLEAN |
| handlePushRegister | Any authenticated | `pushhandler.go:11` | (implicit) | CLEAN |
| handleEpochRotate | Room member (client-side hint) | `epoch.go:268` | (implicit) | CLEAN |

\* handleDelete asymmetry noted under "documentation gaps" below.

## Findings

### F1 (CRITICAL → FIXED 2026-04-19) — handleRoomMembers privacy leak

**File:** `internal/server/session.go:3431-3433` (pre-fix).

**Previous behaviour:** when a non-member requested `room_members` for
a room they were not in, the handler responded with `ErrNotAuthorized`
and a message of the form `"You are not a member of room: " + req.Room`.

**Expected behaviour (Phase 14 privacy invariant):** byte-identical
`ErrUnknownRoom` response, matching the pattern used by `handleSend`,
`handleEdit`, `handleReact`, `handlePin`, `handleUnpin`. A probing
client must not be able to distinguish "room exists, you're not a
member" from "room doesn't exist."

**Impact.** A client could enumerate room existence by sending
`room_members` requests and diffing responses. This defeated the
byte-identical invariant documented in PROTOCOL.md and enforced
everywhere else in the codebase.

**Fix applied 2026-04-19.** Replaced the `ErrNotAuthorized` branch
with a call to the existing `sendUnknownRoom(c)` helper (defined at
`edit.go:438-440`), which collapses both the nil-store defensive path
and the non-member path into a single byte-identical response. The
`req.Room` echo was removed; the helper's generic "You are not a
member of this room" message is identical to the one used by
`handleEdit` and `handleSend`, so all four verbs are now byte-
identical on the non-member / unknown-room paths.

**Test.** New `TestHandleRoomMembers_PrivacyResponsesIdentical` in
`internal/server/room_members_test.go`, modelled on
`TestHandleEdit_PrivacyResponsesIdentical` at `edit_test.go:26-90`.
Asserts `bytes.Equal` across {unknown room, non-member probe}. Also
added `TestHandleRoomMembers_MemberHappyPath` as a non-regression
guard so the fix doesn't break the normal flow.

**Post-fix verification:** `go build ./... && go vet ./... && go test
-count=1 -race ./...` all green.

### F2 (HIGH → FIXED 2026-04-19) — handleDownload guard ordering inconsistency

**File:** `internal/server/filetransfer.go:529+` (pre-fix).

Peer handlers consistently check `s.store == nil` before any store
dereference. `handleDownload` dereferenced `s.store` (via
`authorizeDownload`) without a nil-check in this handler's flow. Not
a bug in production (the server never runs with a nil store), but
drift-prone — a future refactor could introduce a nil-deref
regression.

**Fix applied 2026-04-19.** Added an explicit `s.store == nil` guard
immediately before the `authorizeDownload` call. On the nil branch
the handler calls `respondDownloadError(c, corrID, fileID,
"not_found", "File not found: "+fileID)` — identical to the ACL-deny
and file-missing paths, preserving the privacy-uniform response
shape documented in the handler's opening comment block (lines
525-528). Inline comment references this finding and the master
audit doc.

**Test.** No new test added — the nil-store path is unreachable in
production (`s.store` is set during server startup and never
cleared), so exercising it would require invasive test-only plumbing
that doesn't improve safety. The fix is defensive hardening against
future drift; the happy-path download tests continue to exercise the
authorisation flow as before.

**Post-fix verification:** `go build ./... && go vet ./... && go
test -count=1 -race ./...` all green.

### F3 (MEDIUM → FIXED 2026-04-19) — handleDelete rooms-vs-DMs admin asymmetry undocumented

**Files:**
- `session.go:1820` — rooms path allows admin override of
  own-message-only
- `session.go:1861, 1902` — groups and DMs paths are strictly owner-only

The behaviour is intentional (documented in inline code comments at
1860-1863), but the design rationale was missing from PROTOCOL.md —
a reader of the public spec could see *what* the code does but not
*why* rooms and groups/DMs diverge.

**Fix applied 2026-04-19.** Added a "Why the asymmetry" paragraph to
the `### Message Deletion` section in PROTOCOL.md (after the
existing `**Permissions:**` bullet list) explaining:
- Rooms are the moderation surface (public-by-membership,
  admin-managed; admin-override of delete follows the same
  moderation model as topic/rename/retire).
- Groups use a flat peer-admin model (no moderation role); admin-
  override there would be an escalation without policy justification.
- 1:1 DMs are strictly two-party with no analogous admin role.
- Rare operator interventions in groups/DMs (abuse investigation,
  legal hold) use the `sshkey-ctl` CLI escape hatch acting directly
  on SQLite files — intentionally outside the protocol surface.
- Paragraph cross-references this audit doc and
  `audit_v0.2.0.md#F13` so future readers can trace the rationale.

**No code change.** Pure documentation fix; behaviour is unchanged.

### F4 (MEDIUM → DEFERRED TO PHASE 22) — Missing privacy-regression tests

No `PrivacyResponsesIdentical`-pattern tests for:
- ~~`handleRoomMembers`~~ — **done** as part of F1 (see
  `room_members_test.go`).
- `handleListDevices` (owner-only gate; no explicit non-owner probe test)
- `handleSetStatus` (owner-only gate; no explicit test at all)

**Triage 2026-04-19.** Deferred to **Phase 22 item 13** of
`refactor_plan.md` (Phase 21 handler-auth-audit spin-off). The gates
themselves are correct — these tests lock in the contract as drift
guards rather than closing an active vulnerability. ~1h of test
writing at the dedicated Phase 22 testing-overhaul pass.

### F5 (LOW → DEFERRED TO PHASE 22) — Missing test for handleListPendingKeys gate

**File:** `internal/server/session.go:3371`

The gate (global-admin check) is correct, but no test verifies it.
`TestHandleListPendingKeys_*` doesn't exist. Not a bug — just missing
coverage. (Audit-doc title previously said "Deprecated test assertion"
in error; the accurate title is "missing test for handleListPendingKeys
gate.")

**Triage 2026-04-19.** Deferred to **Phase 22 item 14** of
`refactor_plan.md`. ~30 min of test writing at the Phase 22 pass.

## Summary

- **40 / 44 handlers:** gates correct and tested (implicit or explicit).
- **1 CRITICAL finding (F1):** ~~handleRoomMembers breaks the byte-
  identical privacy invariant.~~ **Fixed 2026-04-19.**
- **1 HIGH finding (F2):** ~~handleDownload guard-order
  inconsistency (defense-in-depth drift surface).~~ **Fixed
  2026-04-19** — nil-store guard added before `authorizeDownload`
  using the same privacy-uniform `not_found` response shape.
- **1 MEDIUM finding (F3):** ~~handleDelete asymmetry doc missing
  from PROTOCOL.md.~~ **Fixed 2026-04-19** — added a "Why the
  asymmetry" paragraph to the Message Deletion section explaining
  the rooms-moderation vs. peer-admin rationale.
- **1 MEDIUM finding (F4):** Missing privacy-regression tests for
  `handleListDevices` + `handleSetStatus`. **Deferred to Phase 22
  item 13** — drift-guard tests locking in the correct gate
  behaviour, not fixing an active vulnerability.
- **1 LOW finding (F5):** Missing test for `handleListPendingKeys`
  admin gate. **Deferred to Phase 22 item 14**.

**Status after 2026-04-19:** all pre-launch-relevant findings
closed. Remaining items are test drift-guards tracked for the
Phase 22 testing-overhaul pass.
