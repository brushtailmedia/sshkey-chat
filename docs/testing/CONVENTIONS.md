# sshkey-chat Testing Conventions

## Scope

This document is the prescriptive test policy for `sshkey-chat` only.
`sshkey-chat` tests `sshkey-chat`. It does not import, exec, or otherwise depend on `sshkey-term` or `sshkey-app` code.

## Product Boundary

- Server protocol correctness is validated in this repo's own integration suite (`cmd/sshkey-server/main_test.go`) using raw Go SSH clients.
- No cross-product test harnesses or build-tagged cross-product paths are allowed.

## Harness Layering

- `integration`: use `cmd/sshkey-server/main_test.go::testEnv` for full TCP + SSH + NDJSON behavior.
- `handler-level`: instantiate `*server.Server` + store with no real SSH transport.
- `store-level`: use real SQLite DB files under `t.TempDir()`.
- `failure-injection`: use `failingStore` where write-path error handling must be asserted.

## Reachability and Absence Checks

- New code is proven through a production entry point. A new verb, frame
  field, config value or stored column needs at least one test that reaches
  it the way production does: through `handleMessage` (the dispatch) at
  handler level, or over the wire in `cmd/sshkey-server`. A direct call to a
  new handler or helper shows that it works, not that anything calls it. A
  changed behaviour of a handler that is already dispatched may be tested by
  calling that handler. A new config value needs a test that sets it and
  observes the behaviour that reads it; a parsing test does not cover a value
  nothing reads.
- An absence assertion needs a positive control. A check that something did
  not happen (no frame, no stored row, no counter, no log record) counts only
  beside a case in which the same check finds that thing: a sibling case, an
  earlier step of the same test, or a well-shaped control row. Without one, a
  wrong type name, a wrong path or a dead channel passes as absence.

## Privacy Regression Pattern

- Membership-sensitive handlers must have `Test<Handler>_PrivacyResponsesIdentical` tests.
- Compare encoded production frames (`protocol.Encoder`) using `bytes.Equal`; do not compare ad-hoc JSON output.

## Helper and Table Discipline

- Every helper that accepts `*testing.T`/`testing.TB` must call `t.Helper()` on entry.
- Prefer table-driven tests for 3+ scenario variants of one setup.
- Use `t.Run` for case-addressable subtests.
- Use `t.Cleanup()` for lifecycle cleanup; avoid parent `defer` for test-scoped resources.

## Fixtures and Data Seeding

- Seed users with `store.InsertUser` into `users.db`.
- Use `testFixtureUsers` and per-test seeding helpers.
- Temporary fixtures must use `t.TempDir()` (no hardcoded `/tmp/sshkey-test-*` paths).

## SQL and Error Assertions

- SQL values in tests must use parameter placeholders (`?`). Identifier construction requires a narrow drift-guard allowlist and an explanation in `docs/security/sql_audit.md`; the read-only S3 snapshot helper quotes schema-derived table names.
- Error assertions must use `errors.Is` / `errors.As` (never string-match on `err.Error()`).

## CorrID and Protocol Assertions

- For corr_id-carrying verbs, assert corr_id echo semantics explicitly.
- Keep tests aligned to production protocol categories/mappings, not ad-hoc client-only interpretations.

## Parallelism and Timing

- `t.Parallel()` is allowed only when tests are isolated (`t.TempDir()`, no package-global mutable state, no shared files).
- No `time.Sleep` for synchronization in new tests; use channels, wait groups, or injected clocks.
- Existing sleep callsites are tracked in `docs/testing/sleep_allowlist.txt`; new callsites must be reviewed and allowlisted with rationale.
- Nightly enforces `docs/testing/duration_budgets.txt` (`.github/scripts/check_test_durations.sh`): serial wall time per package, and 3 s per top-level test unless the func carries a `// slow: <reason>` comment naming the wait.

## Short Mode and Build Tags

- Integration tests must guard with:
  `if testing.Short() { t.Skip("integration test — run without -short") }`
- `-short` is the developer-loop switch (`go test -short ./...` skips the wire suite in `cmd/sshkey-server`). CI runs no separate short pass: it repeated the race pass and was dropped 2026-11-08.
- Do not introduce `//go:build integration`/`//go:build e2e` for server test execution paths.

## Coverage Policy

- Coverage thresholds are enforced by `.github/scripts/check_coverage.sh` using `docs/testing/coverage_thresholds.txt`.
- Coverage thresholds never decrease. Recalculate them after focused tests land and at the end of each implementation plan, using the greater of the existing threshold and floor(measured coverage − 3 percentage points).

## Phase 22b Deferral Registry

No open deferrals remain after the 2026-04-24 deferred-items pass.

- Launch-gate behavior is covered by the new `cmd/sshkey-server/auto_revoke_integration_test.go` suite (including representative-flow counter checks).
- B.5 and B.6 integration scenarios now have concrete `cmd/sshkey-server` coverage (`auto_revoke_integration_test.go`, `upload_quota_integration_test.go`).
- Current CI minimums include: `internal/server` 70.0, `internal/store` 58.0, `internal/protocol` 75.0.

## Identifier Fixtures

Use the pure `internal/testutil` builders for ordinary IDs: `UserID`, `RoomID`,
`GroupID`, `DMID`, `MsgID`, `ReactionID`, `FileID`, and `UploadID`. A readable
label such as `testutil.MsgID("alice-edit")` produces a stable prefixed ID with
21 nanoid characters. `DeviceID` is also available; existing device fixtures and
handshake enforcement belong to the device-session work, not this migration.
Both repositories use SHA-256 of the label and map the first 21 digest bytes
modulo 64 through `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_-`.
Matching hard-coded vectors cover every builder, empty labels and Unicode labels.

`Signature(label)` and `Payload(label, size)` are opaque size fixtures. They do
not promise a valid signature or decryptable ciphertext. Use actual generated
keys, signing and encryption in cryptographic verification and end-to-end tests.

The fixture lint parses Go syntax and checks selected typed ID fields, concrete
message IDs, member/file slices, known store constructor arguments, ID-named
variables, raw JSON, constant concatenations and supported formatting calls.
Runtime-producing calls and variables are not whole-program data-flow checked.
Unsupported constructed strings in recognized ID positions are reported for
review. Non-ID fields (display names, SSH login hints, protocol type names and
trusted system actors) are outside the ID rule. Optional empty fields retain
their protocol semantics. Parse/read failures and an empty scan fail the guard.

Raw JSON `members`, `admins` and `file_ids` arrays are checked element by
element for the repository's selected ID classes, including arrays in nested
message objects.
When an ID-bearing JSON expression cannot be evaluated, the lint reports it
for review instead of skipping its static fields. For example, indexed runtime
formatting (`%[1]s`) is outside the supported template evaluator: rewrite a
valid fixture with supported `%s` formatting/builders. Reserve a malformed
exemption for an actual intentional negative fixture, not a valid unsupported
format. Non-ID JSON/text and disabled ID classes remain outside the scan.

Keep intentional malformed test input and its rejection assertions unchanged.
Attach `// malformed: <specific reason>` to the same source line as that input;
a bare marker, an unrelated comment or a marker on another line does not exempt
it. The lint's own regression corpus locks these rules. Do not replace a negative
fixture with a valid builder to make the guard pass.

The server guard scans `internal/server`, `internal/store` and
`cmd/sshkey-server` test files for `usr_`, `room_`, `group_`, `dm_`, `msg_`,
`react_`, `file_` and `up_`. Device IDs are deliberately excluded.

### Handler ID regression matrix

`internal/server/id_validation_test.go` exercises five malformed forms through
every one of the 68 handler/field/context rows: short, wrong prefix at the
correct byte length, invalid alphabet, oversized suffix and UTF-8 at the correct
byte length. Each case asserts the exact encoded rejection (or silence), one
requesting-device invalid-ID event, no limiter hiding that event, no peer
broadcast/pending upload/typing work, and unchanged logical rows/database files.
Fixed expected wire contracts are independent of the production rejection helper.
Each row also keeps a separate well-shaped control; existing correlation,
authorization, empty-value and flood/size-cap precedence regressions remain.

## Pin/unpin Persistence Regressions

`pin_persistence_test.go` uses real temporary stores and captures both sender and
peer frames. Drop only the room's `pins` table after seeding to force SQL failure.
To test a database-open failure without a production seam, leave the room DB cold
and place a directory at `<dataDir>/data/room-<roomID>.db`; the helper asserts
that `RoomDB` actually fails before invoking the handler. This works without
permission tricks, sleeps or a store interface. Retain the exact correlated
internal-error, operator-log, no-success/no-mutation and invalid-ID-counter
assertions. Success, duplicate/no-op, authorization/retirement precedence and
error-response limiting are separate controls. Keep foreign keys enabled when
checking a well-shaped missing-message pin.

For failed-unpin row preservation, seed an existing pin and install a temporary
`BEFORE DELETE` trigger using `RAISE(ABORT, ...)`. Assert the row and its metadata
survive, with the same error/log/no-success contract. Drop the trigger and repeat
the request to prove normal deletion and fan-out recover once the fault is gone.

Store copied Go source in audit/planning evidence as `.go.txt` or in an archive.
Git-ignored documentation folders are still scanned by `go build/test ./...`;
plain `.go` snapshots can accidentally create packages and break local gates.
