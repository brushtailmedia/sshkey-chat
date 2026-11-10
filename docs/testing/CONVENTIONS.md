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

Keep intentional malformed test input and its rejection assertions unchanged.
Attach `// malformed: <specific reason>` to the same source line as that input;
a bare marker, an unrelated comment or a marker on another line does not exempt
it. The lint's own regression corpus locks these rules. Do not replace a negative
fixture with a valid builder to make the guard pass.

The server guard scans `internal/server`, `internal/store` and
`cmd/sshkey-server` test files for `usr_`, `room_`, `group_`, `dm_`, `msg_`,
`react_`, `file_` and `up_`. Device IDs are deliberately excluded.
