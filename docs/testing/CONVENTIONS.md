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

- Seed users with `store.InsertUser` into `users.db`; never through `users.toml`.
- Use `testFixtureUsers` and per-test seeding helpers.
- Temporary fixtures must use `t.TempDir()` (no hardcoded `/tmp/sshkey-test-*` paths).

## SQL and Error Assertions

- SQL in tests must use parameter placeholders (`?`), never `fmt.Sprintf` SQL construction.
- Error assertions must use `errors.Is` / `errors.As` (never string-match on `err.Error()`).

## CorrID and Protocol Assertions

- For corr_id-carrying verbs, assert corr_id echo semantics explicitly.
- Keep tests aligned to production protocol categories/mappings, not ad-hoc client-only interpretations.

## Parallelism and Timing

- `t.Parallel()` is allowed only when tests are isolated (`t.TempDir()`, no package-global mutable state, no shared files).
- No `time.Sleep` for synchronization in new tests; use channels, wait groups, or injected clocks.
- Existing sleep callsites are tracked in `docs/testing/sleep_allowlist.txt`; new callsites must be reviewed and allowlisted with rationale.

## Short Mode and Build Tags

- Integration tests must guard with:
  `if testing.Short() { t.Skip("integration test — run without -short") }`
- Do not introduce `//go:build integration`/`//go:build e2e` for server test execution paths.

## Coverage Policy

- Coverage thresholds are enforced by `.github/scripts/check_coverage.sh` using `docs/testing/coverage_thresholds.txt`.
- Current thresholds intentionally reflect practical pre-launch baselines and are ratcheted upward only with new focused tests.

## Phase 22b Deferral Registry

No open deferrals remain after the 2026-04-24 deferred-items pass.

- Launch-gate behavior is covered by the new `cmd/sshkey-server/auto_revoke_integration_test.go` suite (including representative-flow counter checks).
- B.5 and B.6 integration scenarios now have concrete `cmd/sshkey-server` coverage (`auto_revoke_integration_test.go`, `upload_quota_integration_test.go`).
- B.15 ratchet is applied in CI thresholds: `internal/server` 54.0, `internal/store` 54.0, `internal/protocol` 75.0.
