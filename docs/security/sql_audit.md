# SQL Injection Sweep

> **Produced during Phase 21 (2026-04-19) as audit-only output.**
> Companion to `audit_v0.2.0.md`. No code changes during the audit.

## Scope

Every `*.go` file under:
- `internal/store/` (primary SQL surface)
- `internal/server/` (handler-layer SQL if any — should be none)
- `cmd/sshkey-ctl/` (CLI administrative SQL)

Audited for:
1. String concatenation in SQL (`"SELECT ..." + variable`)
2. `fmt.Sprintf` with SQL-shaped format strings where any `%` verb
   interpolates user-controllable input.
3. `db.Exec` / `db.Query` / `db.QueryRow` called with any non-literal
   first argument.

## Methodology

Two ripgrep patterns were run against the tree:

```
rg 'fmt\.Sprintf.*(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP|WHERE|FROM|INTO|SET)'
rg '"(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP).*"\s*\+'
rg '\+\s*".*(WHERE|FROM|VALUES|SET)'
```

Every match was manually inspected for whether the interpolated value
is caller-controlled.

## Findings

### Finding 1 — `direct_messages.go:156`

```go
_, err = s.dataDB.Exec(
    fmt.Sprintf(`UPDATE direct_messages SET %s = ? WHERE id = ? AND %s < ?`, col, col),
    leftAt, dmID, leftAt,
)
```

**Context:** `col` is chosen by a `switch userID { case dm.UserA: col =
"user_a_left_at"; case dm.UserB: col = "user_b_left_at"; default:
return error }` at lines 145-152.

**Analysis:** `col` takes only two possible values, both hardcoded
string literals chosen by a switch. The value `userID` (caller input)
is matched against `dm.UserA` / `dm.UserB` (store-controlled) — it does
not flow into the format string. All actual values (`leftAt`, `dmID`)
use `?` placeholders.

**Verdict:** SAFE. No SQL injection surface.

**Drift risk:** If a future refactor adds a third case that passes
`userID` verbatim into `col`, the injection surface appears. Mitigation
is a drift-guard test (see recommendation below).

### Finding 2 — `failing_store_test.go:40`

```go
if err := s.store.ExecRaw("DROP TABLE " + table); err != nil {
    t.Fatalf("drop table %s: %v", table, err)
}
```

**Context:** Test-only helper `dropDataTable` used to exercise
failure-injection paths. Callers pass literal table names
(`"messages"`, `"files"`, etc.) as string literals.

**Analysis:** Test code only, never linked into production binary.
Callers are test authors, not end users. The `ExecRaw` seam exists
specifically for this test purpose.

**Verdict:** SAFE. Test infrastructure, no production surface.

## Recommendations

### Drift-guard test (LOW priority) — SCHEDULED AS PHASE 22 ITEM 17

Add an automated test that fails CI if a new `fmt.Sprintf` with
SQL-shaped format string is introduced anywhere outside the two audited
exceptions. Shape:

```go
//go:build drift

func TestSQLDriftGuard(t *testing.T) {
    // Walk the tree, grep for fmt.Sprintf(`...WHERE|SELECT|INSERT|...`).
    // Allowlist: direct_messages.go:156, failing_store_test.go:40.
    // Any new match → fail with pointer to sql_audit.md.
}
```

Implementation is ~40 lines of Go using `go/ast`. Not urgent — the
current state is clean and the codebase has low enough SQL churn that
a new finding would be caught in review. Would be nice-to-have for
defense in depth.

**Status 2026-04-19:** Scheduled for implementation as **Phase 22
item 17** of `refactor_plan.md` (the testing-overhaul pass that
also folds in the other Phase 21 test-coverage drift guards — see
`audit_v0.2.0.md#F16`). The refactor_plan entry spells out the
deliverable shape including the allowlist of the two audited
exceptions and leaves room for a `go vet` custom analyzer as an
alternative framing.

### Parameterization hygiene note (DOCUMENTATION) — DONE 2026-04-19

Originally recommended to add one paragraph to
`internal/store/STYLE.md` (or create that file) codifying the rule:
"All SQL in this package uses `?` placeholders for every user-facing
value. The only acceptable use of `fmt.Sprintf` with SQL fragments is
for column names chosen by a switch over a closed set of
store-controlled literals, as in `direct_messages.go`. Review any PR
that introduces another."

**Shipped 2026-04-19:** new `internal/store/STYLE.md` covers the rule
with a concrete safe-pattern example (switch-selected column names
from `direct_messages.go`), three-item review-guidance checklist for
PRs that introduce new format-string SQL fragments, and cross-
references back to this audit doc + `audit_v0.2.0.md#F16` + the
Phase 22 drift-guard item. The style doc is the canonical reference
for future SQL review in the store package.

## Summary

- **2 matches** for SQL-shaped `fmt.Sprintf` in the entire repository.
- **Both safe by construction.** No user-controllable input flows into
  either format string.
- **No string concatenation** (`"SELECT..." + x`) in production code.
- **No concerns** from this sweep.

Status: the server's SQL layer is parameterised correctly. This audit
documents that state and recommends a drift-guard so a regression
would be caught mechanically.
