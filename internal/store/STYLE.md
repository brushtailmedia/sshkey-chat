# `internal/store` Style Guide

This package owns all persistent state for sshkey-chat. A single wrong
query can corrupt state, leak data, or open an injection surface, so
code here is under tighter review than handler-layer code. This
document captures the review rules that apply in the store package.

## SQL parameterisation

**Rule.** Every SQL statement in this package uses `?` placeholders
for every value that is not a compile-time string literal. `db.Exec`,
`db.Query`, `db.QueryRow`, and `conn.PrepareContext` all accept
placeholder args — use them.

**The one acceptable exception** — switch-selected column names over
a closed set of store-controlled string literals, as in
`direct_messages.go`:

```go
var col string
switch userID {
case dm.UserA:
    col = "user_a_left_at"
case dm.UserB:
    col = "user_b_left_at"
default:
    return fmt.Errorf("user %q is not a party to DM %q", userID, dmID)
}
_, err := s.dataDB.Exec(
    fmt.Sprintf(`UPDATE direct_messages SET %s = ? WHERE id = ? AND %s < ?`, col, col),
    leftAt, dmID, leftAt,
)
```

This is safe because `col` is assigned exclusively from hardcoded
literals inside a switch; user input (`userID`) is the **switch
discriminator**, not a branch value. The format string contains only
the two possible literal values `"user_a_left_at"` /
`"user_b_left_at"`, never any caller-controlled bytes.

Any other use of `fmt.Sprintf` with SQL fragments, or `"..." + x`
string concatenation, is an injection surface and must be rewritten
to use `?` placeholders.

## Review guidance

A PR that introduces a new `fmt.Sprintf(...SQL...)` or string-
concatenated SQL must include:

1. A justification in the commit message or PR description
   explaining why `?` placeholders cannot be used for the
   interpolated token.
2. Proof that every interpolated value comes from a closed set of
   store-controlled literals — not from caller-controlled input.
3. A new entry in `docs/security/sql_audit.md`'s "Findings" section
   documenting the pattern and why it's safe.

A drift-guard test (scheduled as **Phase 22 item 17** of
`refactor_plan.md`, tracking `audit_v0.2.0.md#F16`) will mechanically
flag new occurrences once implemented.

## See also

- `docs/security/sql_audit.md` — Phase 21 SQL sweep findings + audit
  methodology.
- `docs/security/audit_v0.2.0.md#F16` — SQL drift-guard test
  schedule.
