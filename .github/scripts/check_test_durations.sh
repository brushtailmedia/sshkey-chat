#!/usr/bin/env bash
# Duration guard (nightly): serial wall time per package and per top-level
# test against docs/testing/duration_budgets.txt.
#
#   bash .github/scripts/check_test_durations.sh            # runs the suite once, scores it
#   bash .github/scripts/check_test_durations.sh run.json   # scores a saved `go test -json` run
#
# Env: GO_BIN (default: go); DURATION_TOLERANCE (default: 2) — CI runners are
# slower and noisier than a workstation, so a budget fails only past this
# factor. The scorer is .github/scripts/testbudget.go.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GO_BIN="${GO_BIN:-go}"
BUDGETS="$ROOT/docs/testing/duration_budgets.txt"
TOLERANCE="${DURATION_TOLERANCE:-2}"

if [[ ! -f "$BUDGETS" ]]; then
  echo "duration guard: missing budgets file at $BUDGETS" >&2
  exit 1
fi

json="${1:-}"
if [[ -z "$json" ]]; then
  json="$(mktemp)"
  trap 'rm -f "$json"' EXIT
  echo "duration guard: running the suite once (serial, no race) to measure it"
  # A failing test must still produce the report; the scorer exits 1 on it.
  (cd "$ROOT" && "$GO_BIN" test -count=1 -p 1 -json ./... > "$json") || true
fi

(cd "$ROOT" && "$GO_BIN" run .github/scripts/testbudget.go \
  -budgets "$BUDGETS" -tolerance "$TOLERANCE" -root "$ROOT" "$json")
