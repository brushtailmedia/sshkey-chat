#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
THRESHOLDS="$ROOT/docs/testing/coverage_thresholds.txt"
GO_BIN="${GO_BIN:-go}"

if [[ ! -f "$THRESHOLDS" ]]; then
  echo "coverage guard: missing thresholds file at $THRESHOLDS" >&2
  exit 1
fi

trim() {
  sed 's/^[[:space:]]*//; s/[[:space:]]*$//'
}

fail=0
checked=0

while IFS='|' read -r raw_pkg raw_min _; do
  if [[ -z "${raw_pkg//[[:space:]]/}" ]]; then
    continue
  fi
  if [[ "${raw_pkg#"${raw_pkg%%[![:space:]]*}"}" == \#* ]]; then
    continue
  fi

  pkg="$(printf '%s' "$raw_pkg" | trim)"
  min="$(printf '%s' "$raw_min" | trim)"
  if [[ -z "$pkg" || -z "$min" ]]; then
    continue
  fi

  checked=$((checked + 1))
  echo "coverage guard: checking $pkg (>= ${min}%)"

  output="$(cd "$ROOT" && "$GO_BIN" test -cover -count=1 -p 1 "$pkg" 2>&1)" || {
    echo "$output" >&2
    echo "coverage guard: go test failed for $pkg" >&2
    fail=1
    continue
  }

  echo "$output"
  got="$(printf '%s\n' "$output" | sed -n 's/.*coverage: \([0-9.][0-9.]*\)% of statements.*/\1/p' | tail -n1)"
  if [[ -z "$got" ]]; then
    echo "coverage guard: could not parse coverage percentage for $pkg" >&2
    fail=1
    continue
  fi

  if ! awk -v got="$got" -v min="$min" 'BEGIN { exit (got+0 >= min+0) ? 0 : 1 }'; then
    echo "coverage guard: FAIL $pkg coverage ${got}% is below threshold ${min}%" >&2
    fail=1
    continue
  fi

  echo "coverage guard: PASS $pkg coverage ${got}% >= ${min}%"
done < "$THRESHOLDS"

if [[ "$checked" -eq 0 ]]; then
  echo "coverage guard: no packages configured in $THRESHOLDS" >&2
  exit 1
fi

if [[ "$fail" -ne 0 ]]; then
  exit 1
fi

echo "coverage guard: PASS (${checked} package thresholds met)"
