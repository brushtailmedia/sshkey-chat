#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ALLOWLIST="$ROOT/docs/testing/sleep_allowlist.txt"

if [[ ! -f "$ALLOWLIST" ]]; then
  echo "sleep guard: missing allowlist at $ALLOWLIST" >&2
  exit 1
fi

hits_file="$(mktemp)"
allow_file="$(mktemp)"
trap 'rm -f "$hits_file" "$allow_file"' EXIT

rg -n 'time\.Sleep\(' "$ROOT" --glob '**/*_test.go' -S \
  | sed "s#^$ROOT/##" \
  | cut -d: -f1,2 \
  | sort -u > "$hits_file"

grep -Ev '^[[:space:]]*($|#)' "$ALLOWLIST" \
  | cut -d'|' -f1 \
  | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
  | sort -u > "$allow_file"

missing="$(comm -23 "$hits_file" "$allow_file" || true)"
if [[ -n "$missing" ]]; then
  while IFS= read -r hit; do
    [[ -z "$hit" ]] && continue
    echo "sleep guard: unallowlisted time.Sleep callsite: $hit" >&2
  done <<< "$missing"
  echo "sleep guard: add rationale entry to docs/testing/sleep_allowlist.txt" >&2
  exit 1
fi

count="$(wc -l < "$hits_file" | tr -d ' ')"
echo "sleep guard: PASS (${count} allowlisted callsites)"
