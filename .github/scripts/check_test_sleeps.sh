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

# grep -rn is portable (ripgrep is not guaranteed on default GitHub runners).
# -F treats 'time.Sleep(' as a literal string, so we don't have to juggle BRE
# vs ERE escape rules for the paren. || true keeps pipefail quiet when the
# tree has zero matches.
{ grep -rn --include='*_test.go' -F 'time.Sleep(' "$ROOT" || true; } \
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
