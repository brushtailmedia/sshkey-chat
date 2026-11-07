#!/usr/bin/env bash
set -euo pipefail

# nested-db guard (store-write Part 1).
#
# Every SQLite handle is capped at one connection and takes a write mutex
# on Exec/Begin (internal/store/db.go). A goroutine that holds a Tx or an
# open rows cursor on a handle and then issues another query on the SAME
# handle waits for the connection (and mutex) its own caller holds —
# forever. This guard fails the build on the three shapes that cause it,
# in production code under internal/store and internal/server:
#
#   (a) inside a Begin()/BeginTx() ... Commit() window, any Exec / Query /
#       QueryRow / Prepare that is not on the tx (or a tx.Prepare stmt);
#   (b) a db-level Prepare anywhere (only tx.Prepare is allowed);
#   (c) a second Exec / Query / QueryRow on any handle while a `rows`
#       cursor from `rows, err := x.Query(...)` is still open in the same
#       function (not yet rows.Close()d, and not deferred).
#
# It is the mechanical form of the audit in
# docs/planning/open/PLAN-store-write-serialization.md step 4.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

files=()
for f in internal/store/*.go internal/server/*.go; do
  case "$f" in *_test.go | internal/store/db.go) continue ;; esac # db.go defines the wrapper's own Begin
  files+=("$f")
done

hits_file="$(mktemp)"
trap 'rm -f "$hits_file"' EXIT

begin_sites=0
for f in "${files[@]}"; do
  n="$(grep -c '\.Begin()\|\.BeginTx(' "$f" || true)"
  begin_sites=$((begin_sites + n))

  # (a) handle use inside a transaction window.
  awk -v F="$f" '
    /\.Begin\(\)|\.BeginTx\(/ { inwin = 1 }
    inwin && /\.(Exec|Query|QueryRow|Prepare)\(/ && $0 !~ /(tx|stmt)\.(Exec|Query|QueryRow|Prepare)\(/ && $0 !~ /^[\t ]*\/\// {
      print "(a) handle used inside a transaction window: " F ":" NR ": " $0
    }
    inwin && /\.Commit\(\)/ { inwin = 0 }
    /^}/ { inwin = 0 }
  ' "$f" >> "$hits_file"

  # (b) db-level Prepare.
  awk -v F="$f" '
    /\.Prepare\(/ && $0 !~ /tx\.Prepare\(/ && $0 !~ /^[\t ]*\/\// {
      print "(b) db-level Prepare: " F ":" NR ": " $0
    }
  ' "$f" >> "$hits_file"

  # (c) a query while a rows cursor is open in the same function.
  awk -v F="$f" '
    /^func /                                   { name = $0; open = 0; deferred = 0 }
    /rows, err :?= .*\.Query\(|rows, err = .*\.Query\(/ { open = 1; deferred = 0; next }
    /defer rows\.Close\(\)/                    { deferred = 1 }
    /^[\t ]*rows\.Close\(\)/                   { if (!deferred) open = 0 }
    {
      if (open && $0 ~ /\.(Exec|Query|QueryRow)\(/ && $0 !~ /rows\./) {
        sub(/^func /, "", name); sub(/\{.*/, "", name)
        print "(c) query while a rows cursor is open: " F ":" NR ": in " name " -> " $0
      }
    }
    /^}/ { open = 0; deferred = 0 }
  ' "$f" >> "$hits_file"
done

if [[ -s "$hits_file" ]]; then
  echo "nested-db guard: FAIL" >&2
  echo "A handle is used while the same goroutine holds a Tx or an open cursor on it — with the one-connection pool and the write mutex this deadlocks. Pass the tx, or materialise the cursor first." >&2
  cat "$hits_file" >&2
  exit 1
fi

echo "nested-db guard: PASS ($begin_sites transaction sites, no nested handle use)"
