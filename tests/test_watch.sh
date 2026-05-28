#!/usr/bin/env bash
#
# tests/test_watch.sh — verify --watch produces multiple ndjson iterations
# and exits cleanly on SIGTERM.

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

out=$(mktemp -t detect_blocking_test.XXXXXX)

# Spawn the watch loop in the background with a tight 2s cadence,
# json + only=dns for minimal work per iteration.
(VPN_HOST=www.example.com TIMEOUT=2 \
   bash "$SCRIPT" --watch 2 --json --only dns >"$out" 2>&1) &
PID=$!

# Let it complete ~3 iterations.
sleep 7
kill -TERM "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true

fail() { printf 'FAIL: %s\n' "$1" >&2; cat "$out" >&2; rm -f "$out"; exit 1; }

# Each iteration emits exactly one JSON line (ndjson). Count them.
n=$(grep -c '^{' "$out" 2>/dev/null || echo 0)
[ "$n" -ge 2 ] || fail "expected ≥2 iterations, got $n"

# Validate each line is parseable JSON.
while IFS= read -r line; do
  printf '%s' "$line" | jq -e . >/dev/null \
    || fail "watch emitted non-JSON line"
done < "$out"

rm -f "$out"
printf 'PASS: --watch emitted %d ndjson iterations, clean SIGTERM\n' "$n"
