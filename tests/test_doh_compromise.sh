#!/usr/bin/env bash
#
# tests/test_doh_compromise.sh — spin up a local fake DoH server that
# returns sinkhole IPs for any query (including the integrity canary).
# Assert the script detects the MITM and emits the corresponding verdict.

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
FAKE="$SCRIPT_DIR/tests/fake_doh.py"
PORT="${FAKE_DOH_PORT:-58880}"

command -v python3 >/dev/null || {
  echo "SKIP: python3 not available for fake DoH fixture"
  exit 0
}

# Free the port if a previous run left something behind.
kill_existing() {
  local pids
  pids=$(lsof -ti tcp:"$PORT" 2>/dev/null || true)
  [ -n "$pids" ] && kill $pids 2>/dev/null || true
}
kill_existing

python3 "$FAKE" "$PORT" >/dev/null 2>&1 &
FAKE_PID=$!
cleanup() { kill "$FAKE_PID" 2>/dev/null || true; }
trap cleanup EXIT

# Wait for server to be ready (poll with a small budget).
for _ in 1 2 3 4 5 6 7 8 9 10; do
  if curl -sf --max-time 1 "http://127.0.0.1:$PORT/dns-query?name=test&type=A" >/dev/null 2>&1; then
    break
  fi
  sleep 0.2
done

out=$(VPN_HOST=www.example.com \
       DOH_URL="http://127.0.0.1:$PORT/dns-query" \
       TIMEOUT=2 \
       bash "$SCRIPT" 2>&1)

fail() { printf 'FAIL: %s\n' "$1" >&2; echo "$out" >&2; exit 1; }

echo "$out" | grep -q 'canary returned' \
  || fail "expected canary mismatch line"
echo "$out" | grep -q 'DoH path is compromised' \
  || fail "expected 'DoH path is compromised' verdict"
echo "$out" | grep -q 'ignoring DoH answer' \
  || fail "expected script to discard MITM'd DoH answer"

echo "PASS: DoH compromise detected"
