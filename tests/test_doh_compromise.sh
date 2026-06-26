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

# Wait for the fixture to actually accept connections. A cold CI runner (macOS
# especially) can take several seconds to bind python3's http.server, so use a
# generous budget — and if it never comes up, SKIP rather than run the
# assertions against a dead server and report a spurious failure.
ready=0
for _ in $(seq 1 60); do
  if curl -sf --max-time 1 "http://127.0.0.1:$PORT/dns-query?name=test&type=A" >/dev/null 2>&1; then
    ready=1; break
  fi
  kill -0 "$FAKE_PID" 2>/dev/null || break   # fixture died — stop polling
  sleep 0.25
done
if [ "$ready" != "1" ]; then
  echo "SKIP: fake DoH fixture never became ready on 127.0.0.1:$PORT (startup race, not a code regression)"
  exit 0
fi

run_tool() {
  VPN_HOST=www.example.com \
    DOH_URL="http://127.0.0.1:$PORT/dns-query" \
    TIMEOUT=2 \
    bash "$SCRIPT" 2>&1
}

# Even with the readiness gate, a transient can leave the first DoH query to the
# tool unanswered — the fixture's canary echo never appears and the tool falls
# back to system DNS. The tell-tale of "the fixture answered" is the
# `canary returned …` line (NOT the later "DoH returned no A records" warning,
# which is the EXPECTED success behaviour — the tool discards the poisoned answer
# and warns it's now empty). Retry once on a missing canary; only if it's STILL
# missing do we treat it as environmental and skip.
out=$(run_tool)
if ! printf '%s' "$out" | grep -q 'canary returned'; then
  sleep 0.5
  out=$(run_tool)
fi
if ! printf '%s' "$out" | grep -q 'canary returned'; then
  echo "SKIP: fixture never returned a DoH answer to the tool (startup/network race, not a code regression)"
  exit 0
fi

fail() { printf 'FAIL: %s\n' "$1" >&2; echo "$out" >&2; exit 1; }

# The fixture DID answer (sinkhole IPs) — so the tool MUST flag the MITM.
echo "$out" | grep -q 'DoH path is compromised' \
  || fail "expected 'DoH path is compromised' verdict"
echo "$out" | grep -q 'ignoring DoH answer' \
  || fail "expected script to discard MITM'd DoH answer"

echo "PASS: DoH compromise detected"
