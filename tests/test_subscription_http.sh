#!/usr/bin/env bash
#
# tests/test_subscription_http.sh — exercise the FULL --subscription fetch path over
# real HTTP (not just file://): the tool must get through a UA gate + a 302 cookie
# challenge to retrieve a JSON array of Xray configs, then run --sub-test all and
# render the fleet table + summary. A wrong UA must be rejected (403 → no configs),
# proving the tool actually sends the client UA. All hermetic: a local stdlib server
# serving SAFE placeholders against loopback closed ports (fast "unreachable" rows).
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
SERVER="$SCRIPT_DIR/tests/fixtures/fake_sub_server.py"
command -v jq      >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP: python3 not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${o:-}" >&2; exit 1; }

# Start the fake panel; read its ephemeral port off a FIFO (no sleep; bounded by
# read -t so a stuck server can't hang the suite).
fifo=$(mktemp -u "${TMPDIR:-/tmp}/subhttp.XXXXXX"); mkfifo "$fifo"
python3 "$SERVER" > "$fifo" 2>/dev/null & srv_pid=$!
trap 'kill "$srv_pid" 2>/dev/null; rm -f "$fifo"' EXIT
portline=""; read -t 10 -r portline < "$fifo" || true
port="${portline#PORT=}"
{ [ -n "$port" ] && [ "$port" != "$portline" ]; } || { echo "SKIP: fake sub server did not start"; exit 0; }
url="http://127.0.0.1:${port}/sub/abc123"

# --- correct UA (default Happ/…) clears the UA gate + cookie challenge → 3 configs ---
o=$(TIMEOUT=2 bash "$SCRIPT" --subscription "$url" --sub-test all --sub-jobs 4 2>&1)
printf '%s' "$o" | grep -q 'fetched 3 config'        || fail "should fetch 3 configs through the UA gate + cookie challenge"
printf '%s' "$o" | grep -q 'Subscription fleet scan' || fail "should run the fleet walk over HTTP-fetched configs"
printf '%s' "$o" | grep -q 'fleet detectability:'    || fail "should print the fleet detectability summary"
printf '%s' "$o" | grep -qiE 'no vless outbound|skip' || fail "the Hysteria (no-proxy) config should be marked skipped"

# --- wrong UA → 403 → tool finds no configs (proves it sends the configured UA) ---
o=$(TIMEOUT=2 bash "$SCRIPT" --subscription "$url" --sub-ua "curl/8.0" --sub-test all 2>&1)
printf '%s' "$o" | grep -qiE 'no configs found|error' || fail "a non-matching UA should be 403'd → no configs"

echo "PASS: --subscription clears a UA gate + 302 cookie challenge over HTTP and walks the fleet; wrong UA is rejected"
