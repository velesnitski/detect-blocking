#!/usr/bin/env bash
#
# tests/test_speedtest.sh — verify probe 14 (multi-stream capacity) wiring:
# it runs by default (status != "disabled" unless opted out), reports
# "skipped" when probe 12 didn't bring up a tunnel, flips to "disabled" with
# --no-speedtest, and exposes its JSON schema either way. No xray-core is
# required in CI — probe 12 won't reach "ok", so probe 14 reports "skipped".

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "$out" >&2; exit 1; }

# Case A — default on: no tunnel (missing config) → status "skipped".
out=$(VPN_HOST=www.example.com TIMEOUT=2 \
      bash "$SCRIPT" --xray-config-json /tmp/__nope__.json \
        --only xrayjson --json 2>&1)
status=$(printf '%s' "$out" | jq -r '.probes.xray_speedtest.status')
[ "$status" = "skipped" ] \
  || fail "expected speedtest status=skipped when probe 12 has no tunnel, got '$status'"

# Schema sanity — keys present even when skipped.
printf '%s' "$out" | jq -e '
  .probes.xray_speedtest
  | has("status") and has("streams") and has("best_endpoint")
    and has("best_bytes_per_second") and has("best_mbps") and has("per_endpoint")
' >/dev/null \
  || fail "xray_speedtest schema missing required keys"

# per_endpoint must be an array.
[ "$(printf '%s' "$out" | jq -r '.probes.xray_speedtest.per_endpoint | type')" = "array" ] \
  || fail "xray_speedtest.per_endpoint must be an array"

# Case B — --no-speedtest opts out entirely → status "disabled".
out=$(VPN_HOST=www.example.com TIMEOUT=2 \
      bash "$SCRIPT" --xray-config-json /tmp/__nope__.json --no-speedtest \
        --only xrayjson --json 2>&1)
status=$(printf '%s' "$out" | jq -r '.probes.xray_speedtest.status')
[ "$status" = "disabled" ] \
  || fail "expected speedtest status=disabled with --no-speedtest, got '$status'"

echo "PASS: probe 14 runs by default, skips without a tunnel, disables on --no-speedtest"
