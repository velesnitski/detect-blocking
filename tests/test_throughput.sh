#!/usr/bin/env bash
#
# tests/test_throughput.sh — verify probe 13 (data-plane throughput) wiring:
# the probe must report "skipped" when probe 12 didn't bring up a tunnel,
# and the JSON schema must expose its keys even in the skipped state.
#
# We don't require xray-core in CI; we drive the probe through the normal
# --xray-config-json path with a missing config file so probe 12 reports
# config-missing and probe 13 falls through to skipped.

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "$out" >&2; exit 1; }

# Case A — probe 12 didn't succeed → throughput must be 'skipped'
out=$(VPN_HOST=www.example.com TIMEOUT=2 \
      bash "$SCRIPT" --xray-config-json /tmp/__not_a_real_path__.json \
        --only xrayjson --json 2>&1)

status=$(printf '%s' "$out" | jq -r '.probes.xray_throughput.status')
[ "$status" = "skipped" ] \
  || fail "expected throughput.status=skipped when probe 12 fails, got '$status'"

# Schema sanity — all keys must exist on the throughput block even when skipped.
printf '%s' "$out" | jq -e '
  .probes.xray_throughput
  | has("status")
    and has("bytes_per_second")
    and has("bytes_received")
    and has("seconds")
    and has("target_bytes")
' >/dev/null \
  || fail "xray_throughput schema missing required keys"

# target_bytes must be a positive integer regardless of whether probe ran.
target=$(printf '%s' "$out" | jq -r '.probes.xray_throughput.target_bytes')
case "$target" in
  ''|*[!0-9]*) fail "target_bytes must be numeric, got '$target'" ;;
esac
[ "$target" -gt 0 ] || fail "target_bytes must be > 0, got '$target'"

echo "PASS: probe 13 (throughput) skips cleanly + schema exposes expected keys"
