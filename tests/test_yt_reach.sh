#!/usr/bin/env bash
#
# tests/test_yt_reach.sh — fast wiring/schema check for the YouTube fan-out probe.
# The live behaviour (open N connections through the tunnel; clean/capped/degraded/
# all-failed) needs a real xray tunnel + internet, so it's verified manually and via
# the shared _classify_conn_limit (test_conn_limit.sh). Here we only check, WITHOUT
# spawning xray, that: the youtube_reach JSON block is always present + well-formed,
# and the --yt-test / --no-yt-test flags are wired into help.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }

# A DNS-only run never reaches the xrayjson path, so the YT probe isn't dispatched
# (status null) — but the JSON block must still be emitted and well-formed. Fast, no xray.
out=$(TIMEOUT=3 bash "$SCRIPT" www.example.com --only dns --json 2>/dev/null)
printf '%s' "$out" | jq -e '.probes.youtube_reach
        | has("status") and has("verdict") and has("requested")
          and has("succeeded") and has("failed") and has("min_ttfb_ms") and has("max_ttfb_ms")' >/dev/null 2>&1 \
  || fail "youtube_reach JSON block must be present and well-formed"
printf '%s' "$out" | jq -e '.probes.youtube_reach.status == null' >/dev/null 2>&1 \
  || fail "without the tunnel path the YT probe should not run (status null)"

# flags are wired + documented
help=$(bash "$SCRIPT" --help 2>&1)
printf '%s' "$help" | grep -q -- '--yt-test'    || fail "--yt-test should appear in --help"
printf '%s' "$help" | grep -q -- '--no-yt-test' || fail "--no-yt-test should appear in --help"

echo "PASS: youtube_reach JSON block is well-formed; --yt-test / --no-yt-test are wired"
