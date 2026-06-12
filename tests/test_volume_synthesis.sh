#!/usr/bin/env bash
#
# tests/test_volume_synthesis.sh — cross-probe temporal synthesis. The pure
# decision (_volume_throttle_suspected) fires when the tunnel carried data early
# (12 + 13/14) but >=2 later sustained-use probes (16/17/22) degraded — the
# in-region cumulative-volume-throttle pattern. We extract it and assert it fires
# on that ordering and stays quiet otherwise (it must never fire on a healthy run,
# a dead tunnel, a single incidental failure, or skipped probes). Also checks the
# JSON field is null when the data-plane probes didn't run.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

body=$(awk '/^_volume_throttle_suspected\(\)/,/^}/' "$SCRIPT")
[ -n "$body" ] || fail "could not extract _volume_throttle_suspected"
eval "$body"

ck() { # expected  json tput speed egress stab bbloat
  local want="$1"; shift
  local got; got=$(_volume_throttle_suspected "$@")
  [ "$got" = "$want" ] || fail "_volume_throttle_suspected($*) = '$got', expected '$want'"
}

# args: json throughput speedtest egress stability bufferbloat
# THE 86.54 pattern: tunnel + heavy pull ok, then egress/stability/bufferbloat all degrade.
ck 1  ok ok          ok       no-data slow no-data
# healthy: everything passes → quiet.
ck 0  ok ok          ok       ok      ok   ok
# tunnel never worked → not a volume story.
ck 0  failed ""      ""       no-data slow no-data
# only ONE late degradation → below the >=2 threshold (too FP-prone).
ck 0  ok ok          ok       no-data ok   ok
# >=2 late degradations but NO successful early pull (broken throughput, no speedtest) → premise fails.
ck 0  ok broken      skipped  no-data slow ok
# early pull via throughput only (speedtest skipped) still counts as "carried data early".
ck 1  ok ok          skipped  no-data slow ok
# early pull via the big multi-stream only (throughput skipped).
ck 1  ok skipped     ok       no-data slow ok
# stability 'killed' also counts as a late degradation.
ck 1  ok ok          ok       ok      killed no-data
# skipped/disabled later probes are NOT degradations.
ck 0  ok ok          ok       skipped skipped skipped
# throttled-mild throughput still means data moved early.
ck 1  ok throttled-mild skipped no-data unstable ok

# --- wiring: with no data-plane run, the JSON hint is null (never a false fire). ---
if command -v jq >/dev/null 2>&1; then
  out=$(TIMEOUT=2 bash "$SCRIPT" --only env --json 2>/dev/null)
  [ "$(printf '%s' "$out" | jq -r '.probes.xray_detectability.volume_throttle_suspected')" = "null" ] \
    || fail "volume_throttle_suspected should be null when the data-plane probes didn't run"
fi

echo "PASS: volume-throttle synthesis fires on early-pass/late-fail (>=2), quiet on healthy/dead-tunnel/single-failure/skipped; JSON null when unrun"
