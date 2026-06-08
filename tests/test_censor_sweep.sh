#!/usr/bin/env bash
#
# tests/test_censor_sweep.sh — the --censor-sweep OONI-style reachability sweep.
# With no config there's no tunnel, so it runs DIRECT-only; 127.0.0.1:443 is
# refused → "blocked direct", deterministic and offline. Asserts dispatch, the
# direct-only path, the schema, and absent-by-default.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }
csw() { printf '%s' "$1" | jq -c '.probes.censor_sweep'; }

# Direct-only (no config → no tunnel); unreachable host → blocked direct, tunnel null.
out=$(TIMEOUT=2 bash "$SCRIPT" --censor-sweep 127.0.0.1 --only env --json 2>/dev/null)
[ "$(csw "$out" | jq -r '.status')" = "ok" ]          || fail "--censor-sweep should run and report ok"
[ "$(csw "$out" | jq -r '.tunnel_used')" = "false" ]  || fail "no config → tunnel_used should be false"
printf '%s' "$(csw "$out")" | jq -e '.results[0] | .host == "127.0.0.1" and .direct == false and .tunnel == null' >/dev/null \
  || fail "an unreachable host (no tunnel) should be direct=false, tunnel=null"
printf '%s' "$(csw "$out")" | jq -e 'has("status") and has("tunnel_used") and has("results")' >/dev/null \
  || fail "censor_sweep schema missing keys"

# Absent flag → does not run → status null.
out=$(TIMEOUT=2 bash "$SCRIPT" --only env --json 2>/dev/null)
[ "$(csw "$out" | jq -r '.status')" = "null" ] \
  || fail "censor_sweep should be null when --censor-sweep is absent"

echo "PASS: --censor-sweep runs (direct-only without a tunnel) + classifies + schema intact; absent by default"
