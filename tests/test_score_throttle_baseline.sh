#!/usr/bin/env bash
#
# tests/test_score_throttle_baseline.sh — probes 25 (cover-SNI throttle) and
# 26 (detectability score), plus the --save-baseline / --diff-baseline
# regression mode. No tunnel / live endpoint needed: without a config they
# skip; baseline round-trips through the JSON emitter and the diff detects a
# mutated field. Asserts the share-safe shape (no raw IP/domain in the diff).

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }

# --- Case A: no config → 25 + 26 skipped; schema present. ---
out=$(VPN_HOST=www.example.com TIMEOUT=2 \
      bash "$SCRIPT" --only xray,xrayjson --json 2>&1)
[ "$(printf '%s' "$out" | jq -r '.probes.xray_cover_throttle.status')" = "skipped" ] || fail "cover-throttle should skip without a SNI"
[ "$(printf '%s' "$out" | jq -r '.probes.xray_detectability.status')"  = "skipped" ] || fail "detectability should skip without stealth data"
printf '%s' "$out" | jq -e '
  (.probes.xray_cover_throttle | has("cover_bytes_per_second") and has("baseline_bytes_per_second"))
  and (.probes.xray_detectability | has("score") and has("band"))
' >/dev/null || fail "probes 25/26 schema missing keys"

# --- Case B: --save-baseline writes valid schema-1 JSON. ---
base=$(mktemp -t db_baseline.XXXXXX)
VPN_HOST=www.example.com TIMEOUT=2 bash "$SCRIPT" --only dns,tcp --save-baseline "$base" >/dev/null 2>&1
[ "$(jq -r '.schema_version' "$base" 2>/dev/null)" = "1" ] || { rm -f "$base"; fail "--save-baseline did not write valid JSON"; }

# --- Case C: --diff-baseline against an unchanged baseline → "no changes". ---
out=$(VPN_HOST=www.example.com TIMEOUT=2 bash "$SCRIPT" --only dns,tcp --diff-baseline "$base" 2>&1)
printf '%s' "$out" | grep -q 'no changes since baseline' \
  || { rm -f "$base"; fail "diff against unchanged baseline should report no changes"; }

# --- Case D: mutate a tracked field in the baseline → diff must flag it,
#     render booleans correctly (not 'none'), and leak no IP/domain. ---
jq '.probes.xray_cover.self_signed=false | .probes.xray_egress.country="DE"' "$base" > "$base.m" && mv "$base.m" "$base"
out=$(VPN_HOST=www.example.com TIMEOUT=2 bash "$SCRIPT" --only dns,tcp --diff-baseline "$base" 2>&1)
printf '%s' "$out" | grep -q 'egress_country: DE ->' \
  || { rm -f "$base"; fail "diff should flag the mutated egress_country"; }
printf '%s' "$out" | grep -q 'cover_selfsigned: false ->' \
  || { rm -f "$base"; fail "diff should render boolean false (not 'none')"; }
# Share-safe: the diff section must not contain a dotted IP.
diffsec=$(printf '%s' "$out" | awk '/== Baseline diff/,/^== VERDICT/')
printf '%s' "$diffsec" | grep -qE '([0-9]{1,3}\.){3}[0-9]{1,3}' \
  && { rm -f "$base"; fail "baseline diff leaked a dotted IP"; }

rm -f "$base"
echo "PASS: probes 25/26 gate/schema + baseline save/diff (detects change, renders booleans, no IP leak)"
