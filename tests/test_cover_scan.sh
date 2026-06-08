#!/usr/bin/env bash
#
# tests/test_cover_scan.sh — the --scan-covers cover-SNI scanner. Ranks candidate
# Reality dest/serverNames by TLSv1.3 + H2 + CA-valid + non-redirect. Uses
# 127.0.0.1 as the candidate so curl can't reach :443 → the candidate is flagged
# "unreachable" deterministically and offline (no external network needed); the
# schema + dispatch + absent-by-default behaviour are what's asserted.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }
cs()  { printf '%s' "$1" | jq -c '.probes.cover_scan'; }

# Runs on --scan-covers (regardless of --only); unreachable candidate is flagged.
out=$(TIMEOUT=2 bash "$SCRIPT" --scan-covers 127.0.0.1 --only env --json 2>/dev/null)
[ "$(cs "$out" | jq -r '.status')" = "ok" ] || fail "--scan-covers should run and report status ok"
printf '%s' "$(cs "$out")" | jq -e '.candidates[0] | .domain == "127.0.0.1" and .verdict == "unreachable"' >/dev/null \
  || fail "an unreachable candidate should be flagged 'unreachable'"
printf '%s' "$(cs "$out")" | jq -e 'has("best") and has("candidates")' >/dev/null \
  || fail "cover_scan schema missing best/candidates"

# Without the flag, the scanner does not run → status null.
out=$(TIMEOUT=2 bash "$SCRIPT" --only env --json 2>/dev/null)
[ "$(cs "$out" | jq -r '.status')" = "null" ] \
  || fail "cover_scan should be null when --scan-covers is absent"

echo "PASS: --scan-covers runs + flags unreachable + schema intact; absent by default"
