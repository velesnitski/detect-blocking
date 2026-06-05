#!/usr/bin/env bash
#
# tests/test_detectability.sh — probe 26 is the FINAL synthesis: it folds the
# active stealth signals (15/20/24) AND the passive structure (non-443 port,
# SNI↔IP mismatch + their conjunction = the Reality structural signature) into
# one 0-100 score, and runs last. Checks gating, schema, that it's the last
# xray probe, and that a non-443 port lifts the score (passive tell folded in).
# (The conjunction can't fire deterministically offline — it needs real ASN
# resolution that 127.0.0.1 lacks — so only its schema presence is asserted.)

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }

# Case A — no reality config → skipped; schema present (incl. passive fields).
out=$(VPN_HOST=www.example.com TIMEOUT=2 \
      bash "$SCRIPT" --only xray,xrayjson --json 2>&1)
[ "$(printf '%s' "$out" | jq -r '.probes.xray_detectability.status')" = "skipped" ] \
  || fail "detectability should skip without a reality config"
printf '%s' "$out" | jq -e '
  .probes.xray_detectability
  | has("score") and has("band") and has("port_standard")
    and has("sni_ip_asn_match") and has("passive_fingerprint_strong")
    and has("utls_fp_uncommon") and has("deployment_fingerprint")
    and has("cover_obscure")
' >/dev/null || fail "detectability schema missing keys (incl. uTLS fp + deployment fingerprint)"
# No separate passive-fingerprint probe block should exist anymore.
[ "$(printf '%s' "$out" | jq -r '.probes | has("xray_passive_fingerprint")')" = "false" ] \
  || fail "xray_passive_fingerprint should be folded into xray_detectability"

# Case B — reality config (127.0.0.1:1 = instant refused, fast). Probe 26 must
# be the LAST numbered probe printed, and the non-443-port passive tell folds
# in (port_standard=false, score >= 10).
URL='vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?security=reality&pbk=AAAA&sid=01&sni=www.example.com&fp=chrome&type=tcp'
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config "$URL" --only xray 2>/dev/null)
last=$(printf '%s' "$out" | grep -oE '^== [0-9]+\.' | tail -1)
[ "$last" = "== 26." ] || fail "probe 26 must be the last probe, got '$last'"

out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config "$URL" --only xray --json 2>/dev/null)
[ "$(printf '%s' "$out" | jq -r '.probes.xray_detectability.port_standard')" = "false" ] \
  || fail "non-443 port should set port_standard=false"
score=$(printf '%s' "$out" | jq -r '.probes.xray_detectability.score')
[ "${score:-0}" -ge 10 ] || fail "non-443 port should add >=10 to the score, got '$score'"

echo "PASS: probe 26 is last, folds active + passive (+conjunction) signals, schema intact"
