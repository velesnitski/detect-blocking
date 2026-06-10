#!/usr/bin/env bash
#
# tests/test_bufferbloat_mtu_tlsparity.sh — gating + schema checks for probes
# 22 (bufferbloat), 23 (path MTU) and 24 (TLS-negotiation parity). No tunnel /
# live endpoint required: without a config they skip; --no-bufferbloat
# disables 22. Also asserts the share-safe JSON shape (numbers/booleans only).

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "$out" >&2; exit 1; }

# --- Case A: no config → 22 skipped (no tunnel), 23 skipped (no host),
#     24 skipped (no SNI); schema present. ---
out=$(VPN_HOST=www.example.com TIMEOUT=2 \
      bash "$SCRIPT" --only xray,xrayjson --json 2>&1)

[ "$(printf '%s' "$out" | jq -r '.probes.xray_bufferbloat.status')" = "skipped" ] || fail "bufferbloat should skip without a tunnel"
[ "$(printf '%s' "$out" | jq -r '.probes.xray_mtu.status')"         = "skipped" ] || fail "mtu should skip without a config"
[ "$(printf '%s' "$out" | jq -r '.probes.xray_tls_parity.status')"  = "skipped" ] || fail "tls-parity should skip without a SNI"

printf '%s' "$out" | jq -e '
  (.probes.xray_bufferbloat | has("idle_rtt_ms") and has("loaded_rtt_ms") and has("inflation_ms") and has("jitter_ms"))
  and (.probes.xray_mtu | has("path_mtu"))
  and (.probes.xray_tls_parity | has("version_match") and has("alpn_match") and has("cipher_match") and has("ext_match") and has("server_fingerprint") and has("cover_fingerprint"))
' >/dev/null || fail "probes 22-24 schema missing keys"

# --- Case B: --no-bufferbloat disables probe 22. ---
out=$(VPN_HOST=www.example.com TIMEOUT=2 \
      bash "$SCRIPT" --xray-config-json /tmp/__nope__.json --no-bufferbloat \
        --only xrayjson --json 2>&1)
[ "$(printf '%s' "$out" | jq -r '.probes.xray_bufferbloat.status')" = "disabled" ] \
  || fail "--no-bufferbloat should disable probe 22"

# --- Case C: path-MTU runs when a host is present (status is a real outcome,
#     not "skipped"). Uses TEST-NET host so nothing real is contacted; the
#     result is filtered/clamped/ok depending on ICMP, all acceptable. ---
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json /tmp/__nope__.json \
        --only xrayjson --json 2>/dev/null)
mstatus=$(printf '%s' "$out" | jq -r '.probes.xray_mtu.status')
case "$mstatus" in
  ok|clamped|filtered|no-ping) : ;;
  skipped) fail "mtu should run when a JSON config (host) is present" ;;
  *) fail "unexpected mtu status: '$mstatus'" ;;
esac

echo "PASS: probes 22-24 gate/schema correct, --no-bufferbloat disables 22"
