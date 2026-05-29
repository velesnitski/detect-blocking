#!/usr/bin/env bash
#
# tests/test_cover_egress_stability.sh — schema + gating checks for probes
# 15 (Reality cover authenticity), 16 (egress integrity) and 17 (held-session
# stability). No network/xray needed: without a tunnel, 16/17 report
# "skipped"; without a reality config, 15 reports "skipped"; opt-outs flip
# 16/17 to "disabled". Also asserts no cover domain / egress IP leaks into the
# probe-15/16 JSON (booleans + country code only).

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "$out" >&2; exit 1; }

# Case A — no reality config, no tunnel: 15 skipped, 16 skipped, 17 skipped.
out=$(VPN_HOST=www.example.com TIMEOUT=2 \
      bash "$SCRIPT" --xray-config-json /tmp/__nope__.json \
        --only xray,xrayjson --json 2>&1)

for probe in xray_cover:skipped xray_egress:skipped xray_stability:skipped; do
  key=${probe%%:*}; want=${probe#*:}
  got=$(printf '%s' "$out" | jq -r ".probes.${key}.status")
  [ "$got" = "$want" ] || fail "expected ${key}.status=${want}, got '$got'"
done

# Schema sanity — keys present, booleans are null (not run).
printf '%s' "$out" | jq -e '
  (.probes.xray_cover | has("self_signed") and has("chain_valid") and has("cn_matches_servername"))
  and (.probes.xray_egress | has("country") and has("hosting") and has("proxy") and has("dns_resolver_geo"))
  and (.probes.xray_stability | has("pulses_total") and has("pulses_ok") and has("first_failure_seconds"))
' >/dev/null || fail "probes 15/16/17 schema missing keys"

# No-sensitive-info guard: the cover/egress JSON blocks must not carry domain
# names or dotted IPs (they are designed to emit booleans + country only).
leak=$(printf '%s' "$out" | jq -c '{c:.probes.xray_cover, e:.probes.xray_egress}' \
       | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}|[a-z0-9-]+\.[a-z]{2,}' || true)
[ -z "$leak" ] || fail "probe 15/16 JSON leaked an identifier: $leak"

# Case B — opt-outs: --no-egress-check → 16 disabled; --no-stability → 17 disabled.
out=$(VPN_HOST=www.example.com TIMEOUT=2 \
      bash "$SCRIPT" --xray-config-json /tmp/__nope__.json --no-egress-check --no-stability \
        --only xrayjson --json 2>&1)
[ "$(printf '%s' "$out" | jq -r '.probes.xray_egress.status')" = "disabled" ] \
  || fail "--no-egress-check should set xray_egress.status=disabled"
[ "$(printf '%s' "$out" | jq -r '.probes.xray_stability.status')" = "disabled" ] \
  || fail "--no-stability should set xray_stability.status=disabled"

echo "PASS: probes 15/16/17 gate + schema correct, no identifier leak in JSON"
