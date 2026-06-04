#!/usr/bin/env bash
#
# tests/test_egress_fallback.sh — probe 16 gained a 3rd reputation source
# (XRAY_EGRESS_DC_URL, default ipapi.is) that supplies a datacenter/proxy flag
# when ip-api is rate-limited, so reputation isn't "n/a / partially checked".
# The live fallback needs a working tunnel + the source reachable, so it can't
# be exercised offline; this locks the JSON contract (the datacenter_fallback
# field exists) and the configurable default — the actual fill-in is verified
# manually (force have_flags=0 via XRAY_EGRESS_INFO_URL against a live node).

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

# The egress JSON must carry datacenter_fallback (present even when the probe is
# skipped — here the tunnel can't establish to 127.0.0.1:1, so egress=skipped).
cfg='{"inbounds":[{"protocol":"socks","port":10808,"listen":"127.0.0.1","settings":{"auth":"noauth"}}],"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":1,"users":[{"id":"00000000-0000-0000-0000-000000000000","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.example.com","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortId":"01"}}}]}'
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$cfg" --only xrayjson --json 2>/dev/null)
printf '%s' "$out" | jq -e '.probes.xray_egress | has("datacenter_fallback")' >/dev/null \
  || fail "xray_egress JSON should carry the datacenter_fallback field"
printf '%s' "$out" | jq -e '.probes.xray_egress | has("egress_colocated")' >/dev/null \
  || fail "xray_egress JSON should carry the egress_colocated field (entry↔egress topology)"

# The fallback source must be configurable and default to a real reputation API.
grep -qE 'XRAY_EGRESS_DC_URL=.*ipapi' "$SCRIPT" \
  || fail "XRAY_EGRESS_DC_URL should default to a datacenter/proxy reputation source"

echo "PASS: egress datacenter_fallback wired into JSON + configurable source"
