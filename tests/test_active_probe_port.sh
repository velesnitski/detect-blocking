#!/usr/bin/env bash
#
# tests/test_active_probe_port.sh — regression guard for the probe-20 port bug.
# probe 20 (active-probe) used to hardcode :443 in its curl --resolve, so a
# Reality server on a non-standard port (e.g. :56443) was probed on :443 — where
# it isn't listening — giving a false "not relaying to the cover (+25)". The relay
# probe must target the server's actual port (VPN_PORT_TCP). probe 20's connect
# is hard to exercise offline (it needs a reachable genuine cover to baseline), so
# this guards the source: the relay --resolve/URL must use VPN_PORT_TCP, never a
# hardcoded :443 mapped to the server.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

body=$(awk '/^probe_xray_active_probe\(\)/,/^}/' "$SCRIPT")
[ -n "$body" ] || fail "could not extract probe_xray_active_probe"

# The relay probe must bind the cover SNI to the server on its configured port.
printf '%s' "$body" | grep -q 'resolve "\$sni:\${VPN_PORT_TCP' \
  || fail "active-probe --resolve must use VPN_PORT_TCP (the server's real port), not a hardcoded one"

# And it must NOT reintroduce the hardcoded ":443:\$VPN_HOST" mapping to the server.
printf '%s' "$body" | grep -q 'resolve "\$sni:443:\$VPN_HOST"' \
  && fail "active-probe still hardcodes :443 in --resolve (the port bug)"

# The genuine-cover baseline is a separate curl to the real cover (bare host, no
# port and no --resolve), and it must remain — not be forced to the server. The
# relay probe now uses https://$sni:$VPN_PORT_TCP/, so the bare form is unique to
# the baseline. (Matched anywhere: the assignment spans two lines in the source.)
printf '%s' "$body" | grep -q '"https://\$sni/"' \
  || fail "genuine-cover baseline should fetch the cover directly (bare https://\$sni/)"

echo "PASS: probe 20 relay probe targets the server on VPN_PORT_TCP (no hardcoded :443); cover baseline unchanged"
