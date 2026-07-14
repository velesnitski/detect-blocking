#!/usr/bin/env bash
#
# tests/test_tunnel_effect.sh — VPN tunnel effectiveness probe (run detect-blocking
# while your VPN is up). Unit-tests the pure through-vs-around classifier, then an
# offline check that the JSON block is well-formed and the no-tunnel path records
# status=no-tunnel without touching the network. The live differential needs a real
# tunnel + a bindable physical NIC, so it isn't exercised here.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

# ---- unit: the pure classifier (through_ip, around_ip) → effect ----
eval "$(awk '/^_tunnel_effect\(\)/,/^}/' "$SCRIPT")"
[ "$(_tunnel_effect 1.2.3.4 5.6.7.8)" = "captured" ]            || fail "different egress → captured"
[ "$(_tunnel_effect 1.2.3.4 1.2.3.4)" = "leak" ]               || fail "same egress → leak"
[ "$(_tunnel_effect 1.2.3.4 '')"      = "captured-unverified" ] || fail "no around-leg → captured-unverified"
[ "$(_tunnel_effect '' '')"           = "no-exit" ]            || fail "no through-leg → no-exit"
[ "$(_tunnel_effect '' 5.6.7.8)"      = "no-exit" ]            || fail "no through-leg (even with around) → no-exit"

# ---- offline: no-tunnel path (default route is not a tunnel here) records status,
#      makes NO network call, and the JSON block is well-formed. ----
out=$(TIMEOUT=2 bash "$SCRIPT" --only tunnel 127.0.0.1 --json 2>/dev/null)
[ "$(printf '%s' "$out" | jq -r '.probes.tunnel.status')" = "no-tunnel" ] \
  || fail "no-tunnel default route should record status=no-tunnel"
[ "$(printf '%s' "$out" | jq -r '.probes.tunnel.default_iface_is_tunnel')" = "false" ] \
  || fail "no-tunnel default route should report default_iface_is_tunnel=false"
[ "$(printf '%s' "$out" | jq -r '.probes.tunnel.exit_differs')" = "null" ] \
  || fail "no-tunnel path should leave exit_differs null (unknown)"
# the no-tunnel path is silent on the console (no header) — a normal run isn't noisier.
out=$(TIMEOUT=2 bash "$SCRIPT" --only tunnel 127.0.0.1 2>&1)
printf '%s' "$out" | grep -q 'VPN tunnel effectiveness' \
  && fail "no-tunnel path must NOT print the tunnel header (should stay silent)"

echo "PASS: tunnel effectiveness — classifier (captured/leak/unverified/no-exit) + no-tunnel path silent & JSON well-formed"
