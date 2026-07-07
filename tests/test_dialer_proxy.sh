#!/usr/bin/env bash
#
# tests/test_dialer_proxy.sh — dialerProxy / client-side desync chain support
# (ByeDPI / ciadpi / zapret / GoodbyeDPI). An outbound whose sockopt.dialerProxy
# names a LOCAL socks/http outbound is dialed through it, so the desync proxy
# fragments the ClientHello. The tool must (a) recognize + report the chain,
# (b) not misread a tunnel failure as a shared-config fault when the local dialer
# may just be down, (c) flag a broken (missing-tag) chain. Unit-tests the pure
# extractors, then integration-checks the JSON + the failure caveat.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }

u='00000000-0000-0000-0000-000000000000'
mkcfg() { # file dialer-block
  cat > "$TMP/$1" <<EOF
{ "outbounds": [
  { "tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"cdn.example.com","port":2096,"users":[{"id":"$u","encryption":"none"}]}]},
    "streamSettings":{"network":"httpupgrade","security":"tls","tlsSettings":{"serverName":"cdn.example.com","fingerprint":"chrome"}$2}},
  $3
  {"tag":"direct","protocol":"freedom"} ] }
EOF
}
# local desync dialer (ByeDPI pattern)
mkcfg local.json ',"sockopt":{"dialerProxy":"byedpi-out","tcpKeepAliveInterval":30}' '{"tag":"byedpi-out","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1090}]}},'
# remote dialer (not a local desync)
mkcfg remote.json ',"sockopt":{"dialerProxy":"hop"}' '{"tag":"hop","protocol":"socks","settings":{"servers":[{"address":"10.0.0.5","port":1080}]}},'
# broken: dialerProxy references a tag that does not exist
mkcfg broken.json ',"sockopt":{"dialerProxy":"ghost"}' ''
# no dialerProxy at all
mkcfg plain.json '' ''

# ---- unit: extract the pure extractors and drive them off a fixture ----
check_cmd() { command -v "$1" >/dev/null 2>&1; }
eval "$(awk '/^_dialer_proxy_target\(\)/,/^}/' "$SCRIPT")"
eval "$(awk '/^_dialer_is_local_desync\(\)/,/^}/' "$SCRIPT")"

XRAY_JSON_CONFIG="$TMP/local.json"
[ "$(_dialer_proxy_target)" = "byedpi-out|socks 127.0.0.1:1090" ] || fail "local: target='$(_dialer_proxy_target)'"
[ "$(_dialer_is_local_desync)" = "1" ] || fail "local socks should be a local desync chain"
XRAY_JSON_CONFIG="$TMP/remote.json"
[ "$(_dialer_is_local_desync)" = "0" ] || fail "remote 10.0.0.5 must NOT be a local desync chain"
XRAY_JSON_CONFIG="$TMP/broken.json"
[ "$(_dialer_proxy_target)" = "ghost|missing" ] || fail "broken: target='$(_dialer_proxy_target)'"
[ "$(_dialer_is_local_desync)" = "0" ] || fail "missing-tag chain is not a local desync"
# shellcheck disable=SC2034  # read by the eval'd extractor, invisible to shellcheck
XRAY_JSON_CONFIG="$TMP/plain.json"
[ -z "$(_dialer_proxy_target)" ] || fail "plain config should have no dialerProxy"

command -v jq >/dev/null 2>&1 || { echo "PASS (unit only; jq not installed for integration)"; exit 0; }

J() { TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$TMP/$1" --xray-only --json 2>/dev/null; }

# local desync chain → JSON flags set.
out=$(J local.json)
[ "$(printf '%s' "$out" | jq -r '.probes.xray_lint.dialer_proxy')" = "byedpi-out" ] || fail "dialer_proxy should be byedpi-out"
[ "$(printf '%s' "$out" | jq -r '.probes.xray_lint.desync_chain')" = "true" ] || fail "desync_chain should be true for a local socks dialer"

# broken chain → a lint finding + desync_chain false.
out=$(J broken.json)
printf '%s' "$out" | jq -e '[.probes.xray_lint.findings[] | select(test("references no outbound"))] | length >= 1' >/dev/null \
  || fail "a dialerProxy referencing a missing tag should produce a lint finding"
[ "$(printf '%s' "$out" | jq -r '.probes.xray_lint.desync_chain')" = "false" ] || fail "broken chain: desync_chain should be false"

# no dialerProxy → both null.
out=$(J plain.json)
[ "$(printf '%s' "$out" | jq -r '.probes.xray_lint.dialer_proxy')" = "null" ] || fail "plain config: dialer_proxy should be null"
[ "$(printf '%s' "$out" | jq -r '.probes.xray_lint.desync_chain')" = "null" ] || fail "plain config: desync_chain should be null"

# The tunnel-failure path must NAME the local dialer as a likely cause (readable).
outr=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$TMP/local.json" --xray-only 2>/dev/null)
printf '%s' "$outr" | grep -q 'LOCAL dialerProxy' \
  || fail "a tunnel failure with a local dialerProxy should name the chain as a likely cause"

# ---- fleet detection must EXCLUDE dialerProxy helpers (they aren't endpoints) ----
eval "$(awk '/^_fleet_tags\(\)/,/^}/' "$SCRIPT")"
# proxy dials through byedpi-out → the fleet is just [proxy], NOT [proxy, byedpi-out].
[ "$(_fleet_tags "$TMP/local.json" | tr '\n' ' ')" = "proxy " ] \
  || fail "_fleet_tags should exclude the dialerProxy helper (got: $(_fleet_tags "$TMP/local.json" | tr '\n' ' '))"
# a genuine 2-endpoint fleet (no dialer) keeps both.
cat > "$TMP/twofleet.json" <<EOF
{ "outbounds": [
  {"tag":"a","protocol":"vless","settings":{"vnext":[{"address":"192.0.2.1","port":443,"users":[{"id":"$u"}]}]}},
  {"tag":"b","protocol":"vless","settings":{"vnext":[{"address":"192.0.2.2","port":443,"users":[{"id":"$u"}]}]}},
  {"tag":"direct","protocol":"freedom"} ] }
EOF
[ "$(_fleet_tags "$TMP/twofleet.json" | tr '\n' ' ')" = "a b " ] \
  || fail "_fleet_tags should keep both endpoints of a real 2-node fleet (got: $(_fleet_tags "$TMP/twofleet.json" | tr '\n' ' '))"

echo "PASS: dialerProxy chain recognized (local/remote/broken/none), JSON flags, tunnel-failure caveat, fleet excludes the dialer helper"
