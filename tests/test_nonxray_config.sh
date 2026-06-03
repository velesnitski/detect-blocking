#!/usr/bin/env bash
#
# tests/test_nonxray_config.sh — a JSON config that isn't Xray-core (e.g. a
# sing-box config: outbounds use "type"/"server"/"route", not Xray's
# "protocol"/"settings.vnext"/"streamSettings") must be detected and reported
# plainly — "not an Xray-core config" — and the Xray-protocol probes (11-26)
# skipped, rather than silently mis-parsed. A genuine Xray config must NOT trip
# it. Pure-jq detection → deterministic and offline (--only xrayjson skips the
# transport probes; the format note fires regardless).

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }

# sing-box shape: outbound has type/server/server_port, top-level route.
SB='{"log":{"level":"info"},"outbounds":[{"tag":"proxy_out","type":"vless","server":"127.0.0.1","server_port":1,"uuid":"00000000-0000-0000-0000-000000000000","tls":{"enabled":true,"server_name":"www.example.com"}}],"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":10808}],"route":{"final":"proxy_out"}}'

# genuine Xray shape: outbound has protocol/settings.vnext/streamSettings.
XR='{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":1,"users":[{"id":"00000000-0000-0000-0000-000000000000","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.example.com","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortId":"01"}}}]}'

# A — sing-box config is flagged "not Xray-core" in the verdicts.
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$SB" --only xrayjson --json 2>/dev/null)
printf '%s' "$out" | jq -e '(.verdicts // []) | map(select(test("not Xray-core"))) | length > 0' >/dev/null \
  || fail "sing-box config should be flagged 'not Xray-core'"

# B — and the Xray detectability probe did NOT run (was skipped, not scored).
[ "$(printf '%s' "$out" | jq -r '.probes.xray_detectability.status // "absent"')" != "ok" ] \
  || fail "Xray detectability must not score a non-Xray config"

# C — a genuine Xray config must NOT be flagged.
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$XR" --only xrayjson --json 2>/dev/null)
printf '%s' "$out" | jq -e '(.verdicts // []) | map(select(test("not Xray-core"))) | length == 0' >/dev/null \
  || fail "a genuine Xray config must NOT be flagged non-Xray (false positive)"

echo "PASS: non-Xray (sing-box) config detected and named; genuine Xray config unaffected"
