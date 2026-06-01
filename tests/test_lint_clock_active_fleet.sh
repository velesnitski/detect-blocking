#!/usr/bin/env bash
#
# tests/test_lint_clock_active_fleet.sh — schema + gating + lint-logic checks
# for probes 18 (config lint), 19 (clock skew), 20 (active-probe resistance)
# and 21 (per-outbound fleet matrix). No xray-core / live endpoint needed.

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "$out" >&2; exit 1; }

# --- Case A: no config at all → all four skipped/disabled, schema intact. ---
out=$(VPN_HOST=www.example.com TIMEOUT=2 \
      bash "$SCRIPT" --only xray,xrayjson --json 2>&1)
[ "$(printf '%s' "$out" | jq -r '.probes.xray_lint.status')"   = "skipped" ]  || fail "lint should skip without a config"
[ "$(printf '%s' "$out" | jq -r '.probes.xray_clock.status')"  = "skipped" ]  || fail "clock should skip without a config"
[ "$(printf '%s' "$out" | jq -r '.probes.xray_active_probe.status')" = "skipped" ] || fail "active-probe should skip without a config"
# Fleet auto-detects: with no JSON config it self-gates to "skipped" (not a fleet).
[ "$(printf '%s' "$out" | jq -r '.probes.xray_fleet.status')"  = "skipped" ]  || fail "fleet should skip without a multi-outbound JSON config"

printf '%s' "$out" | jq -e '
  (.probes.xray_lint | has("status") and has("findings"))
  and (.probes.xray_clock | has("status") and has("skew_seconds"))
  and (.probes.xray_active_probe | has("relay_http_code") and has("genuine_http_code") and has("matches_cover"))
  and (.probes.xray_fleet | has("outbounds_total") and has("per_outbound"))
' >/dev/null || fail "probes 18-21 schema missing keys"

# --- Case B: lint must FLAG a known-bad URL (flow=vision on ws + bad shortId
#     + bare-IP SNI). Uses TEST-NET host, no network reached for lint. ---
BAD='vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?type=ws&security=reality&flow=xtls-rprx-vision&sid=ZZZZ&sni=192.0.2.9&encryption=auto'
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config "$BAD" --only xray --json 2>/dev/null)
lstatus=$(printf '%s' "$out" | jq -r '.probes.xray_lint.status')
[ "$lstatus" = "warn" ] || fail "lint should warn on the bad config, got '$lstatus'"
nfind=$(printf '%s' "$out" | jq -r '.probes.xray_lint.findings | length')
[ "${nfind:-0}" -ge 3 ] || fail "lint should report multiple findings on the bad config, got '$nfind'"
# findings must name knobs, never the secret values (no uuid / sni IP echoed).
printf '%s' "$out" | jq -r '.probes.xray_lint.findings[]' | grep -q '00000000' \
  && fail "lint leaked the UUID into findings"

# --- Case C: lint passes a clean URL. ---
GOOD='vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?type=tcp&security=reality&flow=xtls-rprx-vision&pbk=AAAA&sid=01ab&sni=www.example.com&fp=chrome&encryption=none'
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config "$GOOD" --only xray --json 2>/dev/null)
[ "$(printf '%s' "$out" | jq -r '.probes.xray_lint.status')" = "ok" ] \
  || fail "lint should pass the clean config"

# --- Case D: fleet auto-enables on a multi-outbound JSON (no --fleet needed).
#     Endpoints point at 127.0.0.1:1 → instant refused, so it's fast whether or
#     not xray-core is installed (xray-missing in CI, ok/run locally). ---
multi=$(mktemp -t fleet_autodetect.XXXXXX).json
cat > "$multi" <<'JSON'
{
  "inbounds": [{ "tag":"socks","listen":"127.0.0.1","port":10808,"protocol":"socks","settings":{"auth":"noauth","udp":true} }],
  "outbounds": [
    { "protocol":"vless","tag":"node-a","settings":{"vnext":[{"address":"127.0.0.1","port":1,"users":[{"id":"x","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"none"} },
    { "protocol":"vless","tag":"node-b","settings":{"vnext":[{"address":"127.0.0.1","port":1,"users":[{"id":"y","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"none"} },
    { "protocol":"freedom","tag":"direct" }
  ]
}
JSON
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$multi" --only xrayjson --json 2>/dev/null)
fstatus=$(printf '%s' "$out" | jq -r '.probes.xray_fleet.status')
case "$fstatus" in
  ok|xray-missing) : ;;  # auto-detected the fleet (ran, or would have if xray present)
  *) rm -f "$multi"; fail "fleet should auto-enable on multi-outbound JSON, got '$fstatus'" ;;
esac

# --- Case E: --no-fleet disables auto-detection on the same config. ---
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$multi" --no-fleet --only xrayjson --json 2>/dev/null)
[ "$(printf '%s' "$out" | jq -r '.probes.xray_fleet.status')" = "disabled" ] \
  || { rm -f "$multi"; fail "--no-fleet should disable the fleet matrix"; }
rm -f "$multi"

echo "PASS: probes 18-21 gate/schema correct, lint flags bad + passes clean, fleet auto-detects, no secret leak"
