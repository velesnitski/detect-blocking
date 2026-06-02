#!/usr/bin/env bash
#
# tests/test_log_path_neutralize.sh — probe 12 must neutralize device-specific
# log file paths when patching a config. Mobile clients (iOS/Android) bake an
# app-sandbox path into .log.access that doesn't exist on the test machine, so
# without this xray-core fails to open its logger and never starts
# ("xray-bind-failed"). With the fix it starts and the probe proceeds to the
# real outcome (here "failed", since the outbound points at 127.0.0.1:1).
#
# Deterministic across environments: with xray-core present the status must be
# a real outcome (not the startup failure); without it, "xray-missing".

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }

cfg=$(mktemp -t db_logpath.XXXXXX)
cat > "$cfg" << 'EOF'
{
  "log": {
    "access": "/nonexistent/app-sandbox/Library/Xray/logs/access.log",
    "loglevel": "Warning"
  },
  "inbounds": [{ "tag":"socks","listen":"127.0.0.1","port":10808,"protocol":"socks","settings":{"auth":"noauth","udp":true} }],
  "outbounds": [{
    "protocol":"vless","tag":"proxy",
    "settings":{"vnext":[{"address":"127.0.0.1","port":1,"users":[{"id":"x","encryption":"none","flow":"xtls-rprx-vision"}]}]},
    "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.example.com","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortId":"01","fingerprint":"chrome"}}
  }]
}
EOF

out=$(TIMEOUT=3 bash "$SCRIPT" --xray-config-json "$cfg" \
        --only xrayjson --no-stability --no-bufferbloat --json 2>/dev/null)
rm -f "$cfg"

status=$(printf '%s' "$out" | jq -r '.probes.xray_full_config.status')
case "$status" in
  xray-bind-failed)
    fail "xray failed to START because of the foreign log path — neutralization regressed" ;;
  xray-missing)
    echo "PASS: xray-core not installed — log-path neutralization not exercised (CI ok)" ;;
  ok|failed|no-port)
    echo "PASS: foreign log path neutralized — xray started, probe reached '$status'" ;;
  *)
    fail "unexpected status: '$status'" ;;
esac
