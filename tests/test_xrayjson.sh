#!/usr/bin/env bash
#
# tests/test_xrayjson.sh — verify --xray-config-json graceful-degradation
# paths. We don't require xray-core to be installed in CI; the probe
# must skip cleanly with a structured "xray-missing" status when the
# binary is absent, and "config-missing" when the file path doesn't exist.

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "$out" >&2; exit 1; }

# Case A — missing config file path
out=$(VPN_HOST=www.example.com TIMEOUT=2 \
      bash "$SCRIPT" --xray-config-json /tmp/__not_a_real_path__.json \
        --only xrayjson --json 2>&1)
status=$(printf '%s' "$out" | jq -r '.probes.xray_full_config.status')
[ "$status" = "config-missing" ] \
  || fail "expected status=config-missing for nonexistent file, got '$status'"

# Case B — xray binary missing OR config is fine and probe runs.
# CI runners don't have xray-core; we accept either outcome:
#   - xray-missing (no binary)
#   - jq-missing  (no jq — impossible, we'd have skipped above)
#   - no-port / xray-bind-failed / ok / failed (xray IS installed)
# All non-"no-config" statuses are valid here; we just assert the probe ran.
tmp_cfg=$(mktemp -t detect_blocking_xrayjson_test.XXXXXX)
cat > "$tmp_cfg" << 'EOF'
{
  "log": { "loglevel": "warning" },
  "inbounds": [{
    "tag": "socks",
    "listen": "127.0.0.1",
    "port": 10808,
    "protocol": "socks",
    "settings": { "auth": "noauth", "udp": true }
  }],
  "outbounds": [{
    "protocol": "freedom",
    "settings": {}
  }]
}
EOF

out=$(VPN_HOST=www.example.com TIMEOUT=3 \
      bash "$SCRIPT" --xray-config-json "$tmp_cfg" \
        --only xrayjson --json 2>&1)
rm -f "$tmp_cfg"

status=$(printf '%s' "$out" | jq -r '.probes.xray_full_config.status')
case "$status" in
  ok|failed|xray-missing|xray-bind-failed|no-port|jq-missing|config-malformed)
    : ;;
  *) fail "unexpected xray_full_config.status: '$status'" ;;
esac

# Schema sanity for the new block — both keys must exist even when probe skipped.
printf '%s' "$out" | jq -e '.probes.xray_full_config | has("status") and has("config_path")' >/dev/null \
  || fail "xray_full_config schema missing required keys"

echo "PASS: --xray-config-json gracefully handles missing file + missing binary"
