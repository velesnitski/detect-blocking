#!/usr/bin/env bash
#
# tests/test_outbound_select.sh — --outbound TAG narrows a multi-outbound JSON
# config to one server. Synthetic config (no real infra; TEST-NET hosts) with two
# vless outbounds; we assert the derived target host follows the selection. Hosts
# are IP literals so the DNS probe echoes them offline (v0.18.2 IP-literal path).
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }

tmp=$(mktemp -d -t detect_blocking.obtest.XXXXXX) || { echo "FAIL: mktemp"; exit 1; }
trap 'rm -rf "$tmp"' EXIT
cfg="$tmp/cfg.json"
cat > "$cfg" <<'EOF'
{
  "inbounds": [ { "tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": { "auth": "noauth" } } ],
  "routing": { "rules": [ { "type": "field", "network": "tcp,udp", "outboundTag": "ob-a" } ] },
  "outbounds": [
    { "tag": "ob-a", "protocol": "vless",
      "settings": { "vnext": [ { "address": "192.0.2.10", "port": 443, "users": [ { "id": "00000000-0000-0000-0000-000000000001", "flow": "xtls-rprx-vision", "encryption": "none" } ] } ] },
      "streamSettings": { "network": "tcp", "security": "reality", "realitySettings": { "publicKey": "AAAA", "serverName": "a.example.com", "shortId": "01", "fingerprint": "chrome" } } },
    { "tag": "ob-b", "protocol": "vless",
      "settings": { "vnext": [ { "address": "192.0.2.20", "port": 8443, "users": [ { "id": "00000000-0000-0000-0000-000000000001", "flow": "xtls-rprx-vision", "encryption": "none" } ] } ] },
      "streamSettings": { "network": "tcp", "security": "reality", "realitySettings": { "publicKey": "BBBB", "serverName": "b.example.com", "shortId": "01", "fingerprint": "chrome" } } }
  ]
}
EOF

# --- No --outbound: targets the first proxy outbound (ob-a → 192.0.2.10), and
#     surfaces that there are 2 proxy outbounds. ---
out=$(TIMEOUT=3 bash "$SCRIPT" --xray-config-json "$cfg" --only dns 2>&1)
printf '%s' "$out" | grep -q '192.0.2.10'           || fail "default should target the first proxy outbound (192.0.2.10)"
printf '%s' "$out" | grep -q '2 proxy outbounds'    || fail "should note there are 2 proxy outbounds"
printf '%s' "$out" | grep -q '192.0.2.20' && fail "default must NOT target the second outbound"

# --- --outbound ob-b: narrows to that server (192.0.2.20). ---
out=$(TIMEOUT=3 bash "$SCRIPT" --xray-config-json "$cfg" --outbound ob-b --only dns 2>&1)
printf '%s' "$out" | grep -q 'narrowed the config to that outbound' || fail "--outbound should log the narrow note"
printf '%s' "$out" | grep -q '192.0.2.20'           || fail "--outbound ob-b should target 192.0.2.20"
printf '%s' "$out" | grep -q '192.0.2.10' && fail "--outbound ob-b must NOT still target ob-a (192.0.2.10)"

# --- --outbound ob-a: narrows to the first server explicitly. ---
out=$(TIMEOUT=3 bash "$SCRIPT" --xray-config-json "$cfg" --outbound ob-a --only dns 2>&1)
printf '%s' "$out" | grep -q '192.0.2.10' || fail "--outbound ob-a should target 192.0.2.10"

# --- unknown tag → clean error, non-zero exit. ---
if TIMEOUT=3 bash "$SCRIPT" --xray-config-json "$cfg" --outbound nope --only dns >/dev/null 2>&1; then
  fail "an unknown --outbound tag should exit non-zero"
fi

# --- a JSON config narrowed must remain valid JSON (single proxy + freedom). ---
out=$(TIMEOUT=3 bash "$SCRIPT" --xray-config-json "$cfg" --outbound ob-b --only env --json 2>/dev/null)
printf '%s' "$out" | jq empty >/dev/null 2>&1 || fail "--outbound run should still emit valid JSON"

echo "PASS: --outbound narrows to the selected proxy outbound; default targets the first + notes the count; unknown tag errors"
