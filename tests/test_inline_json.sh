#!/usr/bin/env bash
#
# tests/test_inline_json.sh — --xray-config-json accepts inline JSON ('{…}') and
# stdin ('-'), not just a file path. JSON is full of shell-hostile symbols, so
# the value is detected (starts with '{' / equals '-') and materialized to a
# 0600 temp file; invalid JSON and empty stdin must fail fast with exit 1. A
# real file path must keep working unchanged. Deterministic/offline: the config
# points at 127.0.0.1:1 and we only assert host derivation + exit codes.

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

CFG='{"inbounds":[{"protocol":"socks","port":11240,"listen":"127.0.0.1","settings":{"auth":"noauth"}}],"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":1,"users":[{"id":"00000000-0000-0000-0000-000000000000","encryption":"none","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.example.com","fingerprint":"chrome","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortId":"01"}}}]}'

host_of() { printf '%s' "$1" | jq -r '.target.host // "NONE"'; }

# A — inline JSON argument → VPN_HOST derived from it.
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$CFG" --only xrayjson --json 2>/dev/null)
[ "$(host_of "$out")" = "127.0.0.1" ] || fail "inline JSON arg should derive host 127.0.0.1"

# B — stdin ('-') → same.
out=$(printf '%s' "$CFG" | TIMEOUT=2 bash "$SCRIPT" --xray-config-json - --only xrayjson --json 2>/dev/null)
[ "$(host_of "$out")" = "127.0.0.1" ] || fail "stdin (-) JSON should derive host 127.0.0.1"

# C — invalid inline JSON → exit 1.
TIMEOUT=2 bash "$SCRIPT" --xray-config-json '{bad json' --only xrayjson >/dev/null 2>&1
[ "$?" -eq 1 ] || fail "invalid inline JSON should exit 1"

# C2 — empty stdin → exit 1.
printf '' | TIMEOUT=2 bash "$SCRIPT" --xray-config-json - --only xrayjson >/dev/null 2>&1
[ "$?" -eq 1 ] || fail "empty stdin should exit 1"

# D — a real file path still works (regression).
f=$(mktemp); printf '%s' "$CFG" > "$f"
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$f" --only xrayjson --json 2>/dev/null)
rm -f "$f"
[ "$(host_of "$out")" = "127.0.0.1" ] || fail "file-path JSON must still derive host (regression)"

echo "PASS: --xray-config-json accepts inline JSON + stdin + file; invalid/empty fail fast"
