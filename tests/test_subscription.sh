#!/usr/bin/env bash
#
# tests/test_subscription.sh — --subscription fetch + decode + inventory + select.
# We point it at a file:// URL holding a synthetic JSON array of Xray configs (no
# network, all placeholders/TEST-NET) and use --only env so the inventory prints
# without deep-probing the (fake) servers. Asserts: count, inventory lines, the
# selected index is marked, and an out-of-range --sub-test clamps to 0.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }
tmp=$(mktemp -d -t detect_blocking.subtest.XXXXXX) || { echo FAIL; exit 1; }
trap 'rm -rf "$tmp"' EXIT
PBK='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'   # 43-char placeholder (scanner-allowlisted)
ID='00000000-0000-0000-0000-000000000000'
cat > "$tmp/arr.json" <<EOF
[
 {"remarks":"Alpha","outbounds":[
   {"tag":"p","protocol":"vless","settings":{"vnext":[{"address":"192.0.2.10","port":443,"users":[{"id":"$ID","flow":"xtls-rprx-vision","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"publicKey":"$PBK","serverName":"www.example.com","shortId":"01","fingerprint":"chrome"}}},
   {"tag":"direct","protocol":"freedom"}]},
 {"remarks":"Bravo","outbounds":[
   {"tag":"p","protocol":"vless","settings":{"vnext":[{"address":"192.0.2.20","port":8443,"users":[{"id":"$ID","flow":"xtls-rprx-vision","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"publicKey":"$PBK","serverName":"www.microsoft.com","shortId":"01","fingerprint":"chrome"}}}]},
 {"remarks":"Charlie-noproxy","outbounds":[{"protocol":"freedom"}]}
]
EOF

# --- JSON array: 3 configs, select index 1; --only env keeps it fast (no deep probe) ---
out=$(TIMEOUT=2 bash "$SCRIPT" --subscription "file://$tmp/arr.json" --sub-test 1 --only env 2>&1)
printf '%s' "$out" | grep -q 'Subscription inventory (3 configs)' || fail "should parse 3 configs from the array"
printf '%s' "$out" | grep -q 'Alpha'   || fail "inventory should list Alpha"
printf '%s' "$out" | grep -q 'Bravo'   || fail "inventory should list Bravo"
printf '%s' "$out" | grep -qE 'noproxy.*no proxy outbound' || fail "a config with no proxy outbound should be noted"
printf '%s' "$out" | grep -qE '#1 .*Bravo.*tested below' || fail "--sub-test 1 should mark Bravo as the tested config"
printf '%s' "$out" | grep -q '192.0.2.20:8443' || fail "inventory should show the server endpoint"

# --- out-of-range --sub-test clamps to 0 (Alpha) ---
out=$(TIMEOUT=2 bash "$SCRIPT" --subscription "file://$tmp/arr.json" --sub-test 99 --only env 2>&1)
printf '%s' "$out" | grep -qE '#0 .*Alpha.*tested below' || fail "out-of-range --sub-test should clamp to index 0"

# --- single-object sub (one config, not an array) ---
jq -c '.[0]' "$tmp/arr.json" > "$tmp/one.json"
out=$(TIMEOUT=2 bash "$SCRIPT" --subscription "file://$tmp/one.json" --only env 2>&1)
printf '%s' "$out" | grep -q 'Subscription inventory (1 configs)' || fail "a single config object should parse as 1"

echo "PASS: --subscription decodes a JSON array/object, inventories the fleet, selects + clamps --sub-test"
