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
   {"tag":"p","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":1,"users":[{"id":"$ID","flow":"xtls-rprx-vision","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"publicKey":"$PBK","serverName":"www.example.com","shortId":"01","fingerprint":"chrome"}}},
   {"tag":"direct","protocol":"freedom"}]},
 {"remarks":"Bravo","outbounds":[
   {"tag":"p","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":2,"users":[{"id":"$ID","flow":"xtls-rprx-vision","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"publicKey":"$PBK","serverName":"www.microsoft.com","shortId":"01","fingerprint":"chrome"}}}]},
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
printf '%s' "$out" | grep -q '127.0.0.1:2' || fail "inventory should show the server endpoint"

# --- out-of-range --sub-test clamps to 0 (Alpha) ---
out=$(TIMEOUT=2 bash "$SCRIPT" --subscription "file://$tmp/arr.json" --sub-test 99 --only env 2>&1)
printf '%s' "$out" | grep -qE '#0 .*Alpha.*tested below' || fail "out-of-range --sub-test should clamp to index 0"

# --- single-object sub (one config, not an array) ---
jq -c '.[0]' "$tmp/arr.json" > "$tmp/one.json"
out=$(TIMEOUT=2 bash "$SCRIPT" --subscription "file://$tmp/one.json" --only env 2>&1)
printf '%s' "$out" | grep -q 'Subscription inventory (1 configs)' || fail "a single config object should parse as 1"

# --- --no-tunnel: detectability runs (direct probe) but the tunnel probe (12) is skipped ---
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$tmp/one.json" --no-tunnel --json 2>/dev/null)
printf '%s' "$out" | jq -e '.probes.xray_detectability | has("score")' >/dev/null 2>&1 \
  || fail "--no-tunnel should still produce a detectability score (direct probes)"
printf '%s' "$out" | jq -e '.probes.xray_full_config.status == "skipped" or (.probes.xray_full_config.status == null)' >/dev/null 2>&1 \
  || fail "--no-tunnel should skip the full-config tunnel probe (12)"

# --- --sub-test all: fleet walk scores every config + prints a summary (TEST-NET → fast timeouts) ---
out=$(TIMEOUT=2 bash "$SCRIPT" --subscription "file://$tmp/arr.json" --sub-test all 2>&1)
printf '%s' "$out" | grep -q 'Subscription fleet scan' || fail "--sub-test all should run the fleet walk"
printf '%s' "$out" | grep -q 'fleet detectability:'    || fail "fleet walk should print a detectability summary"
printf '%s' "$out" | grep -q 'Alpha'                   || fail "fleet table should list each config"
printf '%s' "$out" | grep -qiE 'no vless outbound|skip' || fail "the no-proxy (Hysteria-like) config should be marked skipped"

# --- the concurrent walk must produce the SAME ordered rows as the serial walk ---
rows_par=$(TIMEOUT=2 bash "$SCRIPT" --subscription "file://$tmp/arr.json" --sub-test all 2>&1 | grep -E '^[[:space:]]+[0-9]+ ')
rows_ser=$(TIMEOUT=2 bash "$SCRIPT" --subscription "file://$tmp/arr.json" --sub-test all --sub-jobs 1 2>&1 | grep -E '^[[:space:]]+[0-9]+ ')
[ -n "$rows_par" ] || fail "parallel walk produced no data rows"
[ "$rows_par" = "$rows_ser" ] || fail "parallel (--sub-jobs 8) and serial (--sub-jobs 1) walks must render identically"

# --- default walk has NO YouTube column (regression: YT stays opt-in) ---
out=$(TIMEOUT=2 bash "$SCRIPT" --subscription "file://$tmp/arr.json" --sub-test all 2>&1)
printf '%s' "$out" | grep -q 'fingerprint-only, no tunnel' || fail "default walk header should say fingerprint-only/no tunnel"
printf '%s' "$out" | grep -q 'YouTube' && fail "default walk must NOT add a YouTube column"

# --- --sub-test all --yt-test → YT-mode walk adds a YouTube column. Fixture nodes
#     are closed loopback ports, so the nc precheck marks them dead BEFORE any xray
#     spawns → no tunnel/network needed; dead rows show "-" in the YouTube cell. ---
out=$(TIMEOUT=2 bash "$SCRIPT" --subscription "file://$tmp/arr.json" --sub-test all --yt-test 2>&1)
printf '%s' "$out" | grep -q 'tunnel + YouTube per node' || fail "--sub-test all --yt-test should switch the walk to YT mode"
printf '%s' "$out" | grep -qE '#.*remarks.*YouTube' || fail "YT-mode fleet table should have a YouTube column header"
printf '%s' "$out" | grep -q 'fleet detectability:' || fail "YT-mode walk should still print the detectability summary"

echo "PASS: --subscription decodes/inventories/selects; --no-tunnel keeps fingerprint only; --sub-test all walks the fleet (parallel == serial); --yt-test adds the YouTube column (opt-in)"
