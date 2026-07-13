#!/usr/bin/env bash
#
# tests/test_config_validity.sh — "config is broken" analytics (probe 18). Catches
# the common structural bugs that stop xray from LOADING at all — which otherwise
# surface only as a cryptic probe-12 tunnel failure: duplicate outbound tags and
# JSON-string ports. Unit-tests the pure detectors, then an offline integration
# check that a broken config reports config_valid=false + a "will NOT load" verdict.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

u='00000000-0000-0000-0000-000000000000'
# broken: two outbounds share tag "p", and ports are JSON strings.
cat > "$TMP/broken.json" <<EOF
{ "outbounds": [
  {"tag":"p","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":"1","users":[{"id":"$u","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"publicKey":"A","serverName":"x","shortId":"01","fingerprint":"qq"}}},
  {"tag":"p","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":"2","users":[{"id":"$u","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"publicKey":"B","serverName":"y","shortId":"01","fingerprint":"qq"}}},
  {"tag":"direct","protocol":"freedom"} ] }
EOF
# clean: unique tags, integer ports.
cat > "$TMP/clean.json" <<EOF
{ "outbounds": [
  {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":1,"users":[{"id":"$u","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"publicKey":"A","serverName":"x","shortId":"01","fingerprint":"qq"}}},
  {"tag":"direct","protocol":"freedom"} ] }
EOF

# ---- unit: the pure detectors ----
eval "$(awk '/^_dup_outbound_tags\(\)/,/^}/' "$SCRIPT")"
eval "$(awk '/^_string_ports_present\(\)/,/^}/' "$SCRIPT")"
[ "$(_dup_outbound_tags "$TMP/broken.json")" = "p" ] || fail "_dup_outbound_tags should return 'p' for the broken config"
[ -z "$(_dup_outbound_tags "$TMP/clean.json")" ]     || fail "_dup_outbound_tags should be empty for unique tags"
[ "$(_string_ports_present "$TMP/broken.json")" = "1" ] || fail "_string_ports_present should be 1 for string ports"
[ -z "$(_string_ports_present "$TMP/clean.json")" ]     || fail "_string_ports_present should be empty for integer ports"

# ---- integration (offline, loopback) ----
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$TMP/broken.json" --no-tunnel --json 2>/dev/null)
[ "$(printf '%s' "$out" | jq -r '.probes.xray_lint.config_valid')" = "false" ] \
  || fail "broken config should report config_valid=false"
printf '%s' "$out" | jq -e '[.probes.xray_lint.findings[] | select(test("duplicate outbound tag"))] | length >= 1' >/dev/null \
  || fail "broken config should have a duplicate-tag finding"
printf '%s' "$out" | jq -e '[.probes.xray_lint.findings[] | select(test("port. is a JSON string"))] | length >= 1' >/dev/null \
  || fail "broken config should have a string-port finding"
printf '%s' "$out" | jq -e '[.verdicts[] | select(test("will NOT load"))] | length >= 1' >/dev/null \
  || fail "broken config should raise a 'will NOT load' verdict"

# clean config: no structural bug → config_valid is null (not false), no dup/port finding.
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$TMP/clean.json" --no-tunnel --json 2>/dev/null)
[ "$(printf '%s' "$out" | jq -r '.probes.xray_lint.config_valid')" != "false" ] \
  || fail "a structurally-clean config must NOT be flagged config_valid=false"

echo "PASS: config-validity — dup-tag + string-port detectors, broken config flagged (config_valid=false + verdict), clean config not"
