#!/usr/bin/env bash
#
# tests/test_whitelist.sh — whitelist-restriction probe + --label vantage stamp +
# httpupgrade transport lint. Unit-tests the pure classifier, then offline checks that
# the JSON blocks are well-formed. The `restricted` quadrant needs a genuinely captive
# network, so it is covered by the classifier units rather than a live path.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

# ---- unit: the pure whitelist classifier (permitted_ok, controls_ok) → status ----
eval "$(awk '/^_classify_whitelist\(\)/,/^}/' "$SCRIPT")"
[ "$(_classify_whitelist 2 2)" = "open" ]                  || fail "both reachable → open"
[ "$(_classify_whitelist 1 2)" = "open" ]                  || fail "controls reachable → open"
[ "$(_classify_whitelist 2 0)" = "restricted" ]            || fail "permitted only → restricted"
[ "$(_classify_whitelist 1 0)" = "restricted" ]            || fail "one permitted, no controls → restricted"
[ "$(_classify_whitelist 0 2)" = "permitted-unreachable" ] || fail "controls only → permitted-unreachable (foreign vantage)"
[ "$(_classify_whitelist 0 0)" = "no-network" ]            || fail "nothing reachable → no-network"
[ "$(_classify_whitelist '' '')" = "no-network" ]          || fail "empty counts → no-network (no crash)"

# ---- whitelist JSON block is well-formed and the probe is skippable ----
out=$(TIMEOUT=5 bash "$SCRIPT" --only whitelist 127.0.0.1 --json 2>/dev/null)
printf '%s' "$out" | jq -e '.probes.whitelist | has("status") and has("permitted_reachable") and has("controls_reachable")' >/dev/null \
  || fail "whitelist block should expose status/permitted_reachable/controls_reachable"
case "$(printf '%s' "$out" | jq -r '.probes.whitelist.status')" in
  open|restricted|permitted-unreachable|no-network) ;;
  *) fail "whitelist status should be one of the four classes" ;;
esac
# not selected → stays null (additive, no side effects on other runs)
out=$(TIMEOUT=3 bash "$SCRIPT" --only env 127.0.0.1 --json 2>/dev/null)
[ "$(printf '%s' "$out" | jq -r '.probes.whitelist.status')" = "null" ] \
  || fail "probe not selected → whitelist.status null"

# ---- --label: stamped when given, null when not ----
out=$(TIMEOUT=3 bash "$SCRIPT" --only env --label lte-megafon 127.0.0.1 --json 2>/dev/null)
[ "$(printf '%s' "$out" | jq -r '.label')" = "lte-megafon" ] || fail "--label should be stamped into .label"
out=$(TIMEOUT=3 bash "$SCRIPT" --only env 127.0.0.1 --json 2>/dev/null)
[ "$(printf '%s' "$out" | jq -r '.label')" = "null" ]        || fail "no --label → .label null"
# the label must survive a baseline round-trip and be named in the diff header
TIMEOUT=4 bash "$SCRIPT" --only env --label wifi-mgts 127.0.0.1 --save-baseline "$TMP/bl.json" --json >/dev/null 2>&1
[ "$(jq -r '.label' "$TMP/bl.json")" = "wifi-mgts" ] || fail "saved baseline should carry its label"
out=$(TIMEOUT=4 bash "$SCRIPT" --only env --label lte-megafon 127.0.0.1 --diff-baseline "$TMP/bl.json" 2>&1)
printf '%s' "$out" | grep -q 'vantage: baseline wifi-mgts' || fail "diff header should name both vantages"

# ---- httpupgrade transport lint (the CDN-frontable transport) ----
u='00000000-0000-0000-0000-000000000000'
cat > "$TMP/hu.json" <<EOF
{ "outbounds": [
 {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":1,"users":[{"id":"$u","encryption":"none"}]}]},
  "streamSettings":{"network":"httpupgrade","security":"tls","tlsSettings":{"serverName":"cdn.example.com","fingerprint":"chrome"},"httpupgradeSettings":{"host":"cdn.example.com"}}},
 {"tag":"direct","protocol":"freedom"} ] }
EOF
out=$(TIMEOUT=4 bash "$SCRIPT" --xray-config-json "$TMP/hu.json" --only xray --no-tunnel --json 2>/dev/null)
printf '%s' "$out" | jq -e '[.probes.xray_lint.findings[]? | select(test("httpupgradeSettings.path is empty"))] | length >= 1' >/dev/null \
  || fail "httpupgrade without a path should raise a lint finding"
# with a path: no path finding, and FET must stay false (HTTP framing, not entropy-exposed)
sed 's|"host":"cdn.example.com"|"path":"/ws","host":"cdn.example.com"|' "$TMP/hu.json" > "$TMP/hu_ok.json"
out=$(TIMEOUT=4 bash "$SCRIPT" --xray-config-json "$TMP/hu_ok.json" --only xray --no-tunnel --json 2>/dev/null)
printf '%s' "$out" | jq -e '[.probes.xray_lint.findings[]? | select(test("httpupgradeSettings.path is empty"))] | length == 0' >/dev/null \
  || fail "httpupgrade WITH a path should not raise the path finding"
[ "$(printf '%s' "$out" | jq -r '.probes.xray_lint.fet_exposed')" = "false" ] \
  || fail "httpupgrade carries HTTP framing → fet_exposed must be false"

echo "PASS: whitelist classifier (open/restricted/permitted-unreachable/no-network) + --label vantage round-trip + httpupgrade lint"
