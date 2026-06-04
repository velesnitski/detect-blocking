#!/usr/bin/env bash
#
# tests/test_routing.sh — the routing-coverage probe (split-tunnel). Tier 1 is
# pure-jq static analysis of routing.rules, so it's deterministic and offline:
# it maps rules per outbound, identifies the default route, lists proxy
# outbounds, and lints undefined outboundTags. (Tier 2's live test needs a
# working tunnel + xray-core, so only its schema presence is asserted here.)

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }
rt() { printf '%s' "$1" | jq -c '.probes.xray_routing'; }

# Split-tunnel config: youtube/telegram → proxy-foreign, a typo'd tag, default → direct.
SPLIT='{"inbounds":[{"tag":"s","listen":"127.0.0.1","port":10808,"protocol":"socks","settings":{"auth":"noauth"}}],"routing":{"rules":[{"type":"field","domain":["domain:youtube.com","geosite:telegram"],"outboundTag":"proxy-foreign"},{"type":"field","domain":["domain:typo.example"],"outboundTag":"prxy-typo"},{"type":"field","network":"tcp,udp","outboundTag":"direct"}]},"outbounds":[{"tag":"proxy-foreign","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":1,"users":[{"id":"00000000-0000-0000-0000-000000000000","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"example.net","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortId":"01"}}},{"tag":"direct","protocol":"freedom"}]}'

out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$SPLIT" --only xrayjson --json 2>/dev/null)
r=$(rt "$out")
[ "$(printf '%s' "$r" | jq -r '.status')" = "ok" ] || fail "routing probe should be 'ok' for a config with rules"
[ "$(printf '%s' "$r" | jq -r '.default_outbound')" = "direct" ] || fail "default route should resolve to 'direct' (the catch-all)"
printf '%s' "$r" | jq -e '.proxy_outbounds | index("proxy-foreign")' >/dev/null || fail "proxy_outbounds should include the vless outbound"
printf '%s' "$r" | jq -e '.undefined_outbound_tags | index("prxy-typo")' >/dev/null || fail "undefined outboundTag 'prxy-typo' should be flagged"
printf '%s' "$r" | jq -e 'has("live_test")' >/dev/null || fail "live_test field should be present"
# The undefined tag is also a verdict.
printf '%s' "$out" | jq -e '(.verdicts // []) | map(select(test("not defined in outbounds"))) | length > 0' >/dev/null \
  || fail "an undefined outboundTag should raise a verdict"

# Regression: a full-tunnel-with-bypass config — only protocol:/domain: rules go
# direct, NO catch-all, proxy is the first outbound → Xray's default is the
# PROXY (everything tunnels except the bypass). A protocol-only rule must NOT be
# mistaken for the catch-all (that read the split backwards as "selective").
BYPASS='{"inbounds":[{"tag":"s","listen":"127.0.0.1","port":10808,"protocol":"socks","settings":{"auth":"noauth"}}],"routing":{"rules":[{"type":"field","protocol":["bittorrent"],"outboundTag":"direct"},{"type":"field","domain":["domain:example.com","domain:example.net"],"outboundTag":"direct"}]},"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":1,"users":[{"id":"00000000-0000-0000-0000-000000000000","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"example.net","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortId":"01"}}},{"tag":"direct","protocol":"freedom"}]}'
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$BYPASS" --only xrayjson --json 2>/dev/null)
[ "$(rt "$out" | jq -r '.default_outbound')" = "proxy" ] \
  || fail "full-tunnel-with-bypass: default must be the first outbound (proxy), not a protocol:-only direct rule"

# A config with NO routing table → status 'none' (nothing to map).
NOROUTE='{"inbounds":[{"tag":"s","listen":"127.0.0.1","port":10808,"protocol":"socks","settings":{"auth":"noauth"}}],"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":1,"users":[{"id":"00000000-0000-0000-0000-000000000000","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"example.net","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortId":"01"}}}]}'
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$NOROUTE" --only xrayjson --json 2>/dev/null)
[ "$(rt "$out" | jq -r '.status')" = "none" ] || fail "a config with no routing.rules should report status 'none'"

echo "PASS: routing map + default route + proxy outbounds + undefined-tag lint; no-routing → none"
