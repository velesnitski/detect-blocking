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

# domainStrategy / DNS-leak: IPOnDemand + an ip/geoip rule + NO dns block →
# dns_leak_risk true (Xray resolves domains via the system resolver). Pure-jq /
# static, so deterministic.
LEAK='{"inbounds":[{"tag":"s","listen":"127.0.0.1","port":10808,"protocol":"socks","settings":{"auth":"noauth"},"sniffing":{"enabled":true,"routeOnly":true,"destOverride":["tls"]}}],"routing":{"domainStrategy":"IPOnDemand","rules":[{"type":"field","domain":["geosite:telegram"],"outboundTag":"proxy"},{"type":"field","ip":["geoip:telegram"],"outboundTag":"proxy"},{"type":"field","network":"tcp,udp","outboundTag":"direct"}]},"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":1,"users":[{"id":"00000000-0000-0000-0000-000000000000","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"example.net","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortId":"01"}}},{"tag":"direct","protocol":"freedom"}]}'
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$LEAK" --only xrayjson --json 2>/dev/null)
[ "$(rt "$out" | jq -r '.domain_strategy')" = "IPOnDemand" ] || fail "domain_strategy should be reported (IPOnDemand)"
[ "$(rt "$out" | jq -r '.dns_leak_risk')" = "true" ]      || fail "IPOnDemand + no dns block should set dns_leak_risk=true"
# Same config switched to AsIs → no local resolution → no leak.
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$(printf '%s' "$LEAK" | sed 's/IPOnDemand/AsIs/')" --only xrayjson --json 2>/dev/null)
[ "$(rt "$out" | jq -r '.dns_leak_risk')" = "false" ] || fail "domainStrategy=AsIs should NOT be a DNS-leak risk"
# Sniffing is reported (the LEAK config enables it on the inbound).
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$LEAK" --only xrayjson --json 2>/dev/null)
[ "$(rt "$out" | jq -r '.sniffing')" = "true" ] || fail "sniffing should be reported true when an inbound enables it"

# Precision: IPOnDemand with NO ip/geoip rules NEVER resolves (it only resolves
# to evaluate an ip rule) → NOT a leak, even with no dns block. IPIfNonMatch in
# the same shape DOES leak (it resolves every unmatched destination regardless).
NOIP='{"inbounds":[{"tag":"s","listen":"127.0.0.1","port":10808,"protocol":"socks","settings":{"auth":"noauth"},"sniffing":{"enabled":true,"routeOnly":true,"destOverride":["tls"]}}],"routing":{"domainStrategy":"IPOnDemand","rules":[{"type":"field","domain":["domain:youtube.com"],"outboundTag":"proxy"},{"type":"field","network":"tcp,udp","outboundTag":"direct"}]},"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":1,"users":[{"id":"00000000-0000-0000-0000-000000000000","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"example.net","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortId":"01"}}},{"tag":"direct","protocol":"freedom"}]}'
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$NOIP" --only xrayjson --json 2>/dev/null)
[ "$(rt "$out" | jq -r '.dns_leak_risk')" = "false" ] || fail "IPOnDemand with no ip/geoip rules is a no-op, NOT a DNS leak"
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$(printf '%s' "$NOIP" | sed 's/IPOnDemand/IPIfNonMatch/')" --only xrayjson --json 2>/dev/null)
[ "$(rt "$out" | jq -r '.dns_leak_risk')" = "true" ] || fail "IPIfNonMatch + no dns leaks regardless of ip rules"

# Split-horizon dns: a dns block with per-domain servers (in real configs a
# tunneled foreign resolver + a local domestic one) is the leak-free way to keep
# geoip routing. Detection is STATIC jq over the config shape (per-domain server
# objects), so the fixture is `freedom`-only with no proxy outbound: that makes
# probe 12 skip the live tunnel entirely (a dns block + IPOnDemand + a dead proxy
# would otherwise stall xray's resolver locally when xray is installed). With a
# dns block present, IPOnDemand is not a leak; split-horizon is reported true.
SPLITDNS='{"inbounds":[{"tag":"s","listen":"127.0.0.1","port":10808,"protocol":"socks","settings":{"auth":"noauth"},"sniffing":{"enabled":true,"routeOnly":true,"destOverride":["tls"]}}],"dns":{"servers":[{"address":"localhost","domains":["example.com"]},{"address":"localhost","domains":["example.net"]}],"queryStrategy":"UseIP"},"routing":{"domainStrategy":"IPOnDemand","rules":[{"type":"field","ip":["geoip:telegram"],"outboundTag":"direct"},{"type":"field","network":"tcp,udp","outboundTag":"direct"}]},"outbounds":[{"tag":"direct","protocol":"freedom"}]}'
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$SPLITDNS" --only xrayjson --json 2>/dev/null)
[ "$(rt "$out" | jq -r '.dns_leak_risk')" = "false" ]     || fail "IPOnDemand WITH a dns block should not be flagged a leak"
[ "$(rt "$out" | jq -r '.dns_split_horizon')" = "true" ]  || fail "per-domain dns servers should be detected as split-horizon"
# A single-server dns block (no per-domain map) → split_horizon false (still present).
SINGLEDNS=$(printf '%s' "$SPLITDNS" | jq -c '.dns.servers = ["localhost"]')
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$SINGLEDNS" --only xrayjson --json 2>/dev/null)
[ "$(rt "$out" | jq -r '.dns_split_horizon')" = "false" ] || fail "a single-server dns block is not split-horizon"
# No dns block → split_horizon null (unknown), schema field still present.
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$LEAK" --only xrayjson --json 2>/dev/null)
printf '%s' "$(rt "$out")" | jq -e 'has("dns_split_horizon")' >/dev/null || fail "dns_split_horizon must be in the schema"
[ "$(rt "$out" | jq -r '.dns_split_horizon')" = "null" ]  || fail "no dns block → dns_split_horizon should be null"

# Egress-vs-routing: a config routing a streaming service through the proxy is
# tagged streaming in proxy_sensitive_categories (static parse; the conflict
# verdict itself needs a live datacenter egress, so only the field is asserted).
STREAM='{"inbounds":[{"tag":"s","listen":"127.0.0.1","port":10808,"protocol":"socks","settings":{"auth":"noauth"}}],"routing":{"rules":[{"type":"field","domain":["domain:netflix.com","domain:adobe.com"],"outboundTag":"proxy"},{"type":"field","network":"tcp,udp","outboundTag":"direct"}]},"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":1,"users":[{"id":"00000000-0000-0000-0000-000000000000","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"example.net","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortId":"01"}}},{"tag":"direct","protocol":"freedom"}]}'
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$STREAM" --only xrayjson --json 2>/dev/null)
printf '%s' "$(rt "$out")" | jq -e '.proxy_sensitive_categories | index("streaming")' >/dev/null \
  || fail "a streaming domain routed to the proxy should be tagged 'streaming'"
# A config with no streaming/payment domains → empty categories.
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$LEAK" --only xrayjson --json 2>/dev/null)
[ "$(rt "$out" | jq -r '.proxy_sensitive_categories | length')" = "0" ] \
  || fail "a config with no streaming/payment proxy domains should have empty proxy_sensitive_categories"

# A config with NO routing table → status 'none' (nothing to map).
NOROUTE='{"inbounds":[{"tag":"s","listen":"127.0.0.1","port":10808,"protocol":"socks","settings":{"auth":"noauth"}}],"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":1,"users":[{"id":"00000000-0000-0000-0000-000000000000","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"example.net","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortId":"01"}}}]}'
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$NOROUTE" --only xrayjson --json 2>/dev/null)
[ "$(rt "$out" | jq -r '.status')" = "none" ] || fail "a config with no routing.rules should report status 'none'"

echo "PASS: routing map + default route + undefined-tag lint + domainStrategy DNS-leak (per-strategy precision + split-horizon dns) + streaming/payment-vs-egress tag; no-routing → none"
