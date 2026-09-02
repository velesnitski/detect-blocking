#!/usr/bin/env bash
#
# tests/test_sni_keyword.sh — cover-SNI keyword detection (probe 26, severe tell).
# A passive SNI blocklist matches an antagonistic cover domain directly, so this is
# the cheapest detection a censor has. Censor NAMES (rkn / tspu) must match on label
# boundaries only: before 1.10.2 the patterns were hyphen-anchored (`*-rkn*`/`*rkn-*`)
# to avoid firing on innocent substrings — which meant a dot-delimited label slipped
# through and scored only as the softer NXDOMAIN tell.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

eval "$(awk '/^_sni_keyword_hit\(\)/,/^}/' "$SCRIPT")"

# ---- must FLAG: protocol vocabulary ----
for s in myvpn.io fast-proxy.net xray.cdn v2ray.test reality.example shadowsocks.io \
         trojan.host wireguard.net outline.dev unblock.me bypass.it censor.example \
         a.vless.io vmess-cdn.net mtproto.example socks5gate.net obfs-relay.io my-tunnel.co \
         byedpi.test psiphon.example ultrasurf.io freegate.net singbox.dev sing-box.example; do
  [ "$(_sni_keyword_hit "$s")" = "1" ] || fail "protocol keyword should flag: $s"
done

# ---- must FLAG: censor names on label boundaries (the 1.10.2 fix) ----
for s in rkn rkn.example.com blocked.rkn foo.rkn.bar my-rkn.com rkn-block.net \
         roskomnadzor.ru zapret.info antizapret.org tspu.example.net anti.tspu tspu-node.net; do
  [ "$(_sni_keyword_hit "$s")" = "1" ] || fail "censor-name keyword should flag: $s"
done
# case-insensitive
[ "$(_sni_keyword_hit 'BLOCKED.RKN')" = "1" ] || fail "matching must be case-insensitive"

# ---- must NOT flag: innocent domains that merely CONTAIN the letters ----
# darkness / networking / workname all contain "rkn"; tsputnik contains "tspu".
# sockshop / hysteria-band guard the widest of the new terms: a keyword list that
# fires on an ordinary retailer or a band is one operators learn to ignore.
for s in workname.com darkness.io networking.dev tsputnik.example \
         sockshop.com hysteria-band.net rentals.example \
         www.microsoft.com storage.yandexcloud.net m.vk.com github.com ozon.ru avito.ru; do
  [ "$(_sni_keyword_hit "$s")" = "0" ] || fail "innocent domain must NOT flag: $s"
done
[ "$(_sni_keyword_hit '')" = "0" ] || fail "empty SNI must not flag"

# ---- integration: a keyword cover scores the severe tell AND raises the verdict ----
if command -v jq >/dev/null 2>&1; then
  PBK='0000000000000000000000000000000000000000000'
  url="vless://00000000-0000-0000-0000-000000000001@127.0.0.1:1?security=reality&type=tcp&sni=blocked.rkn&fp=qq&sid=01&pbk=${PBK}&flow=xtls-rprx-vision"
  out=$(TIMEOUT=3 bash "$SCRIPT" --xray-config "$url" --only xray --no-tunnel --json 2>/dev/null)
  [ "$(printf '%s' "$out" | jq -r '.probes.xray_detectability.sni_keyword')" = "true" ] \
    || fail "a dot-anchored censor-name cover must set sni_keyword=true"
  printf '%s' "$out" | jq -e '[.verdicts[]? | select(test("antagonistic keyword"))] | length >= 1' >/dev/null \
    || fail "a keyword cover must raise the severe antagonistic-keyword verdict"
  # control: a real-looking cover must NOT set the flag
  url2="vless://00000000-0000-0000-0000-000000000001@127.0.0.1:1?security=reality&type=tcp&sni=www.microsoft.com&fp=qq&sid=01&pbk=${PBK}&flow=xtls-rprx-vision"
  out=$(TIMEOUT=3 bash "$SCRIPT" --xray-config "$url2" --only xray --no-tunnel --json 2>/dev/null)
  [ "$(printf '%s' "$out" | jq -r '.probes.xray_detectability.sni_keyword')" != "true" ] \
    || fail "a real-looking cover must NOT be flagged as a keyword SNI"
fi

echo "PASS: cover-SNI keyword — protocol vocabulary + label-anchored censor names (rkn/tspu/zapret) flagged, innocent substrings (workname/darkness/networking/tsputnik) not"
