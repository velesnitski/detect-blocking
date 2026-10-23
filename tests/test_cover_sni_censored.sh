#!/usr/bin/env bash
#
# tests/test_cover_sni_censored.sh — the cover-SNI censorship differential
# (advisory, direct). It disambiguates a blocked node IP from a blocked cover
# serverName by handshaking the cover's OWN origin with the cover SNI vs a
# neutral control SNI. Offline-deterministic without crafting a censor: the
# branches exercised here are decided purely by local name resolution —
#   - no config / non-xray dispatch        → probe does not run      (status null)
#   - a cover serverName that cannot resolve → no independent origin  (no-origin)
#   - a cover serverName that resolves to the node itself → self-host (self-hosted)
# so no network to any real host is needed. The sni-blocked verdict needs a real
# on-path filter and is intentionally NOT asserted here.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }
cc()   { printf '%s' "$1" | jq -c '.probes.cover_sni_censored'; }

PBK='0000000000000000000000000000000000000000000'
UUID='00000000-0000-0000-0000-000000000001'
mk() { printf 'vless://%s@127.0.0.1:1?security=reality&type=tcp&sni=%s&fp=qq&sid=01&pbk=%s&flow=xtls-rprx-vision' "$UUID" "$1" "$PBK"; }

# 1) Not dispatched (no xray probe selected) → the whole object is null.
out=$(TIMEOUT=3 bash "$SCRIPT" --only env --json 2>/dev/null)
[ "$(cc "$out" | jq -r '.status')" = "null" ] \
  || fail "cover_sni_censored should be null when no xray probe runs"

# 2) Reality cover that cannot resolve (RFC 6761 .invalid) → no reachable origin
#    to differential against. Deterministic offline (guaranteed NXDOMAIN).
out=$(TIMEOUT=3 bash "$SCRIPT" --xray-config "$(mk cover.invalid)" --only xray --no-tunnel --json 2>/dev/null)
[ "$(cc "$out" | jq -r '.status')" = "no-origin" ] \
  || fail "a non-resolving cover serverName should yield status=no-origin"
cc "$out" | jq -e 'has("status") and has("cover_origin_handshake") and has("control_sni_handshake")' >/dev/null \
  || fail "cover_sni_censored schema missing keys"

# 3) Reality cover that resolves to the node itself (localhost → 127.0.0.1, the
#    config host) → no independent origin exists. Deterministic offline.
out=$(TIMEOUT=3 bash "$SCRIPT" --xray-config "$(mk localhost)" --only xray --no-tunnel --json 2>/dev/null)
[ "$(cc "$out" | jq -r '.status')" = "self-hosted" ] \
  || fail "a cover resolving to the node itself should yield status=self-hosted"

# 4) Non-Reality transport → the probe is not applicable → skipped (object present,
#    booleans null). A plain-TLS config carries its real host as the SNI.
url_tls=$(printf 'vless://%s@127.0.0.1:1?security=tls&type=tcp&sni=cover.invalid&fp=qq&flow=xtls-rprx-vision' "$UUID")
out=$(TIMEOUT=3 bash "$SCRIPT" --xray-config "$url_tls" --only xray --no-tunnel --json 2>/dev/null)
st=$(cc "$out" | jq -r '.status')
[ "$st" = "skipped" ] || [ "$st" = "null" ] \
  || fail "a non-Reality config should skip the cover-SNI censorship probe (got: $st)"

echo "PASS: cover-SNI censorship differential — dispatch gating, no-origin / self-hosted / non-reality branches, schema intact"
