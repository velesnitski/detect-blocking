#!/usr/bin/env bash
#
# tests/test_fet.sh — GFW fully-encrypted-traffic (FET) exposure (probe 18 lint).
# The GFW (USENIX'23) exempts traffic that looks like a known protocol (TLS
# record header, HTTP verb, mostly-printable bytes) and BLOCKS the rest by an
# entropy test. A proxy with NO TLS/HTTP framing — Shadowsocks, or VMess/VLESS
# over RAW TCP with security=none — is random from byte 0 → blocked. TLS/Reality
# and HTTP-framed transports (ws/grpc/xhttp) are exempt. Purely static, so
# deterministic + offline (run under --only xray, which skips the live tunnel).
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }
lf()  { printf '%s' "$1" | jq -r '.probes.xray_lint.fet_exposed'; }

# 1. VLESS over raw TCP, security=none → fully encrypted, no framing → exposed.
RAW='{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":1,"users":[{"id":"00000000-0000-0000-0000-000000000000","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"none"}}]}'
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$RAW" --only xray --json 2>/dev/null)
[ "$(lf "$out")" = "true" ] || fail "vless + raw TCP + security=none should be FET-exposed"
printf '%s' "$out" | jq -e '(.verdicts // []) | map(select(test("fully-encrypted-traffic"))) | length > 0' >/dev/null \
  || fail "FET exposure should raise a verdict"

# 2. Shadowsocks → fully encrypted, no framing → exposed.
SS='{"outbounds":[{"protocol":"shadowsocks","settings":{"servers":[{"address":"127.0.0.1","port":1,"method":"aes-256-gcm","password":"x"}]}}]}'
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$SS" --only xray --json 2>/dev/null)
[ "$(lf "$out")" = "true" ] || fail "shadowsocks should be FET-exposed"

# 3. REALITY (presents a TLS record header) → matches the TLS exemption → safe.
REALITY='{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":1,"users":[{"id":"00000000-0000-0000-0000-000000000000","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.microsoft.com","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortId":"01"}}}]}'
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$REALITY" --only xray --json 2>/dev/null)
[ "$(lf "$out")" = "false" ] || fail "REALITY should NOT be FET-exposed (matches the TLS exemption)"

# 4. VLESS over WebSocket, security=none → plaintext HTTP upgrade framing → exempt.
WS='{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":1,"users":[{"id":"00000000-0000-0000-0000-000000000000","encryption":"none"}]}]},"streamSettings":{"network":"ws","security":"none"}}]}'
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$WS" --only xray --json 2>/dev/null)
[ "$(lf "$out")" = "false" ] || fail "ws + security=none carries HTTP framing → not FET-exposed"

# 5. id format (share-safe): a canonical UUID id → id_uuid true; a non-UUID
# string → id_uuid false (VLESS hashes it; valid but flagged). Value never leaked.
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$REALITY" --only xray --json 2>/dev/null)
[ "$(printf '%s' "$out" | jq -r '.probes.xray_lint.id_uuid')" = "true" ] \
  || fail "a canonical UUID id should report id_uuid=true"
NONUUID=$(printf '%s' "$REALITY" | jq -c '.outbounds[0].settings.vnext[0].users[0].id = "test-nonuuid-id-001"')
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$NONUUID" --only xray --json 2>/dev/null)
[ "$(printf '%s' "$out" | jq -r '.probes.xray_lint.id_uuid')" = "false" ] \
  || fail "a non-UUID id should report id_uuid=false"
# Share-safe: the id value must NEVER appear in JSON output.
printf '%s' "$out" | grep -q 'test-nonuuid-id-001' && fail "the id value leaked into JSON output" || true

echo "PASS: FET exposure (raw/Shadowsocks flagged, TLS/HTTP-framed exempt) + share-safe id-format note"
