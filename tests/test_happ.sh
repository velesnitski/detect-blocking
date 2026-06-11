#!/usr/bin/env bash
#
# tests/test_happ.sh — Happ deep-link input adapter. happ:// links wrap configs:
#   import/<url>     → unwrapped to the normal URL path (we point at a TEST-NET IP
#                      literal so it's offline + deterministic: DNS shows it).
#   routing/add/<b64>→ recognised as a routing profile (no server) + linted.
#   crypt…           → detected as encrypted (can't open).
#   unknown          → clean error, non-zero exit.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }
b64() { printf '%s' "$1" | base64 | tr -d '\n'; }

# --- import: happ://import/vless://…@<TEST-NET ip> → unwrapped; the IP literal
#     shows up in the DNS probe (offline, my v0.18.2 IP-literal path). ---
url='vless://00000000-0000-0000-0000-000000000000@192.0.2.7:443?security=reality&pbk=AAAA&sid=01&sni=www.example.com&fp=chrome&type=tcp&flow=xtls-rprx-vision'
out=$(TIMEOUT=3 bash "$SCRIPT" --xray-config "happ://import/${url}" --only dns 2>&1)
printf '%s' "$out" | grep -q 'unwrapped happ://import/' || fail "import link should log an unwrap note"
printf '%s' "$out" | grep -q '192.0.2.7'               || fail "import should unwrap to the inner vless and target its host"

# --- routing/add: a synthetic profile (NO real infra) → recognised + linted. ---
profile='{"Name":"Test RU Profile","DomainStrategy":"IPOnDemand","FakeDns":false,"GlobalProxy":true,"RouteOrder":"block-direct-proxy","RemoteDNSDomain":"https://cloudflare-dns.com/dns-query"}'
out=$(TIMEOUT=3 bash "$SCRIPT" --xray-config "happ://routing/add/$(b64 "$profile")" 2>&1)
printf '%s' "$out" | grep -qi 'Happ routing profile'   || fail "routing/add should be recognised as a routing profile"
printf '%s' "$out" | grep -q 'Test RU Profile'         || fail "routing profile name should be shown"
printf '%s' "$out" | grep -qi 'DNS-leak vector'        || fail "IPOnDemand + FakeDns off should warn about the DNS-leak vector"
printf '%s' "$out" | grep -qi 'blocked in some regions' || fail "cloudflare-dns remote DoH should get the region-risk note"

# --- routing/add with FakeDns on → the leak note downgrades to mitigated (info). ---
profile2='{"Name":"Mitigated","DomainStrategy":"IPOnDemand","FakeDns":true,"RemoteDNSIp":"1.1.1.1"}'
out=$(TIMEOUT=3 bash "$SCRIPT" --xray-config "happ://routing/add/$(b64 "$profile2")" 2>&1)
printf '%s' "$out" | grep -qi 'FakeDns=on here mitigates' || fail "FakeDns on should be reported as mitigating"

# --- crypt: detected as encrypted, not decoded. ---
out=$(TIMEOUT=3 bash "$SCRIPT" --xray-config 'happ://crypt4/QUJDRA==' 2>&1)
printf '%s' "$out" | grep -qi 'encrypted Happ link' || fail "crypt link should be detected as encrypted"

# --- unknown happ variant → clean error + non-zero exit. ---
if TIMEOUT=3 bash "$SCRIPT" --xray-config 'happ://nonsense/foo' >/dev/null 2>&1; then
  fail "an unrecognized happ:// link should exit non-zero"
fi

echo "PASS: happ import unwraps, routing/add recognised+linted, crypt detected, unknown errors cleanly"
