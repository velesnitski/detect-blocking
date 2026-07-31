#!/usr/bin/env bash
#
# tests/test_http_versions.sh — HTTP version posture (1.1 / 2 / 3).
# Three things are covered:
#   (a) the static alpn lint — h2 pinned on a transport that rides an HTTP/1.1 Upgrade
#       (ws / httpupgrade) needs Extended CONNECT (RFC 8441) and commonly breaks;
#   (b) the REALITY advisory — a pinned alpn must be one the cover would negotiate,
#       otherwise the operator manufactures the probe-24 parity mismatch themselves;
#   (c) the JSON surface — the negotiated ALPN of BOTH sides is exposed (it used to be
#       a lone boolean, so "negotiation differs" could not be acted on) plus the
#       advisory HTTP/3 cover-parity fields.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

PBK='0000000000000000000000000000000000000000000'
ID='00000000-0000-0000-0000-000000000001'

# ---- (a) alpn=h2 on an Upgrade-based transport must raise a lint finding ----
for net in ws httpupgrade; do
  url="vless://${ID}@127.0.0.1:1?security=tls&type=${net}&sni=cdn.example.com&fp=chrome&alpn=h2"
  out=$(TIMEOUT=3 bash "$SCRIPT" --xray-config "$url" --only xray --no-tunnel --json 2>/dev/null)
  printf '%s' "$out" | jq -e '[.probes.xray_lint.findings[]? | select(test("alpn declares h2"))] | length >= 1' >/dev/null \
    || fail "alpn=h2 with network=$net should raise the Extended-CONNECT lint"
done
# control: http/1.1 on the same transport must NOT flag
url="vless://${ID}@127.0.0.1:1?security=tls&type=ws&sni=cdn.example.com&fp=chrome&alpn=http%2F1.1"
out=$(TIMEOUT=3 bash "$SCRIPT" --xray-config "$url" --only xray --no-tunnel --json 2>/dev/null)
printf '%s' "$out" | jq -e '[.probes.xray_lint.findings[]? | select(test("alpn declares h2"))] | length == 0' >/dev/null \
  || fail "alpn=http/1.1 on ws must NOT raise the h2 lint"
# control: no alpn at all must NOT flag
url="vless://${ID}@127.0.0.1:1?security=tls&type=ws&sni=cdn.example.com&fp=chrome"
out=$(TIMEOUT=3 bash "$SCRIPT" --xray-config "$url" --only xray --no-tunnel --json 2>/dev/null)
printf '%s' "$out" | jq -e '[.probes.xray_lint.findings[]? | select(test("alpn declares h2"))] | length == 0' >/dev/null \
  || fail "an unset alpn must NOT raise the h2 lint"

# ---- (b) REALITY + pinned alpn prints the cover-parity advisory ----
url="vless://${ID}@127.0.0.1:1?security=reality&type=tcp&sni=www.microsoft.com&fp=qq&sid=01&pbk=${PBK}&alpn=h2"
out=$(TIMEOUT=3 bash "$SCRIPT" --xray-config "$url" --only xray --no-tunnel 2>&1)
printf '%s' "$out" | grep -q 'alpn is pinned' \
  || fail "a REALITY config with a pinned alpn should warn that it must match the cover"
# and a REALITY config WITHOUT alpn must stay quiet about it
url="vless://${ID}@127.0.0.1:1?security=reality&type=tcp&sni=www.microsoft.com&fp=qq&sid=01&pbk=${PBK}"
out=$(TIMEOUT=3 bash "$SCRIPT" --xray-config "$url" --only xray --no-tunnel 2>&1)
printf '%s' "$out" | grep -q 'alpn is pinned' \
  && fail "no alpn set → the pinned-alpn advisory must not appear"

# ---- (c) the JSON surface exists (values are null when probe 24 cannot run) ----
out=$(TIMEOUT=3 bash "$SCRIPT" --xray-config "$url" --only xray --no-tunnel --json 2>/dev/null)
printf '%s' "$out" | jq -e '.probes.xray_tls_parity
        | has("server_alpn") and has("cover_alpn") and has("cover_http3") and has("http3_parity")' >/dev/null \
  || fail "probe 24 JSON must expose server_alpn/cover_alpn/cover_http3/http3_parity"
# when the probe cannot complete, they must be null — never an invented value
[ "$(printf '%s' "$out" | jq -r '.probes.xray_tls_parity.server_alpn')" = "null" ] \
  || fail "unreachable target → server_alpn must be null, not fabricated"
# http3_parity, when set, must be one of the known classes
case "$(printf '%s' "$out" | jq -r '.probes.xray_tls_parity.http3_parity')" in
  null|ok|cover-only|n/a) ;;
  *) fail "http3_parity must be null | ok | cover-only | n/a" ;;
esac

echo "PASS: HTTP versions — alpn lint (h2 vs ws/httpupgrade Upgrade semantics), REALITY pinned-alpn advisory, and ALPN/HTTP-3 parity exposed in JSON"
