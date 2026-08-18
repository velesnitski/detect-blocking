#!/usr/bin/env bash
#
# tests/test_cdn_detection.sh — CDN-edge detection is TRI-STATE.
#
# An open 8080/2053 means opposite things depending on what the host is: on your own
# origin it is a takeover risk, on a CDN edge it is the CDN's own port served by
# design. So "is this a CDN edge" must distinguish NO from CANNOT-TELL.
#
# Before 1.12.1 it did not: a failed lookup collapsed into "not a CDN" and produced a
# false takeover verdict on CDN-fronted hosts. That fired routinely, because the
# caller passes VPN_HOST when probe 1 has not run (--only xray / --skip dns) and the
# IP-info APIs 404 on a hostname. Found on a CDN-fronted fleet: every
# node reported an exposed panel that did not exist.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

check_cmd() { command -v "$1" >/dev/null 2>&1; }
TIMEOUT=5
eval "$(awk '/^_curl\(\)/,/^}/' "$SCRIPT")"
eval "$(awk '/^_first_word\(\)/,/^}/' "$SCRIPT")"
eval "$(awk '/^_is_ip_literal\(\)/,/^}/' "$SCRIPT")"
eval "$(awk '/^_resolve_a_records\(\)/,/^}/' "$SCRIPT")"
eval "$(awk '/^_is_cdn_ip\(\)/,/^}/' "$SCRIPT")"

# ---- unit: unknown must be exit 2, never 1 ("not a CDN") ----
rc=0; _is_cdn_ip "" || rc=$?
[ "$rc" = "2" ] || fail "empty input must be UNKNOWN (2), got $rc"
rc=0; _is_cdn_ip "no-such-host.invalid" || rc=$?
[ "$rc" = "2" ] || fail "an unresolvable name must be UNKNOWN (2), not 'not a CDN' (1), got $rc"

# ---- static: the caller must branch on the unknown state and NOT raise a verdict ----
blk=$(awk '/_cdnrc=0; _is_cdn_ip/,/^  fi$/' "$SCRIPT")
[ -n "$blk" ] || fail "could not locate the host-exposure CDN branch"
printf '%s' "$blk" | grep -q '_cdnrc" = "2"' \
  || fail "host exposure must handle the UNKNOWN CDN state explicitly"
# the unknown arm must not add a verdict — assert no add_verdict before the 'no' arm
unknown_arm=$(printf '%s' "$blk" | sed -n '/_cdnrc" = "2"/,/elif/p')
printf '%s' "$unknown_arm" | grep -q 'add_verdict' \
  && fail "the UNKNOWN arm must NOT raise a takeover verdict (that is the false positive)"

# ---- the auto panel-probe must not fire on an unknown CDN state ----
grep -q 'XRAY_HOSTEXP_CDN:-}" = "0"' "$SCRIPT" \
  || fail "auto --panel-probe should trigger only on a CONFIRMED non-CDN (=0), not on unknown"

# ---- integration: a CDN-fronted host must not report an exposed panel, with or
#      without the dns probe having run (the regression that started this) ----
if command -v jq >/dev/null 2>&1 && command -v dig >/dev/null 2>&1; then
  for only in "xray" "dns,xray"; do
    url='vless://00000000-0000-0000-0000-000000000001@www.cloudflare.com:443?security=tls&type=ws&sni=www.cloudflare.com&fp=chrome'
    out=$(TIMEOUT=6 bash "$SCRIPT" --xray-config "$url" --only "$only" --no-tunnel --json 2>/dev/null)
    n=$(printf '%s' "$out" | jq -r '[.verdicts[]?|select(test("proxy-panel port"))]|length')
    [ "$n" = "0" ] || fail "--only $only: a CDN-fronted host must not raise a panel-exposure verdict (got $n)"
  done
fi

echo "PASS: CDN detection is tri-state (unknown != 'not a CDN'), hostnames are resolved first, and an unknown state raises no takeover verdict"
