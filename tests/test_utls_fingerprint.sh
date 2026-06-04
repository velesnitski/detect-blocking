#!/usr/bin/env bash
#
# tests/test_utls_fingerprint.sh — probe 26's uTLS-fingerprint signal + the
# deployment fingerprint (provider-match hash). A regional/uncommon uTLS fp
# (qq, 360) is a distinctive, stable JA3 → scored + flagged; a common one
# (chrome) is not. The deployment fingerprint is a stable, share-safe hash of
# the config's identifying shape: same config → same hash; a changed fp → a
# different hash. Deterministic/offline (parsing + openssl hash; the reality
# config points at 127.0.0.1:1 so the cover probe sets a non-skipped status and
# probe 26 runs).

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }
command -v openssl >/dev/null 2>&1 || { echo "SKIP: openssl not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

cfg() {  # $1 = fingerprint value
  printf '%s' '{"inbounds":[{"protocol":"socks","port":10808,"listen":"127.0.0.1","settings":{"auth":"noauth"}}],"outbounds":[{"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":1,"users":[{"id":"00000000-0000-0000-0000-000000000000","encryption":"none","flow":"xtls-rprx-vision"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.example.com","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","shortId":"01","fingerprint":"'"$1"'"}}}]}'
}
det() { printf '%s' "$1" | jq -r ".probes.xray_detectability.$2"; }

# qq → flagged uncommon (reported), and the SCORE captured.
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$(cfg qq)" --only xrayjson --json 2>/dev/null)
[ "$(det "$out" utls_fp_uncommon)" = "true" ]  || fail "fp=qq should set utls_fp_uncommon=true"
fp_qq=$(det "$out" deployment_fingerprint)
score_qq=$(det "$out" score)
[ -n "$fp_qq" ] && [ "$fp_qq" != "null" ]       || fail "deployment_fingerprint should be present"

# chrome → common, not flagged.
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$(cfg chrome)" --only xrayjson --json 2>/dev/null)
[ "$(det "$out" utls_fp_uncommon)" = "false" ] || fail "fp=chrome should set utls_fp_uncommon=false"
fp_chrome=$(det "$out" deployment_fingerprint)
score_chrome=$(det "$out" score)

# The uTLS fp is a TRADEOFF, NOT scored: qq and an otherwise-identical chrome
# config must yield the SAME detectability score (rarity neither helps nor hurts
# the number — the operator's empirical result vs the censor decides).
[ "$score_qq" = "$score_chrome" ] \
  || fail "uTLS fp must not change the score (qq=$score_qq vs chrome=$score_chrome) — it's a tradeoff, not scored"

# Fingerprint stability + sensitivity: same config → same hash; fp change → different.
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$(cfg qq)" --only xrayjson --json 2>/dev/null)
[ "$(det "$out" deployment_fingerprint)" = "$fp_qq" ] || fail "deployment fingerprint must be stable for the same config"
[ "$fp_qq" != "$fp_chrome" ] || fail "a different uTLS fp must still change the deployment fingerprint (identification)"

echo "PASS: uncommon uTLS fp reported but NOT scored (tradeoff); fingerprint stable + fp-sensitive"
