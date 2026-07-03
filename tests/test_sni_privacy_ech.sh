#!/usr/bin/env bash
#
# tests/test_sni_privacy_ech.sh — probe 27 (SNI privacy / ECH posture). This is
# an ADVISORY that runs after the probe-26 synthesis (unnumbered header, so 26
# stays the last SCORED probe) and adds the axis probe 26 ignores: can the
# cleartext cover SNI be HIDDEN at all (Encrypted ClientHello), and does the
# transport allow it? Reality forgoes ECH by design (cover N/A); a TLS-over-CDN
# transport can use it. Unit-tests the pure classifier _sni_privacy_advisory,
# then an offline integration check that the JSON block is emitted and the probe
# does NOT displace probe 26 as the last numbered probe.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }

# --- unit: extract the pure classifier and assert code + a message keyword ---
body=$(awk '/^_sni_privacy_advisory\(\)/,/^}/' "$SCRIPT")
[ -n "$body" ] || fail "could not extract _sni_privacy_advisory"
eval "$body"

ckcode() { # want_code  want_substring  args...
  local wc="$1" ws="$2"; shift 2
  local got code msg; got=$(_sni_privacy_advisory "$@")
  code=${got%%|*}; msg=${got#*|}
  [ "$code" = "$wc" ] || fail "_sni_privacy_advisory($*) code='$code', want '$wc'"
  case "$msg" in *"$ws"*) ;; *) fail "_sni_privacy_advisory($*) msg lacks '$ws': $msg" ;; esac
}

# reality → cleartext by design, ECH N/A regardless of the ech arg.
ckcode reality              'BY DESIGN'          reality 1
ckcode reality              'BY DESIGN'          reality unknown
# tls + front publishes ECH but it's unused → the actionable tell.
ckcode ech-available-unused 'enabling ECH'       tls 1
# tls + front has no ECH → SNI stays visible.
ckcode ech-unpublished      'does NOT publish'   tls 0
# tls + couldn't tell → unknown (also the default when the ech arg is omitted).
ckcode ech-unknown          'could not determine' tls unknown
ckcode ech-unknown          'could not determine' tls
# anything else → n/a.
ckcode na                   'no cleartext-SNI'   ss ""

# --- integration: reality share-link, fully offline (127.0.0.1:1 = instant
# refuse; reality means NO DNS lookup, so this is hermetic and fast). ---
command -v jq >/dev/null 2>&1 || { echo "PASS (unit only; jq not installed for integration)"; exit 0; }

URL='vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?security=reality&pbk=AAAA&sid=01&sni=www.example.com&fp=qq&type=tcp'
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config "$URL" --only xray --json 2>/dev/null)
[ "$(printf '%s' "$out" | jq -r '.probes.xray_sni_privacy.status')" = "ok" ] \
  || fail "sni_privacy should be ok on a reality config"
[ "$(printf '%s' "$out" | jq -r '.probes.xray_sni_privacy.posture')" = "reality" ] \
  || fail "reality config should yield posture=reality"
[ "$(printf '%s' "$out" | jq -r '.probes.xray_sni_privacy.ech_applies')" = "false" ] \
  || fail "reality config: ech_applies should be false"
[ "$(printf '%s' "$out" | jq -r '.probes.xray_sni_privacy.ech_published_by_cover')" = "null" ] \
  || fail "reality config: ech_published_by_cover should be null (no lookup done)"

# The advisory must NOT displace probe 26 as the last NUMBERED probe.
outp=$(TIMEOUT=2 bash "$SCRIPT" --xray-config "$URL" --only xray 2>/dev/null)
last=$(printf '%s' "$outp" | grep -oE '^== [0-9]+\.' | tail -1)
[ "$last" = "== 26." ] || fail "probe 26 must stay the last numbered probe, got '$last'"
# ...and its (unnumbered) header must actually appear after it.
printf '%s' "$outp" | grep -q 'SNI privacy / ECH posture' \
  || fail "sni-privacy advisory header should be printed"

# A non-reality TLS config gets ech_applies=true and a schema-valid block.
URLT='vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?security=tls&sni=www.example.com&type=ws&host=www.example.com'
outt=$(TIMEOUT=2 bash "$SCRIPT" --xray-config "$URLT" --only xray --json 2>/dev/null)
[ "$(printf '%s' "$outt" | jq -r '.probes.xray_sni_privacy.ech_applies')" = "true" ] \
  || fail "tls transport: ech_applies should be true"

echo "PASS: probe 27 classifier (reality/ECH matrix), reality integration, 26 stays last numbered, tls ech_applies"
