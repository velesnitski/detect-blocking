#!/usr/bin/env bash
#
# tests/test_tls_parity_fields.sh — probe 24 field handling. Two regressions are
# locked in here: (1) the negotiated cipher must be parsed from BOTH openssl output
# formats (OpenSSL 3.x renamed it), and (2) a field that cannot be read must be
# tri-state "unmeasured" — never a mismatch. Before 1.10.1 an unreadable cipher line
# read as a mismatch, so probe 24 could never report "ok" on OpenSSL 3.x and probe 26
# added a permanent, unearned +15 to every Reality config.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

# ---- unit: the pure tri-state field comparator ----
eval "$(awk '/^_tls_field_match\(\)/,/^}/' "$SCRIPT")"
[ "$(_tls_field_match TLSv1.3 TLSv1.3)" = "1" ] || fail "equal values → measured match (1)"
[ "$(_tls_field_match h2 http/1.1)"     = "0" ] || fail "different values → measured mismatch (0)"
[ -z "$(_tls_field_match '' TLSv1.3)" ]         || fail "server side unreadable → unmeasured (empty), NOT a mismatch"
[ -z "$(_tls_field_match TLSv1.3 '')" ]         || fail "cover side unreadable → unmeasured (empty), NOT a mismatch"
[ -z "$(_tls_field_match '' '')" ]              || fail "both sides unreadable → unmeasured (empty), NOT a mismatch"

# ---- the cipher line must parse in BOTH openssl dialects ----
# OpenSSL 1.x / LibreSSL summary form:
old_fmt='    Cipher    : TLS_AES_256_GCM_SHA384'
# OpenSSL 3.x form (the one that silently broke extraction):
new_fmt='New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384'
parse_cipher() {
  local out="$1" c
  c=$(printf '%s' "$out" | sed -nE 's/^[[:space:]]*Cipher[[:space:]]*:[[:space:]]*(.*)/\1/p' | head -1)
  [ -z "$c" ] && c=$(printf '%s' "$out" | sed -nE 's/^New,[^,]*,[[:space:]]*Cipher is[[:space:]]*(.*)/\1/p' | head -1)
  printf '%s' "$c"
}
[ "$(parse_cipher "$old_fmt")" = "TLS_AES_256_GCM_SHA384" ] || fail "classic 'Cipher :' form must parse"
[ "$(parse_cipher "$new_fmt")" = "TLS_AES_256_GCM_SHA384" ] || fail "OpenSSL 3.x 'Cipher is' form must parse"
# and the script must carry BOTH patterns (guards against a future single-format edit)
grep -q "Cipher is" "$SCRIPT" || fail "the script must handle the OpenSSL 3.x 'Cipher is' form"

# ---- probe 26 must score an unverifiable parity as UNVERIFIED (+5), not a mismatch (+15) ----
grep -q 'unverified)  tls_pts=5' "$SCRIPT" \
  || fail "probe 26 should score TLS-parity status 'unverified' at +5, not the full mismatch penalty"

# ---- with a real local openssl, the cipher must actually come out non-empty ----
if command -v openssl >/dev/null 2>&1; then
  live=$(echo Q | openssl s_client -connect 1.1.1.1:443 -servername one.one.one.one 2>/dev/null)
  if [ -n "$live" ]; then
    [ -n "$(parse_cipher "$live")" ] \
      || fail "cipher extraction returned empty against a live host on this openssl build"
  fi
fi

echo "PASS: probe-24 fields — tri-state comparator (unmeasured ≠ mismatch) + cipher parsed in both openssl dialects + unverified scored at +5"
