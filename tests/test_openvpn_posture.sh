#!/usr/bin/env bash
#
# tests/test_openvpn_posture.sh — OpenVPN fingerprintability posture (probe 7 v2,
# --ovpn-config). Unit-tests the pure classifier, then an offline integration check
# that a parsed .ovpn reports the right posture + JSON fields, never leaks the inline
# CA/cert/key/tls-crypt secrets, and scopes to the OpenVPN probe. All endpoints are
# loopback (127.0.0.1) — no real infra, no network dependency.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

# ---- unit: the pure classifier (extracted like the other pure helpers) ----
eval "$(awk '/^_ovpn_fingerprintability\(\)/,/^}/' "$SCRIPT")"
#                                        tls_crypt tls_auth obfs
[ "$(_ovpn_fingerprintability 0 0 1)" = "wrapped" ]         || fail "obfs → wrapped"
[ "$(_ovpn_fingerprintability 1 0 0)" = "probe-resistant" ] || fail "tls-crypt → probe-resistant"
[ "$(_ovpn_fingerprintability 1 1 1)" = "wrapped" ]         || fail "obfs wins over tls-crypt/tls-auth"
[ "$(_ovpn_fingerprintability 1 1 0)" = "probe-resistant" ] || fail "tls-crypt wins over tls-auth"
[ "$(_ovpn_fingerprintability 0 1 0)" = "hmac-only" ]       || fail "tls-auth only → hmac-only"
[ "$(_ovpn_fingerprintability 0 0 0)" = "exposed" ]         || fail "nothing → exposed"

# ---- fixtures (loopback; inline blocks carry a SECRET_MARKER we assert never leaks) ----
cat > "$TMP/exposed.ovpn" <<'EOF'
client
dev tun
proto udp
remote 127.0.0.1 1194 udp
cipher AES-256-GCM
<ca>
-----BEGIN CERTIFICATE-----
CA_SECRET_MARKER_A1
-----END CERTIFICATE-----
</ca>
EOF
cat > "$TMP/hardened.ovpn" <<'EOF'
client
proto tcp
remote 127.0.0.1 443 tcp
<tls-crypt>
-----BEGIN OpenVPN Static key V1-----
TLSCRYPT_SECRET_MARKER_B2
-----END OpenVPN Static key V1-----
</tls-crypt>
EOF
cat > "$TMP/hmac.ovpn" <<'EOF'
client
proto udp
remote 127.0.0.1 1194
tls-auth ta.key 1
EOF

run() { TIMEOUT=2 bash "$SCRIPT" --ovpn-config "$1" --json 2>/dev/null; }

# exposed: no tls-crypt/tls-auth → posture exposed, fingerprintable yes, a verdict raised.
out=$(run "$TMP/exposed.ovpn")
[ "$(printf '%s' "$out" | jq -r '.probes.openvpn.posture')" = "exposed" ]        || fail "exposed → posture exposed"
[ "$(printf '%s' "$out" | jq -r '.probes.openvpn.fingerprintable')" = "yes" ]     || fail "exposed → fingerprintable yes"
[ "$(printf '%s' "$out" | jq -r '.probes.openvpn.tls_crypt')" = "false" ]         || fail "exposed → tls_crypt false"
[ "$(printf '%s' "$out" | jq -r '.probes.openvpn.proto')" = "udp" ]               || fail "exposed → proto udp"
[ "$(printf '%s' "$out" | jq -r '.probes.openvpn.config_provided')" = "true" ]    || fail "exposed → config_provided true"
printf '%s' "$out" | jq -e '[.verdicts[] | select(test("unwrapped"))] | length >= 1' >/dev/null || fail "exposed → 'unwrapped' verdict"

# hardened: tls-crypt + tcp/443 → probe-resistant, fingerprintable partial.
out=$(run "$TMP/hardened.ovpn")
[ "$(printf '%s' "$out" | jq -r '.probes.openvpn.posture')" = "probe-resistant" ] || fail "hardened → posture probe-resistant"
[ "$(printf '%s' "$out" | jq -r '.probes.openvpn.fingerprintable')" = "partial" ] || fail "hardened → fingerprintable partial"
[ "$(printf '%s' "$out" | jq -r '.probes.openvpn.tls_crypt')" = "true" ]           || fail "hardened → tls_crypt true"
[ "$(printf '%s' "$out" | jq -r '.probes.openvpn.proto')" = "tcp" ]                || fail "hardened → proto tcp"

# hmac: tls-auth only → hmac-only, fingerprintable yes.
out=$(run "$TMP/hmac.ovpn")
[ "$(printf '%s' "$out" | jq -r '.probes.openvpn.posture')" = "hmac-only" ]        || fail "hmac → posture hmac-only"
[ "$(printf '%s' "$out" | jq -r '.probes.openvpn.tls_auth')" = "true" ]            || fail "hmac → tls_auth true"

# share-safety: inline CA/cert/key/tls-crypt secrets must NEVER appear in output.
for f in exposed hardened hmac; do
  leaked=$(TIMEOUT=2 bash "$SCRIPT" --ovpn-config "$TMP/$f.ovpn" 2>&1 | grep -c 'SECRET_MARKER')
  [ "$leaked" = "0" ] || fail "$f: inline secret leaked into output ($leaked hit(s))"
  leaked=$(TIMEOUT=2 bash "$SCRIPT" --ovpn-config "$TMP/$f.ovpn" --json 2>/dev/null | grep -c 'SECRET_MARKER')
  [ "$leaked" = "0" ] || fail "$f: inline secret leaked into JSON ($leaked hit(s))"
done

# no config: the openvpn block still emits, config_provided=false, posture null.
out=$(TIMEOUT=2 bash "$SCRIPT" --only openvpn 127.0.0.1 --json 2>/dev/null)
[ "$(printf '%s' "$out" | jq -r '.probes.openvpn.config_provided')" = "false" ] || fail "no-config → config_provided false"
[ "$(printf '%s' "$out" | jq -r '.probes.openvpn.tls_crypt')" = "null" ]        || fail "no-config → tls_crypt null (unknown)"

echo "PASS: OpenVPN posture — classifier (wrapped/probe-resistant/hmac-only/exposed), .ovpn parse + JSON, secrets never leak, no-config tri-state null"
