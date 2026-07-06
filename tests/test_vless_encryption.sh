#!/usr/bin/env bash
#
# tests/test_vless_encryption.sh — VLESS Encryption awareness (Xray 2025+, the
# native post-quantum ML-KEM-768 + X25519 layer) + the VLESS-without-flow
# deprecation (XTLS/Xray-core #5568). Locks in:
#   - the pure classifier _vless_enc_method (none/native/xorpub/random/invalid);
#   - that encryption=mlkem768x25519plus.* is RECOGNIZED, not false-errored as
#     "vless requires encryption=none";
#   - FET is method-aware: random = still exposed, native/xorpub = not asserted;
#   - flow=vision over a non-raw transport with VLESS Encryption does NOT trip the
#     "handshake will fail" lint (encryption lifts the raw-TCP restriction), and
#     probe 26 reads it as vision-protected;
#   - the flow-deprecation warning fires on flow-less VLESS.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }

# ---- unit: the pure method classifier ----
body=$(awk '/^_vless_enc_method\(\)/,/^}/' "$SCRIPT")
[ -n "$body" ] || fail "could not extract _vless_enc_method"
eval "$body"
ck() { local want="$1" got; got=$(_vless_enc_method "$2"); [ "$got" = "$want" ] || fail "_vless_enc_method('$2')='$got', want '$want'"; }
ck none    ""
ck none    none
ck native  "mlkem768x25519plus.native.600s"
ck xorpub  "mlkem768x25519plus.xorpub.600s+100-111-1111"
ck random  "mlkem768x25519plus.random.0s"
ck native  "mlkem768x25519plus"
ck invalid "aes-128-gcm"
ck invalid "garbage.value"

command -v jq >/dev/null 2>&1 || { echo "PASS (unit only; jq not installed for integration)"; exit 0; }

J() { TIMEOUT=2 bash "$SCRIPT" --xray-config "$1" --only xray --json 2>/dev/null; }
T() { TIMEOUT=2 bash "$SCRIPT" --xray-config "$1" --only xray 2>/dev/null; }
u='00000000-0000-0000-0000-000000000000'

# 1) VLESSENC native + XHTTP + vision (the frontier config): recognized, NOT
#    false-errored, and the "handshake will fail" lint must NOT fire.
out=$(J "vless://$u@127.0.0.1:1?security=none&encryption=mlkem768x25519plus.native.600s&flow=xtls-rprx-vision&type=xhttp&sni=x")
[ "$(printf '%s' "$out" | jq -r '.probes.xray_lint.vless_encryption')" = "native" ] || fail "native VLESS Encryption should be recognized"
printf '%s' "$out" | jq -e '[.probes.xray_lint.findings[] | select(test("handshake will fail|requires encryption=none"))] | length == 0' >/dev/null \
  || fail "VLESSENC+xhttp+vision must NOT trip 'handshake will fail' / 'requires encryption=none'"

# 2) VLESSENC random + raw TCP + no TLS → still FET-exposed.
out=$(J "vless://$u@127.0.0.1:1?security=none&encryption=mlkem768x25519plus.random.0s&type=tcp")
[ "$(printf '%s' "$out" | jq -r '.probes.xray_lint.vless_encryption')" = "random" ] || fail "random method should be recognized"
[ "$(printf '%s' "$out" | jq -r '.probes.xray_lint.fet_exposed')" = "true" ] || fail "random VLESS Encryption on raw TCP must be FET-exposed"

# 3) VLESSENC native + raw TCP → NOT asserted as FET-exposed (native reshapes it).
out=$(J "vless://$u@127.0.0.1:1?security=none&encryption=mlkem768x25519plus.native.600s&type=tcp")
[ "$(printf '%s' "$out" | jq -r '.probes.xray_lint.fet_exposed')" = "false" ] || fail "native method should NOT be asserted FET-exposed"

# 4) flow-less VLESS → deprecation flag set.
out=$(J "vless://$u@127.0.0.1:1?security=tls&type=ws&sni=x&host=x")
[ "$(printf '%s' "$out" | jq -r '.probes.xray_lint.vless_flow_deprecated')" = "true" ] || fail "flow-less VLESS should set vless_flow_deprecated=true"

# 5) invalid encryption string → a lint finding, not silent.
out=$(J "vless://$u@127.0.0.1:1?security=reality&pbk=A&sid=01&sni=x&fp=qq&type=tcp&flow=xtls-rprx-vision&encryption=aes-128-gcm")
printf '%s' "$out" | jq -e '[.probes.xray_lint.findings[] | select(test("recognized VLESS Encryption|typo"))] | length >= 1' >/dev/null \
  || fail "an invalid encryption string should produce a lint finding"

# 6) probe 26: REALITY + gRPC + VLESS Encryption + vision → vision-protected
#    (encryption lifts the raw-TCP limit), tls_in_tls_protected=true.
out=$(J "vless://$u@127.0.0.1:1?security=reality&pbk=A&sid=01&sni=www.example.com&fp=qq&type=grpc&flow=xtls-rprx-vision&encryption=mlkem768x25519plus.native.600s")
[ "$(printf '%s' "$out" | jq -r '.probes.xray_detectability.tls_in_tls_protected')" = "true" ] \
  || fail "REALITY+gRPC+VLESS-Encryption+vision should read tls_in_tls_protected=true (encryption lifts the raw-TCP limit)"

# 7) regression: classic REALITY (no encryption) unchanged — vless_encryption=none,
#    flow present so not deprecated, and no VLESS-Encryption noise.
out=$(J "vless://$u@127.0.0.1:1?security=reality&pbk=A&sid=01&sni=www.example.com&fp=qq&type=tcp&flow=xtls-rprx-vision")
[ "$(printf '%s' "$out" | jq -r '.probes.xray_lint.vless_encryption')" = "none" ] || fail "classic reality should report vless_encryption=none"
[ "$(printf '%s' "$out" | jq -r '.probes.xray_lint.vless_flow_deprecated')" = "false" ] || fail "reality+vision should NOT be flow-deprecated"

echo "PASS: VLESS Encryption recognized (method-aware FET, no false 'encryption=none'), flow-deprecation flagged, vision-on-any-transport via encryption, classic reality unchanged"
