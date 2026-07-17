#!/usr/bin/env bash
#
# tests/test_dns_block.sh — DNS-level block disambiguation. When system-DNS and DoH
# resolve to different public IPs, the probe now TLS-tests both: a dead system IP + a
# live DoH IP = DNS-layer block/poisoning (not "TLS DPI"). Unit-tests the pure verdict
# and the _tls_reachable helper, and checks the additive JSON defaults. Loopback only.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

# ---- unit: the pure divergence classifier (sys_tls, doh_tls) → class ----
eval "$(awk '/^_dns_block_verdict\(\)/,/^}/' "$SCRIPT")"
[ "$(_dns_block_verdict 0 1)" = "dns-block" ]  || fail "system dead + DoH live → dns-block"
[ "$(_dns_block_verdict 1 0)" = "system-ok" ]  || fail "system serves → system-ok (benign divergence)"
[ "$(_dns_block_verdict 1 1)" = "system-ok" ]  || fail "system serves (both ok) → system-ok"
[ "$(_dns_block_verdict 0 0)" = "both-fail" ]  || fail "neither serves → both-fail (real IP block / dead)"

# ---- _tls_reachable: a closed loopback :443 must read as NOT reachable ----
eval "$(awk '/^_nc_tcp_probe\(\)/,/^}/' "$SCRIPT")"
eval "$(awk '/^_tls_reachable\(\)/,/^}/' "$SCRIPT")"
if TIMEOUT=2 _tls_reachable 127.0.0.1 example.com; then
  fail "_tls_reachable should return non-zero for a closed loopback :443"
fi
[ -z "$(_tls_reachable '' example.com && echo reachable)" ] || fail "_tls_reachable empty IP → non-zero"

# ---- additive JSON: fields present, defaults when there's no divergence ----
out=$(TIMEOUT=3 bash "$SCRIPT" --only dns 127.0.0.1 --json 2>/dev/null)
[ "$(printf '%s' "$out" | jq -r '.probes.dns.dns_block')" = "false" ]        || fail "no divergence → dns_block false"
[ "$(printf '%s' "$out" | jq -r '.probes.dns.divergence_class')" = "null" ]   || fail "no divergence → divergence_class null"

echo "PASS: dns-block — divergence classifier (dns-block/system-ok/both-fail) + _tls_reachable + additive JSON"
