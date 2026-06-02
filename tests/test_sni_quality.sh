#!/usr/bin/env bash
#
# tests/test_sni_quality.sh — probe 26 cover-SNI quality (Fix C). A Reality
# cover SNI is sent in cleartext in every ClientHello, so a valid cert can't
# hide a self-cooked or keyword-bearing name. Probe 26 must flag:
#   (a) an SNI that does not publicly resolve (NXDOMAIN) — a .invalid TLD
#       (RFC 2606) never resolves, so this is deterministic and offline-safe;
#   (b) an SNI carrying a circumvention keyword (pure string match — offline).
# Server is 127.0.0.1:1 (instant refuse) so the cover probe sets a non-skipped
# status and probe 26 runs; no real endpoint is needed.

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }

det() { printf '%s' "$1" | jq -r ".probes.xray_detectability.$2"; }

base='vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=01&fp=chrome&type=tcp'

# Case A — keyword SNI (contains "vpn"), non-resolving .invalid TLD.
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config "$base&sni=vpn-node-test.invalid" --only xray --json 2>/dev/null)
[ "$(det "$out" sni_keyword)"  = "true"  ] || fail "keyword SNI should set sni_keyword=true"
[ "$(det "$out" sni_resolves)" = "false" ] || fail ".invalid SNI should set sni_resolves=false"

# Case B — clean-looking but still non-resolving (no keyword).
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config "$base&sni=qzxwlk-node-7.invalid" --only xray --json 2>/dev/null)
[ "$(det "$out" sni_keyword)"  = "false" ] || fail "non-keyword SNI should set sni_keyword=false"
[ "$(det "$out" sni_resolves)" = "false" ] || fail ".invalid SNI should set sni_resolves=false"

# Both cases must carry the non-resolving tell into the score (>=10).
score=$(det "$out" score)
[ "${score:-0}" -ge 10 ] || fail "non-resolving cover SNI should add >=10 to detectability, got '$score'"

# Case C — FP guard: a real, resolving domain must NOT be flagged non-resolving,
# and (key) a transient/timeout DNS miss must not either — only a confirmed
# NXDOMAIN flags. example.com resolves online; offline its lookup times out
# (SERVFAIL/timeout, NOT NXDOMAIN), so either way sni_resolves != false.
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config "$base&sni=example.com" --only xray --json 2>/dev/null)
[ "$(det "$out" sni_resolves)" != "false" ] || fail "a real/transient-miss SNI must not be flagged non-resolving (only a confirmed NXDOMAIN should)"
[ "$(det "$out" sni_keyword)"  = "false"  ] || fail "example.com carries no keyword"

echo "PASS: probe 26 flags NXDOMAIN + keyword cover SNIs, no false positive on a real domain"
