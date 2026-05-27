#!/usr/bin/env bash
#
# tests/test_smoke.sh — end-to-end run against the demo target.
# Asserts the script produces a header, completes all probes, and emits a
# "no blocking signals" verdict (since www.example.com is unrestricted).

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

out=$(VPN_HOST=www.example.com TIMEOUT=3 bash "$SCRIPT" 2>&1)

fail() { printf 'FAIL: %s\n' "$1" >&2; echo "$out" >&2; exit 1; }

echo "$out" | grep -q 'VPN-blocking diagnostic for www.example.com' \
  || fail "missing header"

for section in '0. Environment' '1. DNS resolution' '2. TCP reachability' \
               '3. TLS handshake' '4. Request-header' '5. Mid-handshake RST' \
               '6. UDP-based protocols' '7. OpenVPN' '8. Control' 'VERDICT'; do
  echo "$out" | grep -q "$section" || fail "missing section: $section"
done

echo "$out" | grep -q 'no blocking signals detected' \
  || fail "expected clean baseline against www.example.com"

echo "PASS: smoke test"
