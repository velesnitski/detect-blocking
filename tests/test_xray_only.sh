#!/usr/bin/env bash
#
# tests/test_xray_only.sh — the --xray-only convenience flag. It runs only the
# Xray-protocol probes (11-26 + routing/egress) and skips the transport probes
# (0-10), as an alias for --only xray,xrayjson. We use a URL config so probe 12
# (full-config tunnel) self-skips (no JSON) and the run stays fast/offline.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }

URL='vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?security=reality&pbk=AAAA&sid=01&sni=www.example.com&fp=chrome&type=tcp'

out=$(TIMEOUT=2 bash "$SCRIPT" --xray-only --xray-config "$URL" 2>&1)

# Transport probes 0-10 must be skipped.
printf '%s' "$out" | grep -qE '== 1\. DNS'             && fail "--xray-only should skip the DNS probe (1)"
printf '%s' "$out" | grep -qE '== 2\. TCP'             && fail "--xray-only should skip the TCP probe (2)"
printf '%s' "$out" | grep -qE '== 3\. TLS handshake'   && fail "--xray-only should skip the TLS probe (3)"
# An Xray-protocol probe must still run (cover/lint/detectability are 11-26).
printf '%s' "$out" | grep -qE '== (15|18|26)\.' || fail "--xray-only should run the Xray-protocol probes (11-26)"

# Guard: --xray-only with no config emits a note to stderr.
note=$(TIMEOUT=2 bash "$SCRIPT" --xray-only 2>&1 >/dev/null)
printf '%s' "$note" | grep -q 'nothing to probe' || fail "--xray-only with no config should warn 'nothing to probe'"

echo "PASS: --xray-only runs 11-26, skips transport 0-10, warns when no config given"
