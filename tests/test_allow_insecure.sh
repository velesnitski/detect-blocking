#!/usr/bin/env bash
#
# tests/test_allow_insecure.sh — allowInsecure / insecure=true handling.
#
# Two things must hold for a skip-verify WS/TLS share-link (the sing-box
# "insecure": true class): (1) the config lint (probe 18, static — fires even
# against an unreachable node) must flag allowInsecure as a detectability tell,
# and (2) both client spellings (allowInsecure= and insecure=) must be honored.
# The lint is static, so this is deterministic and offline (CI-safe). The synth
# half (carrying allowInsecure into tlsSettings) is covered by the standalone
# jq check in the commit; here we lock the user-visible detection.

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }

has_insecure_finding() {
  printf '%s' "$1" \
    | jq -e '.probes.xray_lint.findings | map(select(test("allowInsecure"))) | length > 0' \
      >/dev/null 2>&1
}

base='vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?type=ws&security=tls&sni=example.com&host=example.com&path=%2Fp'

# Case A — allowInsecure=1 → lint flags it.
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config "$base&allowInsecure=1" --only xray --json 2>/dev/null)
has_insecure_finding "$out" || fail "allowInsecure=1 should produce an allowInsecure lint finding"

# Case B — the insecure= alias → lint flags it too.
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config "$base&insecure=1" --only xray --json 2>/dev/null)
has_insecure_finding "$out" || fail "insecure=1 (alias) should produce an allowInsecure lint finding"

# Case C — neither param → no allowInsecure finding (no false positive).
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config "$base" --only xray --json 2>/dev/null)
has_insecure_finding "$out" && fail "no insecure param should NOT produce an allowInsecure finding"

echo "PASS: allowInsecure/insecure flagged by lint (both spellings), no false positive"
