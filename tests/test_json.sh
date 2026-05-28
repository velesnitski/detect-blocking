#!/usr/bin/env bash
#
# tests/test_json.sh — verify --json output:
#  - parses as valid JSON
#  - contains expected schema (target.host, probes.dns, verdicts, ...)
#  - suppresses human-readable stdout

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null || { echo "SKIP: jq not installed"; exit 0; }

out=$(VPN_HOST=www.example.com TIMEOUT=3 \
      bash "$SCRIPT" --json --only dns,tcp 2>&1)

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "$out" >&2; exit 1; }

# 1. Parses as JSON
printf '%s' "$out" | jq -e . >/dev/null \
  || fail "output is not valid JSON"

# 2. No human-readable lines leaked
printf '%s' "$out" | grep -qE '^==|^\[OK\]|^\[FAIL\]|^\[WARN\]' \
  && fail "human-readable lines leaked into --json output"

# 3. Schema sanity
printf '%s' "$out" | jq -e '.schema_version == 1' >/dev/null \
  || fail "missing or wrong schema_version"
printf '%s' "$out" | jq -e '.version' >/dev/null \
  || fail "missing version"
printf '%s' "$out" | jq -e '.target.host == "www.example.com"' >/dev/null \
  || fail "target.host mismatch"
printf '%s' "$out" | jq -e '.target.port_tcp == 443' >/dev/null \
  || fail "target.port_tcp mismatch"
printf '%s' "$out" | jq -e '.probes.dns.doh_integrity.state == "ok"' >/dev/null \
  || fail "doh_integrity.state expected 'ok' for normal run"
printf '%s' "$out" | jq -e '.verdicts | type == "array"' >/dev/null \
  || fail "verdicts must be array"
printf '%s' "$out" | jq -e '.timestamp | test("^[0-9]{4}-[0-9]{2}-[0-9]{2}T")' >/dev/null \
  || fail "timestamp not ISO-8601"

echo "PASS: --json output is valid + schema sane"
