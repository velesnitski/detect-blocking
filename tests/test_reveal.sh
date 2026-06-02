#!/usr/bin/env bash
#
# tests/test_reveal.sh — the --reveal escape hatch. It prints the real offending
# values (here the cover serverName) to the TERMINAL so an operator knows what
# to change, but must NEVER leak them into --json or appear without the flag.
# Three invariants:
#   A. with --reveal (human output): the serverName is shown;
#   B. without --reveal: it is NOT shown (default output stays share-safe);
#   C. with --reveal --json: it is NOT in the JSON, and the JSON stays valid
#      (reveal is suppressed under --quiet/--json, never persisted).
# A reality config on 127.0.0.1:1 (instant refuse) drives probe 26 with an
# NXDOMAIN (.invalid) serverName, which triggers the SNI-quality reveal.

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }

marker="reveal-marker-zq7x.invalid"
base="vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=01&fp=chrome&type=tcp&sni=$marker"

# A — with --reveal the serverName must appear (terminal/human output).
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config "$base" --only xrayjson --reveal 2>&1)
printf '%s' "$out" | grep -q "$marker" || fail "--reveal should print the real serverName"

# B — without --reveal the serverName must NOT appear anywhere.
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config "$base" --only xrayjson 2>&1)
printf '%s' "$out" | grep -q "$marker" && fail "serverName leaked without --reveal (default must be share-safe)"

# C — with --reveal --json the serverName must NOT be in the JSON, and JSON valid.
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config "$base" --only xrayjson --reveal --json 2>/dev/null)
printf '%s' "$out" | jq -e . >/dev/null 2>&1 || fail "--reveal --json must still emit valid JSON"
printf '%s' "$out" | grep -q "$marker" && fail "serverName leaked into --json (reveal must be terminal-only)"

echo "PASS: --reveal shows the value in the terminal only; never in --json, never by default"
