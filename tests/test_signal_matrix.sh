#!/usr/bin/env bash
#
# tests/test_signal_matrix.sh — _signal_matrix turns "<signal> <idx>" pairs into the
# fleet's profile×signal grid (HDR codes / ROW per signal-set / TOT per-signal totals
# / LEG). We extract just that helper and feed two synthetic nodes with different
# signal sets, asserting the columns, grouping, per-signal totals, and legend.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }
fn=$(awk '/^_signal_matrix\(\)/,/^}/' "$SCRIPT"); [ -n "$fn" ] || fail "could not extract _signal_matrix"
eval "$fn"

# node 0 = {self-signed, chain-invalid, exposed}; node 1 = {self-signed, non443, exposed}
out=$(printf '%s\n' \
  "self-signed 0" "chain-invalid 0" "exposed 0" \
  "self-signed 1" "non443 1" "exposed 1" | _signal_matrix)

hdr=$(printf '%s\n' "$out" | awk -F'\t' '$1=="HDR"{print $2}')
# canonical column order → SS (self-signed) CI (chain-invalid) NP (non443) EX (exposed)
case "$hdr" in *SS*CI*NP*EX*) : ;; *) fail "HDR missing expected codes (got '$hdr')" ;; esac

rows=$(printf '%s\n' "$out" | grep -c '^ROW')
[ "$rows" = 2 ] || fail "two distinct signal-sets should yield 2 ROWs (got $rows)"

# each node is its own group of size 1
printf '%s\n' "$out" | awk -F'\t' '$1=="ROW"{print $2}' | grep -qx '1' || fail "ROW group counts should be 1"

tot=$(printf '%s\n' "$out" | awk -F'\t' '$1=="TOT"{print $2}')
# SS is the first column and both nodes have it → total starts with "2"
case "$tot" in "2 "*) : ;; *) fail "self-signed total should be 2 (got '$tot')" ;; esac

leg=$(printf '%s\n' "$out" | awk -F'\t' '$1=="LEG"{print $2}')
case "$leg" in *"SS=self-signed"*) : ;; *) fail "legend should map SS=self-signed (got '$leg')" ;; esac
case "$leg" in *"NP=non443"*) : ;; *) fail "legend should map NP=non443 (got '$leg')" ;; esac

# a signal NOT present must not appear as a column
case "$hdr" in *VO*) fail "vision-off (VO) absent from input must not be a column" ;; *) : ;; esac

echo "PASS: _signal_matrix builds aligned columns, groups by signal-set, totals per signal, and legends codes"
