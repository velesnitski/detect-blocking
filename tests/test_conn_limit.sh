#!/usr/bin/env bash
#
# tests/test_conn_limit.sh — _classify_conn_limit maps a concurrency burst
# (succeeded/total + min/max handshake ms) to all-failed / capped / degraded /
# clean. We extract just that pure helper and check the boundaries.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
fn=$(awk '/^_classify_conn_limit\(\)/,/^}/' "$SCRIPT"); [ -n "$fn" ] || fail "could not extract _classify_conn_limit"
eval "$fn"

chk() { got=$(_classify_conn_limit "$1" "$2" "$3" "$4"); [ "$got" = "$5" ] || fail "$1/$2 min$3 max$4 → '$got' (want $5)"; }

chk 16 16 40 90   clean        # all completed, stable timing
chk 8  16 40 90   capped       # only half completed → cap/rate-limit
chk 0  16 0  0    all-failed   # nothing completed despite open TCP
chk 16 16 50 900  degraded     # all completed but slowest >=3x fastest and >=800ms
chk 16 16 300 800 clean        # spread under the degraded threshold
chk 15 16 10 20   capped       # one short → still a cap
chk 1  1  120 120 clean        # single connection, fine

echo "PASS: _classify_conn_limit classifies all-failed / capped / degraded / clean at the boundaries"
