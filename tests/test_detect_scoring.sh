#!/usr/bin/env bash
#
# tests/test_detect_scoring.sh — unit-tests the pure probe-26 active scorers
# (_score_cover_cert, _score_active) WITHOUT a live server. The bug these lock in:
# an UNREACHABLE cover used to fall through to "authentic, matches serverName"
# (+0) — a false-clean — and an "exposed" active-probe against an unreachable
# server was scored as a confirmed +25 tell rather than UNVERIFIED. We extract the
# functions and assert the "points|description" they emit.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

for fn in _score_cover_cert _score_active; do
  body=$(awk "/^${fn}\\(\\)/,/^}/" "$SCRIPT")
  [ -n "$body" ] || fail "could not extract $fn"
  eval "$body"
done

ck() { # expected  fn args...
  local want="$1"; shift
  local fnname="$1"; shift
  local got; got=$("$fnname" "$@")
  [ "$got" = "$want" ] || fail "$fnname($*) = '$got', expected '$want'"
}

# --- cover-cert ---
# THE bug: unreachable cover → UNVERIFIED +5, NOT authentic +0.
ck '5|UNVERIFIED (cover unreachable — cert not seen)' _score_cover_cert unreachable 0 1 1
# reachable, clean cert → authentic +0 (unchanged).
ck '0|authentic, matches serverName' _score_cover_cert ok 0 1 1
# self-signed → +40.
ck '40|self-signed' _score_cover_cert ok 1 1 1
# CA-invalid chain → +15.
ck '15|not CA-valid' _score_cover_cert ok 0 0 1
# CN mismatch alone → +10.
ck '10|CN≠serverName' _score_cover_cert ok 0 1 0
# self-signed AND CN mismatch → +50, combined desc.
ck '50|self-signed + CN≠serverName' _score_cover_cert ok 1 1 0

# --- active-probe ---
# THE bug: exposed + cover unreachable → UNVERIFIED +5 (blackhole, not a relay refusal).
ck "5|UNVERIFIED (server unreachable — cannot tell relay-refusal from blackhole)" _score_active exposed unreachable ""
# exposed + cover reachable → confirmed +25 tell (unchanged).
ck '25|no coherent HTTP to an unauth prober' _score_active exposed ok ""
# mismatch → +15.
ck '15|unauth response differs from cover' _score_active mismatch ok ""
# ok → +0.
ck '0|relays unauth probes to the real cover' _score_active ok ok ""
# no-baseline → UNVERIFIED +5 (default note).
ck '5|UNVERIFIED (no genuine cover to baseline)' _score_active no-baseline "" ""

echo "PASS: cover-cert unreachable scores UNVERIFIED (not authentic); active exposed-vs-unreachable scores UNVERIFIED (not +25); reachable cases unchanged"
