#!/usr/bin/env bash
#
# tests/test_stability_classifier.sh — unit-tests the pure probe-17 kill-ladder
# classifier (_classify_stability_ladder) WITHOUT a live tunnel. We extract the
# function from the script and eval it, then assert the class for representative
# pulse tallies — crucially the dogfood case (1MB reset, 4MB then passed) must be
# 'transient', not the old false 'volumetric kill-shaping'.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

# Pull the pure function out of the single-file script and define it here.
fn=$(awk '/^_classify_stability_ladder\(\)/,/^}/' "$SCRIPT")
[ -n "$fn" ] || fail "could not extract _classify_stability_ladder from the script"
eval "$fn"

check() { # expected  total okc killc kill_bytes max_ok_bytes
  local want="$1"; shift
  local got; got=$(_classify_stability_ladder "$@")
  [ "$got" = "$want" ] || fail "classify($*) = '$got', expected '$want'"
}

# args: total okc killc kill_bytes max_ok_bytes
check none       0 0 0 ""      ""              # nothing ran
check ok         4 4 0 ""      ""              # every pulse passed
check slow       4 2 0 ""      262144          # some timed out, no resets
# THE dogfood regression: 1MB reset but 4MB then succeeded → non-monotonic.
check transient  4 3 1 1048576 4194304
# Monotonic: tiny+256KB passed, 1MB+4MB reset, nothing larger survived.
check volumetric 4 2 2 1048576 262144
# Only the tiniest pulse passed, larger reset → still volumetric (maxok < kb).
check volumetric 3 1 2 1048576 0
# The reset was the tiniest pulse (kb=0) → generic mid-session reset.
check reset      3 2 1 0       4194304
# Nothing passed at all → generic reset (not a clean byte threshold).
check reset      2 0 2 262144  ""
# Boundary: a pulse exactly at the kill size "passed" → not strictly larger → volumetric.
check volumetric 4 2 2 1048576 1048576

echo "PASS: _classify_stability_ladder maps transient/volumetric/reset/ok/slow/none correctly"
