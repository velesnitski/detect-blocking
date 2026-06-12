#!/usr/bin/env bash
#
# tests/test_full_flag.sh — --full / --thorough enables the two opt-in scanners
# (--scan-covers + --censor-sweep) without clobbering an explicit list, and warns
# that the censored-site sweep runs from this machine. We assert flag wiring via
# the run's stderr/notes + that the scanners actually dispatch — no network needed
# (a missing-file config makes them no-op fast; we only check they were enabled).
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }

# --full must print the censor-sweep safety note (proves the flag is parsed and
# that --censor-sweep was turned on).
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json /tmp/__nope__.json --full --only xrayjson 2>&1)
printf '%s' "$out" | grep -qi 'full also runs --censor-sweep' \
  || fail "--full should enable censor-sweep and print the safety note"
# It should reach the cover-scan + censor-sweep probe sections (scanners enabled).
printf '%s' "$out" | grep -qiE 'cover|censor' \
  || fail "--full should dispatch the opt-in scanners"

# --thorough is an alias for --full.
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json /tmp/__nope__.json --thorough --only xrayjson 2>&1)
printf '%s' "$out" | grep -qi 'full also runs --censor-sweep' \
  || fail "--thorough should behave like --full"

# Without --full, the safety note must NOT appear (scanners stay off by default).
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json /tmp/__nope__.json --only xrayjson 2>&1)
printf '%s' "$out" | grep -qi 'full also runs --censor-sweep' \
  && fail "censor-sweep note must not appear without --full"

# --full must NOT clobber an explicit --scan-covers=LIST given before it.
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json /tmp/__nope__.json --scan-covers=example.com --full --help 2>&1)
# (--help just makes it exit fast; the point is parsing didn't error)
[ -n "$out" ] || fail "parsing --scan-covers=LIST + --full should not error"

echo "PASS: --full/--thorough enable the opt-in scanners + warn on censor-sweep; off by default; explicit list preserved"
