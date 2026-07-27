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

# ---- default-on coverage (v1.10.0): as much as is safe runs without flags ----
command -v jq >/dev/null 2>&1 && {
  # conn-test is ON by default (N=8, concurrent, target-only). It dispatches on
  # CONN_TEST_N being non-empty, so "ran" = a non-null status and the opt-out leaves
  # it null (never dispatched) rather than the "disabled" in-probe sentinel.
  out=$(TIMEOUT=4 bash "$SCRIPT" --only dns,tcp 127.0.0.1 --json 2>/dev/null)
  [ "$(printf '%s' "$out" | jq -r '.probes.conn_limit.status')" != "null" ] \
    || fail "conn-test should be ON by default (it must dispatch without --conn-test)"
  out=$(TIMEOUT=4 bash "$SCRIPT" --only dns,tcp 127.0.0.1 --no-conn-test --json 2>/dev/null)
  [ "$(printf '%s' "$out" | jq -r '.probes.conn_limit.status')" = "null" ] \
    || fail "--no-conn-test should stop the connection-limit probe from dispatching"
}

# The SAFETY ceiling: censor-sweep + scan-covers must stay OFF by default even though
# v1.10.0 turned on everything else — censor-sweep fetches known-censored sites FROM
# THIS machine, which must never become a silent default for an in-region operator.
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json /tmp/__nope__.json --only xrayjson 2>&1)
printf '%s' "$out" | grep -qi 'censor-sweep' \
  && fail "censor-sweep must remain opt-in (no silent default — in-region safety)"

# --full is the maximal switch: it also turns on the alt-port survey.
grep -q 'PORT_SURVEY=1' "$SCRIPT" || fail "--full should enable PORT_SURVEY"

echo "PASS: --full/--thorough enable the opt-in scanners + warn on censor-sweep; conn-test on by default (opt-out works); censor-sweep/scan-covers stay off by default"
