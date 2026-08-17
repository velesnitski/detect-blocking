#!/usr/bin/env bash
#
# scripts/mutation-test.sh — does the suite actually CATCH the bugs it claims to guard?
#
# Every defect found in this tool by real-world use has had the same shape: a default or
# fallback value standing in for a measurement that never happened ("not measured" read
# as "measured bad"; a failed lookup read as a finding). Each fix installed an invariant
# and a test. This harness verifies those tests are load-bearing rather than decorative:
# it re-introduces each historical bug as a MUTANT, runs the test that is supposed to
# object, and requires that the test FAILS.
#
#   killed   = the mutant was rejected → that test genuinely guards the invariant
#   SURVIVED = the mutant passed unnoticed → a real coverage gap, the point of this run
#
# A mutant whose text no longer matches the source is reported as STALE, never silently
# skipped — otherwise the harness rots into false confidence as the code moves.
#
# Not part of tests/run.sh: it rewrites detect_blocking.sh in place (restored via a trap
# on every exit path, interrupts included) and is meant to be run deliberately.
#
#   bash scripts/mutation-test.sh            # all mutants
#   bash scripts/mutation-test.sh localize   # only mutants whose name matches
set -u

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/detect_blocking.sh"
BACKUP="$(mktemp -t detect_blocking.mutbak.XXXXXX)"
FILTER="${1:-}"

cp "$SCRIPT" "$BACKUP"
restore() { cp "$BACKUP" "$SCRIPT"; }
cleanup() { restore; rm -f "$BACKUP"; }
trap cleanup EXIT INT TERM

# name :: test file :: original text :: mutated text
# The original text is asserted present before mutating, so a moved line reports STALE.
# A literal \n inside a field means a real newline (multi-line mutants).
read -r -d '' MUTANTS <<'LIST' || true
localize-tristate::test_localize.sh::  if [ "$reachable" != "0" ]; then echo "incomplete"; return 0; fi::  if [ "$reachable" = "1" ]; then echo "incomplete"; return 0; fi
tls-field-unmeasured::test_tls_parity_fields.sh::  { [ -n "$a" ] && [ -n "$b" ]; } || { printf '%s' ""; return 0; }::  { [ -n "$a" ] && [ -n "$b" ]; } || { printf '0'; return 0; }
cdn-unknown-as-not-cdn::test_cdn_detection.sh::  [ -n "$ip" ] || return 2::  [ -n "$ip" ] || return 1
suppressor-keys-on-prose::test_verdict_codes.sh::      transport-silent-drop)::      *"Silent packet drop (firewall blackhole"*)
sni-keyword-hyphen-only::test_sni_keyword.sh::    rkn|rkn.*|*.rkn|*.rkn.*|*-rkn|*-rkn.*|*rkn-*) printf '1'; return 0 ;;::    *-rkn*|*rkn-*) printf '1'; return 0 ;;
h3-parity-false-ok::test_unmeasured_claims.sh::    if [ "$XRAY_TLSPAR_COVER_H3" != "vn" ] || [ -z "${UDP_QUIC_TARGET:-}" ]; then::    if [ "$XRAY_TLSPAR_COVER_H3" != "vn" ]; then
normalize-drops-host-guard::test_target_normalize.sh::    ''|*[!A-Za-z0-9._:-]*) printf '%s\t' "${1-}"; return 0 ;;::    '')  printf '%s\t' "${1-}"; return 0 ;;
whitelist-quadrant-collapse::test_whitelist.sh::    echo "permitted-unreachable"; return 0::    echo "open"; return 0
ovpn-posture-order::test_openvpn_posture.sh::  if [ "$obfs" = "1" ];      then echo "wrapped";         return 0; fi::  if [ "$obfs" = "9" ];      then echo "wrapped";         return 0; fi
dns-block-never-detected::test_dns_block.sh::  if [ "$sys_tls" = "0" ] && [ "$doh_tls" = "1" ]; then echo "dns-block"; return 0; fi::  if [ "$sys_tls" = "9" ] && [ "$doh_tls" = "1" ]; then echo "dns-block"; return 0; fi
value-gate-canary::test_json_values_golden.sh::      schema_version: 1,::      schema_version: 1,\n      _mutant_canary: "x",
LIST

killed=0; survived=0; stale=0
printf '%-30s %-30s %s\n' MUTANT TEST RESULT
printf '%-30s %-30s %s\n' '------------------------------' '------------------------------' '------'

while IFS= read -r line; do
  [ -n "$line" ] || continue
  name=${line%%::*};       rest=${line#*::}
  test_file=${rest%%::*};  rest=${rest#*::}
  orig=${rest%%::*};       mutated=${rest#*::}
  case "$name" in *"$FILTER"*) ;; *) continue ;; esac

  # Apply the mutant. Exit 3 means the original text is gone → STALE, not skipped.
  if ! ORIG="$orig" MUT="$mutated" python3 - "$SCRIPT" <<'PY'
import os, sys
p = sys.argv[1]
orig = os.environ["ORIG"].replace("\\n", "\n")
mut  = os.environ["MUT"].replace("\\n", "\n")
s = open(p).read()
if orig not in s:
    sys.exit(3)
open(p, "w").write(s.replace(orig, mut, 1))
PY
  then
    printf '%-30s %-30s %s\n' "$name" "$test_file" "STALE (source moved — update the mutant)"
    stale=$((stale + 1)); restore; continue
  fi

  # The mapped test MUST reject the mutant.
  if bash "$ROOT/tests/$test_file" >/dev/null 2>&1; then
    printf '%-30s %-30s %s\n' "$name" "$test_file" "*** SURVIVED — coverage gap ***"
    survived=$((survived + 1))
  else
    printf '%-30s %-30s %s\n' "$name" "$test_file" "killed"
    killed=$((killed + 1))
  fi
  restore
done <<< "$MUTANTS"

printf '\n%s killed · %s survived · %s stale\n' "$killed" "$survived" "$stale"
# A surviving or stale mutant means the suite is not guarding what it claims to.
[ "$survived" -eq 0 ] && [ "$stale" -eq 0 ]
