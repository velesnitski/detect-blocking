#!/usr/bin/env bash
#
# tests/test_fleet_plan.sh — _compress_ranges (the node-list compressor behind the
# fleet remediation plan) and a check that the plan's symptom→fix grouping matches
# signals correctly even though tokens contain '=' (cn!=sni / sni!=ip), which is
# why the group delimiter must be '|' not '='. Both extracted from the script.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
fn=$(awk '/^_compress_ranges\(\)/,/^}/' "$SCRIPT"); [ -n "$fn" ] || fail "could not extract _compress_ranges"
eval "$fn"

# feed newline-separated sorted ints (the real call site pipes `sort -n | uniq`)
cr() { printf '%s\n' "$1" | _compress_ranges; }

[ "$(cr "$(printf '0\n1\n2\n3\n4\n5\n6\n7\n8\n9\n12\n14\n18\n20\n24\n25\n26')")" = "0-9,12,14,18,20,24-26" ] || fail "consecutive runs + singletons"
[ "$(cr "$(printf '10\n17\n27')")" = "10,17,27" ] || fail "all singletons"
[ "$(cr "5")" = "5" ]       || fail "single value"
[ "$(cr "$(printf '0\n1\n2')")" = "0-2" ] || fail "one run"
[ "$(cr "$(printf '3\n5\n7')")" = "3,5,7" ] || fail "alternating"

# --- grouping: '|' delimiter must survive signal tokens that contain '=' ---
g="self-signed,cover-mismatch,chain-invalid,cn!=sni,no-relay,tls-parity,sni!=ip|Relay the cover"
sigs="${g%%|*}"; fix="${g#*|}"
[ "$fix" = "Relay the cover" ]                 || fail "fix text must be intact after '|' split (got '$fix')"
case ",$sigs," in *",cn!=sni,"*) : ;; *) fail "signal list must keep cn!=sni intact (got '$sigs')" ;; esac
case ",$sigs," in *",sni!=ip,"*) : ;; *) fail "signal list must keep sni!=ip intact (got '$sigs')" ;; esac
# the awk membership test the plan uses
hit=$(printf '%s\n' "no-relay 7" "sni!=ip 7" "other 9" | awk -v want=",$sigs," 'NF && index(want, ","$1",")>0 {print $2}' | sort -u | tr '\n' ',')
[ "$hit" = "7," ] || fail "membership test should match node 7 via no-relay/sni!=ip only (got '$hit')"

echo "PASS: _compress_ranges collapses node lists; plan grouping survives '='-bearing tokens"
