#!/usr/bin/env bash
#
# tests/test_ip_route_vantage.sh — probe 2 must not overclaim censorship for an
# unreachable host on a CLEAN vantage. When TCP 80+443 both fail it now emits a
# vantage-neutral "Target host is unreachable …" verdict (not the old "IP route
# blocked entirely"), and the recommendation — cross-referencing the control
# sites (probe 8) — says the server is likely DOWN / "rotating your own IP won't
# help" on a clean vantage, instead of "rotate to a fresh IP".
#
# Target 192.0.2.1 is RFC 5737 TEST-NET-1 — guaranteed unreachable, so the
# failure path is deterministic. Needs network for the baseline + control sites;
# skips cleanly without it.

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }

# (A) Verdict, via JSON — new vantage-neutral wording, old overclaim gone.
out=$(TIMEOUT=2 bash "$SCRIPT" 192.0.2.1 --only dns,tcp,control --json 2>/dev/null)
printf '%s' "$out" | jq -e '(.verdicts // []) | map(select(test("Network connectivity broken"))) | length > 0' >/dev/null 2>&1 \
  && { echo "SKIP: no network (baseline unreachable)"; exit 0; }
printf '%s' "$out" | jq -e '(.verdicts // []) | map(select(test("Target host"))) | length > 0' >/dev/null \
  || fail "an unreachable host should yield a 'Target host …' verdict"
printf '%s' "$out" | jq -e '(.verdicts // []) | map(select(test("IP route blocked entirely"))) | length == 0' >/dev/null \
  || fail "the old overclaiming 'IP route blocked entirely' verdict must be gone"
# JSON carries the ICMP liveness too.
printf '%s' "$out" | jq -e '.probes.tcp | has("target_icmp_ok")' >/dev/null \
  || fail "probes.tcp.target_icmp_ok should be present"

# (B) Recommendation is vantage-aware — only assertable when THIS vantage is
#     clean (all control sites reachable). Otherwise the rec correctly differs.
out=$(TIMEOUT=2 bash "$SCRIPT" 192.0.2.1 --only dns,tcp,control 2>&1)
if printf '%s' "$out" | grep -q "all control domains reachable"; then
  printf '%s' "$out" | grep -qiE "most likely DOWN|won't help" \
    || fail "on a clean vantage, the rec should say the server is likely down (not 'rotate your IP')"
fi

echo "PASS: unreachable host → vantage-neutral verdict + vantage-aware rec, no censorship overclaim"
