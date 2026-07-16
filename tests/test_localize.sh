#!/usr/bin/env bash
#
# tests/test_localize.sh — censorship localization probe ("where does the block sit?").
# Unit-tests the pure last-hop classifier, checks the additive JSON block defaults, and
# (when traceroute is present) an offline loopback trace that reaches the target →
# class=endpoint. No real infra: loopback + placeholder inputs only.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

# ---- unit: the pure classifier (reached, reachable, last_hop, max_hops, last_cc, target_cc) ----
eval "$(awk '/^_localize_class\(\)/,/^}/' "$SCRIPT")"
[ "$(_localize_class 1 0 20 20 US US)" = "endpoint" ]         || fail "reached target → endpoint"
[ "$(_localize_class 0 0 2  20 ''  '')" = "access-edge" ]      || fail "genuinely dies within 3 hops → access-edge"
[ "$(_localize_class 0 0 14 20 DE DE)" = "near-destination" ] || fail "genuinely dies in target's country → near-destination"
[ "$(_localize_class 0 0 8  20 NL DE)" = "transit" ]          || fail "genuinely dies mid-path elsewhere → transit"
[ "$(_localize_class 0 0 0  20 ''  '')" = "unknown" ]         || fail "no hops → unknown"
[ "$(_localize_class 0 0 '' 20 ''  '')" = "unknown" ]         || fail "empty hop → unknown"
# the false-positive guards (the www.cloudflare.com --localize case):
[ "$(_localize_class 0 1 7  20 DE US)" = "incomplete" ]      || fail "target REACHABLE but trace didn't finish → incomplete, NOT transit"
[ "$(_localize_class 0 0 7  7  DE US)" = "incomplete" ]      || fail "trace hit the hop budget (last_hop>=max) → incomplete, NOT transit"
[ "$(_localize_class 0 1 7  7  DE US)" = "incomplete" ]      || fail "reachable + hop budget → incomplete"

# ---- additive JSON block: present with null defaults when the probe isn't selected ----
out=$(TIMEOUT=3 bash "$SCRIPT" --only dns,tcp 127.0.0.1 --json 2>/dev/null)
[ "$(printf '%s' "$out" | jq -r '.probes.localize.status')" = "null" ]              || fail "not selected → status null"
[ "$(printf '%s' "$out" | jq -r '.probes.localize.reached_destination')" = "null" ] || fail "not selected → reached_destination null"
printf '%s' "$out" | jq -e '.probes.localize | has("class") and has("last_hop") and has("last_hop_asn")' >/dev/null \
  || fail "localize block should expose class/last_hop/last_hop_asn"

# ---- offline integration: forced trace to loopback reaches hop 1 → endpoint ----
if command -v traceroute >/dev/null 2>&1; then
  out=$(TIMEOUT=6 bash "$SCRIPT" --only dns,tcp,localize 127.0.0.1 --localize --json 2>/dev/null)
  [ "$(printf '%s' "$out" | jq -r '.probes.localize.status')" = "ran" ]               || fail "loopback --localize → status ran"
  [ "$(printf '%s' "$out" | jq -r '.probes.localize.class')" = "endpoint" ]           || fail "loopback reaches → class endpoint"
  [ "$(printf '%s' "$out" | jq -r '.probes.localize.reached_destination')" = "true" ] || fail "loopback → reached_destination true"
else
  echo "  (traceroute not installed — skipped the loopback integration leg)"
fi

echo "PASS: localization — classifier (endpoint/access-edge/near-destination/transit/unknown) + additive JSON + loopback endpoint trace"
