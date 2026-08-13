#!/usr/bin/env bash
#
# tests/test_unmeasured_claims.sh — two guards against the recurring failure mode in
# this codebase: reporting a conclusion that was never actually measured.
#
# Both were found on a real in-region run whose output contradicted itself.
#
# (a) The YouTube "egress is blocked by Google" verdict may only be raised when probe 12
#     PROVED the tunnel carries traffic. When probe 12 also failed, "YouTube unreachable"
#     merely restates "the tunnel is dead" — the same report claimed both, sending the
#     operator to audit a perfectly healthy egress.
# (b) HTTP/3 parity may only read "ok" when BOTH sides were measured. A Reality/TCP
#     config never gets its target QUIC-probed, and that was being recorded as "ok" —
#     asserting a parity nobody observed.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

# ---- (a) the egress verdict must be gated on a working tunnel ----
blk=$(awk '/all-failed\)/,/;;$/' "$SCRIPT" | sed -n '/YouTube/,/;;/p')
[ -n "$blk" ] || fail "could not locate the YouTube all-failed branch"
printf '%s' "$blk" | grep -q 'XRAY_JSON_STATUS:-}" = "ok"' \
  || fail "the YouTube egress verdict must be gated on probe 12 having passed"
# the verdict itself must sit INSIDE the gate, not before it
gate_line=$(printf '%s' "$blk" | grep -n 'XRAY_JSON_STATUS:-}" = "ok"' | head -1 | cut -d: -f1)
verd_line=$(printf '%s' "$blk" | grep -n 'add_verdict yt-egress-blocked' | head -1 | cut -d: -f1)
[ -n "$verd_line" ] || fail "the egress verdict should carry the code yt-egress-blocked"
[ "$verd_line" -gt "$gate_line" ] \
  || fail "the egress verdict must be raised INSIDE the working-tunnel gate"

# ---- (b) h3 parity truth table (mirrors the implementation) ----
h3() {
  local c="$1" t="$2"
  if [ "$c" != "vn" ] || [ -z "$t" ]; then printf 'n/a'
  elif [ "$t" = "vn" ]; then printf 'ok'
  elif [ "$c" = "vn" ] && [ -n "$t" ] && [ "$t" != "vn" ]; then printf 'cover-only'
  else printf 'n/a'; fi
}
[ "$(h3 vn '')"       = "n/a" ]        || fail "target never QUIC-probed must be n/a, NOT ok"
[ "$(h3 vn vn)"       = "ok" ]         || fail "both sides serve h3 -> ok"
[ "$(h3 vn silent)"   = "cover-only" ] || fail "cover serves h3, target does not -> cover-only"
[ "$(h3 silent vn)"   = "n/a" ]        || fail "cover has no h3 -> nothing to compare -> n/a"
# and the script must order the checks so "ok" cannot be reached with an unmeasured target
impl=$(awk '/Order matters: "ok" may only be claimed/,/^  fi$/' "$SCRIPT")
[ -n "$impl" ] || fail "could not locate the h3-parity block"
printf '%s' "$impl" | grep -q 'UDP_QUIC_TARGET:-}" \]; then' \
  || fail "h3 parity must test for an unmeasured target BEFORE it can return ok"

echo "PASS: unmeasured claims — YouTube egress verdict gated on a proven-working tunnel; h3 parity reports ok only when both sides were measured"
