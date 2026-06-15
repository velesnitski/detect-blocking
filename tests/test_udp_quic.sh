#!/usr/bin/env bash
#
# tests/test_udp_quic.sh — QUIC / UDP-443 reachability probe (probe 6). The
# verdict logic is a pure function (_classify_udp_quic) we extract and assert
# offline; then a wiring check that the JSON exposes a valid verdict. The live VN
# probe itself (perl UDP) is network/perl-dependent, so we don't assert its value
# — only that the classification + schema are sound.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }

body=$(awk '/^_classify_udp_quic\(\)/,/^}/' "$SCRIPT")
[ -n "$body" ] || fail "could not extract _classify_udp_quic"
eval "$body"

ck() { local want="$1"; shift; local got; got=$(_classify_udp_quic "$@"); [ "$got" = "$want" ] || fail "_classify_udp_quic($*) = '$got', expected '$want'"; }

# baseline target → verdict
ck net-ok               vn ""          # UDP/443 usable, no server UDP target
ck target-quic          vn vn          # baseline + target both QUIC (Hysteria2 up)
ck net-ok-target-silent vn silent      # UDP/443 ok, target doesn't answer (obfs/TCP)
ck net-ok-target-silent vn response    # ditto (a non-VN reply isn't a QUIC server)
ck net-blocked          silent ""      # baseline silent → UDP/443 blocked in this network
ck net-blocked          silent vn      # baseline blocked dominates even if target replied
ck net-blocked          error ""       # socket error → treat as blocked/inconclusive
ck net-blocked          no-perl ""     # no perl → can't confirm → not "ok"
ck net-blocked          response ""    # baseline must be a clean VN; a non-VN reply isn't "usable"

# --- wiring: probe 6 emits a valid quic_verdict + baseline in JSON ---
if command -v jq >/dev/null 2>&1; then
  out=$(TIMEOUT=3 bash "$SCRIPT" --only udp --json www.example.com 2>/dev/null)
  printf '%s' "$out" | jq -e '.probes.udp | has("quic_verdict") and has("quic_baseline")' >/dev/null \
    || fail "udp JSON should expose quic_verdict + quic_baseline"
  v=$(printf '%s' "$out" | jq -r '.probes.udp.quic_verdict')
  case "$v" in net-blocked|net-ok|target-quic|net-ok-target-silent|null) : ;; *) fail "unexpected quic_verdict: $v" ;; esac
fi

echo "PASS: _classify_udp_quic maps net-blocked/net-ok/target-quic/net-ok-target-silent; JSON wiring intact"
