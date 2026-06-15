#!/usr/bin/env bash
#
# tests/test_vision_flow.sh — regression guard for the vision-flow match. probe 26
# used to recognise vision by exact string (= "xtls-rprx-vision"), so the valid
# variant xtls-rprx-vision-udp443 (same TLS-in-TLS splicing, also passes UDP/443)
# read as "no vision" and was wrongly scored +15. The TLS-in-TLS field is computed
# from the flow param in the URL (no network), so this is deterministic. We assert
# tls_in_tls_protected across the vision family and the no-vision case.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }
PBK='0000000000000000000000000000000000000000000'   # 43-char placeholder
base="vless://00000000-0000-0000-0000-000000000001@192.0.2.10:443?security=reality&type=tcp&sni=www.microsoft.com&fp=chrome&sid=01&pbk=${PBK}"
tip() { printf '%s' "$1" | jq -r '.probes.xray_detectability.tls_in_tls_protected'; }

# vision variant -udp443 → protected (true), NOT a +15 exposure.
out=$(TIMEOUT=3 bash "$SCRIPT" --xray-config "${base}&flow=xtls-rprx-vision-udp443" --only xrayjson --json 2>/dev/null)
[ "$(tip "$out")" = "true" ] || fail "flow=xtls-rprx-vision-udp443 should be recognised as vision (tls_in_tls_protected=true)"

# bare vision → protected (true), unchanged.
out=$(TIMEOUT=3 bash "$SCRIPT" --xray-config "${base}&flow=xtls-rprx-vision" --only xrayjson --json 2>/dev/null)
[ "$(tip "$out")" = "true" ] || fail "flow=xtls-rprx-vision should be recognised as vision"

# no flow on REALITY+TCP → NOT protected (false) → the genuine +15 case still fires.
out=$(TIMEOUT=3 bash "$SCRIPT" --xray-config "$base" --only xrayjson --json 2>/dev/null)
[ "$(tip "$out")" = "false" ] || fail "REALITY+TCP with no vision flow should be tls_in_tls_protected=false"

echo "PASS: xtls-rprx-vision and xtls-rprx-vision-udp443 both recognised as vision; no-flow raw TCP stays exposed"
