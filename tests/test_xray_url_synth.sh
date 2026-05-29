#!/usr/bin/env bash
#
# tests/test_xray_url_synth.sh — verify that probe 12 can synthesize a
# minimal xray-core config from a --xray-config share-link URL (so probes
# 12/13 run without a hand-written --xray-config-json FILE), and that the
# JSON schema exposes the new failure-classification / retry / from-url keys.
#
# Points the endpoint at 127.0.0.1:1 — nothing listens there, so if
# xray-core IS installed it gets an instant connection-refused (reset class,
# no retry, no network, no real infrastructure touched) and the probe
# finishes fast and deterministically. If xray-core is absent (typical CI),
# synthesis still runs before the binary check, so synthesized_from_url is
# true either way.

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "$out" >&2; exit 1; }

URL='vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?type=tcp&security=reality&pbk=TESTPUBKEYxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx&sid=0123abcd&fp=chrome&sni=www.example.com&flow=xtls-rprx-vision#synth-test'

out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config "$URL" --only xrayjson --json 2>/dev/null)

# 1) Synthesis must have happened regardless of xray-core presence.
synth=$(printf '%s' "$out" | jq -r '.probes.xray_full_config.synthesized_from_url')
[ "$synth" = "true" ] \
  || fail "expected synthesized_from_url=true for --xray-config URL, got '$synth'"

# 2) config_path must be suppressed (it would otherwise leak a temp path).
cpath=$(printf '%s' "$out" | jq -r '.probes.xray_full_config.config_path')
[ "$cpath" = "null" ] \
  || fail "expected config_path=null when synthesized from URL, got '$cpath'"

# 3) New schema keys must exist on the full-config block.
printf '%s' "$out" | jq -e '
  .probes.xray_full_config
  | has("failure_kind") and has("slow_handshake_retry") and has("synthesized_from_url")
' >/dev/null \
  || fail "xray_full_config missing failure_kind / slow_handshake_retry / synthesized_from_url"

# 4) New schema keys must exist on the protocol (probe 11) block.
printf '%s' "$out" | jq -e '
  .probes.xray_protocol | has("failure_kind") and has("slow_handshake_retry")
' >/dev/null \
  || fail "xray_protocol missing failure_kind / slow_handshake_retry"

# 5) Status must be a sane enum value (xray-missing in CI; or a real outcome
#    if xray-core happens to be installed on the dev box).
status=$(printf '%s' "$out" | jq -r '.probes.xray_full_config.status')
case "$status" in
  ok|failed|xray-missing|jq-missing|config-malformed|no-port|xray-bind-failed) : ;;
  *) fail "unexpected xray_full_config.status: '$status'" ;;
esac

# 6) No synthesized temp config may survive the run.
tmpdir=$(dirname "$(mktemp -u 2>/dev/null || echo /tmp/x)")
leaked=$(ls "$tmpdir"/detect_blocking.synthcfg* 2>/dev/null | wc -l | tr -d ' ')
[ "$leaked" = "0" ] \
  || fail "synthesized config tempfile leaked in $tmpdir ($leaked file(s))"

echo "PASS: --xray-config URL synthesizes a probe-12 config + schema/cleanup intact"
