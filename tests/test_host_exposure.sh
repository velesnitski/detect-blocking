#!/usr/bin/env bash
#
# tests/test_host_exposure.sh — whole-host disguise probe. With a config it
# checks the server for giveaway ports (SSH / proxy panels) beyond 443; a host
# impersonating a CDN cover should answer only 443. We point at 127.0.0.1 (a
# reality URL) so the checks are local + fast (closed ports → refused); we assert
# status + schema, NOT the open list (machine-dependent). Without a config it skips.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }
command -v nc >/dev/null 2>&1 || { echo "SKIP: nc not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }
hx() { printf '%s' "$1" | jq -c '.probes.host_exposure'; }

# With a config → runs against the server (127.0.0.1 here); status ok, schema present.
URL='vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?security=reality&pbk=AAAA&sid=01&sni=www.example.com&fp=chrome&type=tcp'
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config "$URL" --only xray --json 2>/dev/null)
[ "$(hx "$out" | jq -r '.status')" = "ok" ] || fail "host_exposure should run (status ok) when a config is given"
printf '%s' "$(hx "$out")" | jq -e 'has("status") and has("open_ports") and (.open_ports | type == "array")' >/dev/null \
  || fail "host_exposure schema missing status/open_ports"

# Without a config → does not run → status null.
out=$(TIMEOUT=2 bash "$SCRIPT" --only env --json 2>/dev/null)
[ "$(hx "$out" | jq -r '.status')" = "null" ] \
  || fail "host_exposure should be null without a config"

echo "PASS: host_exposure runs with a config (schema intact), skips without one"
