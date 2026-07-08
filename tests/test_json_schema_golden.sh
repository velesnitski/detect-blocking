#!/usr/bin/env bash
#
# tests/test_json_schema_golden.sh — the --json shape is a frozen 1.0 contract
# (schema_version:1). This snapshots every key PATH the emitter produces for a
# representative config and asserts none of them disappear. Removing/renaming a
# key is a breaking change (→ 2.0 + a schema_version bump); ADDING keys is fine
# (the 1.x additive rule), so new paths are reported, not failed. This is also the
# safety net for refactoring _emit_json: the output shape must stay identical.
#
# To intentionally update the contract after an additive change, regenerate:
#   bash tests/test_json_schema_golden.sh --update
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
GOLDEN="$SCRIPT_DIR/tests/fixtures/json_schema.golden"
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

# A reality config over a dead loopback: hermetic, and exercises the lint / cover /
# active-probe / tls-parity / detectability / sni-privacy / host-exposure blocks.
URL='vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?security=reality&pbk=AAAA&sid=01&sni=www.example.com&fp=chrome&type=tcp&flow=xtls-rprx-vision'
schema() {
  TIMEOUT=2 bash "$SCRIPT" --xray-config "$URL" --xray-only --json 2>/dev/null \
    | jq -r '[paths | map(if type=="number" then "[]" else . end) | join(".")] | unique | .[]'
}

if [ "${1:-}" = "--update" ]; then
  schema > "$GOLDEN" && echo "updated $GOLDEN ($(wc -l < "$GOLDEN" | tr -d ' ') paths)"; exit 0
fi

[ -s "$GOLDEN" ] || fail "golden schema missing: $GOLDEN (run with --update)"

cur=$(schema)
[ -n "$cur" ] || fail "emitter produced no JSON paths (is the run broken?)"

# contract keys that vanished = breaking change
missing=$(comm -23 <(sort -u "$GOLDEN") <(printf '%s\n' "$cur" | sort -u))
[ -z "$missing" ] || fail "JSON contract keys disappeared (breaking — bump schema_version):
$missing"

# additive new keys: fine, just report
added=$(comm -13 <(sort -u "$GOLDEN") <(printf '%s\n' "$cur" | sort -u))
[ -n "$added" ] && printf 'note: new (additive) JSON keys since the golden:\n%s\n' "$added"

echo "PASS: all $(wc -l < "$GOLDEN" | tr -d ' ') contract JSON paths still present (schema_version:1 intact)"
