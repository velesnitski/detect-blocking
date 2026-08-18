#!/usr/bin/env bash
#
# tests/test_json_values_golden.sh — full-output contract gate.
#
# test_json_schema_golden.sh compares KEY PATHS only, so it cannot see a value landing
# in the wrong key, a positional field decoded in the wrong order, or a share-safety
# leak into a field that used to hold a boolean. This test compares the WHOLE emitted
# JSON — every value — against a stored blob.
#
# It is the safety net for refactors of `_emit_json` (a ~590-line function whose ~250
# `--arg` bindings sit hundreds of lines away from the object literal that consumes
# them, so a mis-wired field is easy to introduce and invisible to a path-only check).
#
# Key ORDER is normalised (`jq -S`) on purpose: order is semantically meaningless in
# JSON, and normalising keeps the blob stable while still catching every case that
# matters — wrong value, wrong key, dropped field, changed type.
#
# Masked fields fall into two groups, and nothing else may be added without a reason:
#   VOLATILE  — .timestamp, .version (changes each release), the random SOCKS port.
#   HOST/TOOLCHAIN — values that describe the machine rather than the emitter: the
#     ports 127.0.0.1 happens to listen on (CI runners run sshd, laptops usually do
#     not), and which optional tester binary is installed (xray-knife vs xray, which
#     also determines probe 11 status/failure_kind). Recording these made the gate
#     pass locally and fail on CI for three releases.
# If a future field is genuinely non-deterministic, mask it here — never by loosening
# the comparison itself.
#
#   bash tests/test_json_values_golden.sh            # verify
#   bash tests/test_json_values_golden.sh --update   # accept an intended change
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
GOLDEN="$SCRIPT_DIR/tests/fixtures/json_values.golden"
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

# Same hermetic fixture as the schema gate: a reality config over a dead loopback port.
# Exercises lint / cover / active-probe / tls-parity / detectability / sni-privacy /
# host-exposure without touching the network.
URL='vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?security=reality&pbk=AAAA&sid=01&sni=www.example.com&fp=chrome&type=tcp&flow=xtls-rprx-vision'

canon() {
  TIMEOUT=2 bash "$SCRIPT" --xray-config "$URL" --xray-only --json 2>/dev/null \
    | jq -S '
        .timestamp = "<masked>"
      | .version   = "<masked>"
      | (if (.probes.xray_full_config? // empty) | type == "object"
           then .probes.xray_full_config.socks_port_used = "<masked>" else . end)
      # --- fields that describe the HOST the test runs on, not the emitter ---
      # The fixture points at 127.0.0.1, so host-exposure reports whatever this machine
      # happens to listen on (a CI runner has sshd; a laptop usually does not).
      | (if (.probes.host_exposure? // empty) | type == "object"
           then .probes.host_exposure.open_ports = "<masked>" else . end)
      # Probe 11 picks whichever optional tester is installed (xray-knife vs xray), and
      # its status/failure_kind follow from that choice — toolchain, not wiring.
      | (if (.probes.xray_protocol? // empty) | type == "object"
           then .probes.xray_protocol.tester_binary = "<masked>"
              | .probes.xray_protocol.status        = "<masked>"
              | .probes.xray_protocol.failure_kind  = "<masked>"
           else . end)
      # The clock probe fetches a live HTTPS `Date` header and reports
      # `local_epoch - server_epoch`. That is a property of this machine and this
      # moment — it lands on 0/-1/+1 depending on the second boundary and RTT — and
      # `status` follows from the same fetch (`unknown` wherever the header is
      # unreachable). Both describe the environment, not the emitter.
      | (if (.probes.xray_clock? // empty) | type == "object"
           then .probes.xray_clock.skew_seconds = "<masked>"
              | .probes.xray_clock.status       = "<masked>"
           else . end)
      '
}

if [ "${1:-}" = "--update" ]; then
  canon > "$GOLDEN" || fail "could not regenerate $GOLDEN"
  [ -s "$GOLDEN" ] || fail "regenerated blob is empty — is the emitter broken?"
  echo "updated $GOLDEN ($(wc -l < "$GOLDEN" | tr -d ' ') lines)"; exit 0
fi

[ -s "$GOLDEN" ] || fail "golden values blob missing: $GOLDEN (run with --update)"

cur=$(canon)
[ -n "$cur" ] || fail "emitter produced no JSON (is the run broken?)"
printf '%s' "$cur" | jq -e . >/dev/null 2>&1 || fail "emitter produced invalid JSON"

if ! diff -u "$GOLDEN" <(printf '%s\n' "$cur") > /tmp/_jsonvals.diff 2>&1; then
  printf 'FAIL: emitted JSON differs from the recorded contract.\n' >&2
  printf '      A value moved, changed type, or vanished. If the change is INTENDED,\n' >&2
  printf '      review the diff and re-record with: bash tests/test_json_values_golden.sh --update\n\n' >&2
  head -60 /tmp/_jsonvals.diff >&2
  exit 1
fi

# schema_version is frozen at 1 for the whole 1.x line — a bump here is a 2.0 decision.
[ "$(printf '%s' "$cur" | jq -r '.schema_version')" = "1" ] \
  || fail "schema_version must stay 1 for the 1.x contract"

echo "PASS: full JSON output matches the recorded contract (values + structure, volatile fields masked)"
