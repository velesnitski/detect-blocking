#!/usr/bin/env bash
#
# tests/test_yt_reach.sh — --yt-test wiring. It's a TUNNEL probe, so without a tunnel
# it must skip GRACEFULLY (status=skipped, no crash) and still emit a well-formed
# youtube_reach JSON block. The live fan-out path needs a real tunnel + internet; its
# clean/capped/degraded/all-failed classification is the shared _classify_conn_limit,
# covered by test_conn_limit.sh.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }
tmp=$(mktemp -d) || { echo FAIL; exit 1; }
trap 'rm -rf "$tmp"' EXIT
PBK='AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
ID='00000000-0000-0000-0000-000000000000'
# loopback closed port → the tunnel can't establish, so the YT probe must skip
cat > "$tmp/cfg.json" <<EOF
{"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":1,"users":[{"id":"$ID","flow":"xtls-rprx-vision","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"publicKey":"$PBK","serverName":"www.example.com","shortId":"01","fingerprint":"chrome"}}}]}
EOF

out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$tmp/cfg.json" --yt-test 8 --json 2>/dev/null)
printf '%s' "$out" | jq -e '.probes.youtube_reach.status == "skipped"' >/dev/null 2>&1 \
  || fail "--yt-test without a tunnel should skip (status=skipped)"
printf '%s' "$out" | jq -e '.probes.youtube_reach | has("verdict") and has("requested") and has("max_ttfb_ms")' >/dev/null 2>&1 \
  || fail "youtube_reach JSON block should be well-formed even when skipped"

# without the flag the probe never runs (block present, status null — not skipped)
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$tmp/cfg.json" --json 2>/dev/null)
printf '%s' "$out" | jq -e '.probes.youtube_reach.status == null' >/dev/null 2>&1 \
  || fail "without --yt-test the probe should not run (status null)"

echo "PASS: --yt-test is a tunnel probe that skips gracefully with no tunnel and emits a well-formed JSON block"
