#!/usr/bin/env bash
#
# tests/test_panel_probe.sh — --panel-probe (audit an origin IP for an exposed
# x-ui/3x-ui panel) + the _panel_classify classifier. Host-exposure only nc-scans
# the resolved IP (= the CDN edge on a fronted config); this actively fetches the
# panel ports/paths on a named backend and classifies each.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"; [ -n "${ppid:-}" ] && kill "$ppid" 2>/dev/null' EXIT
fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }

# ---- unit: the pure classifier ----
eval "$(awk '/^_panel_classify\(\)/,/^}/' "$SCRIPT")"
ck() { local w="$1" g; g=$(_panel_classify "$2" "$3" "$4"); [ "$g" = "$w" ] || fail "_panel_classify($2,$3,...)='$g' want '$w'"; }
ck closed 000 "" ""
ck cdn    521 cloudflare "whatever"
ck cdn    403 Cloudflare ""
ck panel  200 ""    "<title>3x-ui</title>"          # 3x-ui brand marker
ck panel  200 nginx "welcome to the x-ui panel"     # x-ui brand marker
ck login  200 ""    '<form><input type="password"></form>'   # login form, no brand
ck web    200 nginx "<html><body>hello</body></html>"        # plain web

command -v jq >/dev/null 2>&1 || { echo "PASS (unit only; jq not installed)"; exit 0; }

# ---- integration: stand up a fake x-ui panel on 127.0.0.1:54321 and detect it ----
if command -v python3 >/dev/null 2>&1; then
  mkdir -p "$TMP/web"; printf '<html><title>3x-ui</title><body>login</body></html>' > "$TMP/web/index.html"
  python3 -m http.server 54321 --bind 127.0.0.1 --directory "$TMP/web" >/dev/null 2>&1 & ppid=$!
  disown "$ppid" 2>/dev/null || true
  sleep 0.6
  out=$(TIMEOUT=3 bash "$SCRIPT" --panel-probe 127.0.0.1 --only env --json 2>/dev/null)
  [ "$(printf '%s' "$out" | jq -r '.probes.panel_probe.status')" = "ok" ] || fail "panel_probe should run (status ok)"
  [ "$(printf '%s' "$out" | jq -r '.probes.panel_probe.panel_found')" = "true" ] \
    || fail "a fake x-ui panel on :54321 should be detected (panel_found=true)"
  kill "$ppid" 2>/dev/null; ppid=""
else
  echo "note: python3 missing — skipping the live panel detection"
fi

# ---- no panel ports open on the target → clean (found=false) ----
out=$(TIMEOUT=3 bash "$SCRIPT" --panel-probe 127.0.0.1 --only env --json 2>/dev/null)
[ "$(printf '%s' "$out" | jq -r '.probes.panel_probe.status')" = "ok" ] || fail "panel_probe should still run with no ports open"
[ "$(printf '%s' "$out" | jq -r '.probes.panel_probe.panel_found')" = "false" ] \
  || fail "with no panel port open, panel_found should be false"

echo "PASS: _panel_classify matrix; --panel-probe detects a fake x-ui panel and reports clean when none"
