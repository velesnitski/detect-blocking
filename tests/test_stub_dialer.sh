#!/usr/bin/env bash
#
# tests/test_stub_dialer.sh — --stub-dialer: serve a LOCAL desync dialerProxy
# chain (ByeDPI/zapret) with a throwaway plain SOCKS5 so the tunnel probes run
# without the real desync proxy up. Tests (a) the embedded perl SOCKS5 relay
# actually forwards, and (b) the flag's gating: ignored with --no-tunnel, a no-op
# when there's no chain, and it won't stub a non-local dialer.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"; [ -n "${spid:-}" ] && kill "$spid" 2>/dev/null; [ -n "${hpid:-}" ] && kill "$hpid" 2>/dev/null' EXIT
fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }

u='00000000-0000-0000-0000-000000000000'
mkcfg() { # file  dialer-outbound-json  sockopt-json
  cat > "$TMP/$1" <<EOF
{ "outbounds": [
  {"tag":"proxy","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":1,"users":[{"id":"$u","encryption":"none"}]}]},
   "streamSettings":{"network":"httpupgrade","security":"tls","tlsSettings":{"serverName":"x","fingerprint":"chrome"}$3}},
  $2
  {"tag":"direct","protocol":"freedom"} ] }
EOF
}
mkcfg local.json  '{"tag":"byedpi-out","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":1090}]}},' ',"sockopt":{"dialerProxy":"byedpi-out"}'
mkcfg remote.json '{"tag":"hop","protocol":"socks","settings":{"servers":[{"address":"10.0.0.5","port":1080}]}},'         ',"sockopt":{"dialerProxy":"hop"}'
mkcfg plain.json  '' ''

# ---- (a) the embedded perl SOCKS5 relay forwards a connection ----
if command -v perl >/dev/null 2>&1 && command -v python3 >/dev/null 2>&1; then
  awk '/^_socks5_stub_serve\(\)/{g=1} g && /<<.PERL./{f=1;next} g && /^PERL$/{exit} f' "$SCRIPT" > "$TMP/stub.pl"
  [ -s "$TMP/stub.pl" ] || fail "could not extract the stub perl program"
  perl "$TMP/stub.pl" 39051 & spid=$!; disown "$spid" 2>/dev/null || true
  python3 -m http.server 39052 --bind 127.0.0.1 >/dev/null 2>&1 & hpid=$!; disown "$hpid" 2>/dev/null || true
  sleep 0.6
  body=$(curl -s --max-time 6 --socks5-hostname 127.0.0.1:39051 http://127.0.0.1:39052/ 2>/dev/null)
  case "$body" in *"Directory listing"*) ;; *) fail "SOCKS5 stub did not relay a connection (got: ${body:0:80})" ;; esac
  kill "$spid" "$hpid" 2>/dev/null; spid=""; hpid=""
else
  echo "note: perl or python3 missing — skipping the live relay check"
fi

# ---- (b) flag gating (fast: --no-tunnel or --only xray, endpoint 127.0.0.1:1) ----
# ignored with --no-tunnel
out=$(STUB_DIALER=1 TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$TMP/local.json" --stub-dialer --no-tunnel 2>/dev/null)
printf '%s' "$out" | grep -q 'stub-dialer ignored with --no-tunnel' || fail "--stub-dialer should be ignored under --no-tunnel"

# no dialerProxy chain → nothing to stub
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$TMP/plain.json" --stub-dialer --only xray 2>/dev/null)
printf '%s' "$out" | grep -q 'no dialerProxy chain' || fail "plain config should report nothing to stub"

# non-local dialer → not stubbed
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$TMP/remote.json" --stub-dialer --only xray 2>/dev/null)
printf '%s' "$out" | grep -q 'not a local proxy' || fail "a remote dialer must not be stubbed"

echo "PASS: perl SOCKS5 stub relays; --stub-dialer gates on --no-tunnel / no-chain / non-local dialer"
