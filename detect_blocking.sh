#!/usr/bin/env bash
#
# detect_blocking.sh – VPN-blocking diagnostic
#
# Primary platform: macOS. Linux supported best-effort (Section 0 detects
# VPN state via platform-appropriate tools, all other probes are portable).
#
# Probes:
#   0. Environment           (is a VPN currently active? results describe its exit path)
#   1. DNS resolution        (sets-based; sinkhole / system-fail / DoH-fail / CDN-different)
#   2. TCP reachability      (baseline chain + target host on 443 / fallback to 80)
#   3. TLS handshake         (proper SNI / no SNI / innocent SNI)
#   4. Request-header filter (UA-based; NOT full JA3 — see probe 4 note)
#   5. Mid-handshake RST     (timing-based DPI-RST vs silent drop)
#   6. UDP protocols         (real IKE_SA_INIT + QUIC/HTTP3 check)
#   7. OpenVPN handshake     (random-SID 0x38 → expect 0x40); strict verdict opt-in
#   8. Control sites         (broad / partial / none censorship)
#
# Usage:
#   ./detect_blocking.sh                       # uses defaults / config file
#   ./detect_blocking.sh www.example.com    # CLI override of VPN_HOST
#   VPN_HOST=h.example.com ./detect_blocking.sh
#   ./detect_blocking.sh --log-file /tmp/d.log --quiet
#   ./detect_blocking.sh --xray-config 'vless://…' --reveal   # show real values
#   ./detect_blocking.sh --xray-config-json '{"outbounds":[…]}'   # inline JSON
#   ./detect_blocking.sh --xray-config-json - <<'EOF'  …json…  EOF   # via stdin
#   CONFIG_FILE=/path/to/file ./detect_blocking.sh
#
# --xray-config-json takes a file path, INLINE JSON ('{…}'), or '-' (stdin).
# JSON is full of shell-special symbols ({ } " space) — single-quote inline
# JSON, or pipe it with a quoted heredoc (<<'EOF') to avoid quoting entirely.
#
# --reveal prints the real offending values (cover serverName, egress IP/org,
# the flagged SNI) to the TERMINAL so you know exactly what to change. It is
# never logged, never in --json, never committed — and NOT safe to paste/share.
# Default output stays share-safe (booleans / country / codes only).
#
# Precedence: CLI arg > env var > config file > built-in default.
# See detect_blocking.conf.example for all knobs (including STRICT_OPENVPN_VERDICT).

set -u

readonly DETECT_BLOCKING_VERSION="1.12.3"

# ============================================================================
# FILE MAP — single-file by design (copy & run, no install). Jump to a section
# by searching its banner, e.g.  /^# ---------- Xray-protocol probes
#   setup ...... early helpers · portability + deps · config file · CLI args
#   drivers .... batch (--from-file) · watch (--watch)
#   globals .... config defaults · state (per-probe result vars)
#   helpers .... colors · log + emit · platform-aware (resolve / asn / synth / url)
#   probes ..... transport probes (0-10): env,dns,tcp,tls,ua,rst,udp,openvpn,control,ipv6,compare
#                Xray-protocol probes (11-26): protocol,json,throughput,capacity,cover,
#                  egress,stability,lint,clock,active-probe,fleet,routing,bufferbloat,mtu,
#                  tls-parity,cover-throttle,detectability(+deployment fingerprint)
#                  + SNI-privacy/ECH posture (advisory, after 26 — is the cleartext SNI hideable?)
#                opt-in scanners: probe_cover_scan (--scan-covers), probe_censor_sweep (--censor-sweep)
#                non-Xray: probe_hysteria (static Hysteria2/QUIC analysis; auto on a Hysteria2 config)
#                happ://: import→unwrap, probe_happ_routing (routing-profile lint), probe_happ_crypt (encrypted)
#   output ..... JSON emitter (--json) · main (probe dispatch) · summary (verdict + recommendations)
# ============================================================================

# Capture original CLI invocation before parsing — needed so --watch and
# --from-file can re-invoke ourselves with the same flags minus the looping
# flag (set via _WATCH_CHILD / _BATCH_CHILD to break recursion).
# shellcheck disable=SC2034
_ORIGINAL_ARGS=("$@")

# ---------- early helpers ----------

die()       { printf 'Error: %s\n' "$1" >&2; exit 2; }
check_cmd() { command -v "$1" >/dev/null 2>&1; }
# Standard silent, bounded curl — the common case across the tool. Centralizes the
# -sS/--max-time policy (and keeps flag choices in one place — e.g. never -D, which
# a case-insensitive `-d` egress-guard mis-flags). New network calls should use it;
# existing call sites migrate on touch. Extra flags/URL pass through: _curl -L "$u".
_curl() { curl -sS --max-time "${TIMEOUT:-10}" "$@"; }
# Guard a required-value flag: if its value is missing or looks like another flag,
# the value was omitted and the flag swallowed the next flag (e.g.
# `--xray-config-json --stub-dialer <path>`). Die with the correct order. Runs as
# a statement (not $(...)) so die exits the real shell.
_req_val() { case "${2:-}" in ''|--*) die "$1 needs a value, but got '${2:-<none>}' — the value was omitted. Put it right after $1, then other flags: e.g. $1 <value> --stub-dialer";; esac; }

# ---------- portability + dependency checks ----------

case "$OSTYPE" in
  darwin*|linux*) ;;
  *) printf '%s\n' "detect_blocking.sh: unsupported OS '$OSTYPE' (macOS / Linux only)" >&2; exit 2 ;;
esac

check_cmd openssl || die "openssl not found in PATH"
for _req in curl nc awk sed grep; do
  check_cmd "$_req" || die "$_req not found in PATH"
done
unset _req

# openssl -brief requires OpenSSL 1.1.1+ or LibreSSL 3+.
_ossl_ver=$(openssl version 2>/dev/null | awk '{print $1" "$2}')
case "$_ossl_ver" in
  "OpenSSL 1.1.1"*|"OpenSSL 3."*|"OpenSSL 4."*|"LibreSSL 3."*|"LibreSSL 4."*) ;;
  *)
    printf 'detect_blocking.sh: need OpenSSL 1.1.1+ or LibreSSL 3+ for -brief\n  detected: %s\n' \
      "$_ossl_ver" >&2
    exit 2
    ;;
esac
unset _ossl_ver

# Optional commands — warn but continue.
_missing_optional=""
check_cmd jq   || _missing_optional="$_missing_optional jq"
check_cmd dig  || _missing_optional="$_missing_optional dig"
check_cmd perl || _missing_optional="$_missing_optional perl"
check_cmd xxd  || _missing_optional="$_missing_optional xxd"

# ---------- config file (optional, sourced before defaults) ----------

# Resolve THROUGH symlinks so a symlinked-in-PATH install (e.g. /usr/local/bin/detect-blocking
# -> /opt/…/detect_blocking.sh) still finds the detect_blocking.conf that sits next to the
# REAL file, not next to the symlink. (Bash shebang → BASH_SOURCE is always set; no zsh path.)
_self="${BASH_SOURCE[0]}"
while [ -L "$_self" ]; do
  _sd="$( cd -P -- "$( dirname -- "$_self" )" &> /dev/null && pwd )"
  _self="$( readlink -- "$_self" )"
  case "$_self" in /*) ;; *) _self="$_sd/$_self" ;; esac
done
SCRIPT_DIR="$( cd -P -- "$( dirname -- "$_self" )" &> /dev/null && pwd )"
unset _self _sd
CONFIG_FILE="${CONFIG_FILE:-$SCRIPT_DIR/detect_blocking.conf}"
if [ -f "$CONFIG_FILE" ]; then
  # shellcheck disable=SC1090
  . "$CONFIG_FILE"
fi

# ---------- CLI args ----------

LOG_FILE="${LOG_FILE:-}"
LOG_QUIET="${LOG_QUIET:-0}"
ONLY_PROBES="${ONLY_PROBES:-}"
OUTBOUND_TAG="${OUTBOUND_TAG:-}"   # --outbound TAG: narrow a multi-outbound JSON to one server
SUB_URL="${SUB_URL:-}"             # --subscription URL: fetch a sub (JSON-array / single / base64), inventory it, test one
SUB_TEST="${SUB_TEST:-0}"          # which config index from the sub to run the full suite on (default 0)
SUB_UA="${SUB_UA:-Happ/2.6.0}"     # client User-Agent for the sub fetch (many panels gate on it)
SUB_DIR=""                         # temp dir holding the extracted per-config files (EXIT-cleaned)
SUB_COUNT=""                       # number of configs found in the sub
SUB_WALK=""                        # set when --sub-test all: walk + score every config
SUB_JOBS="${SUB_JOBS:-8}"          # --sub-test all: concurrent fingerprint probes (1 = serial)
NO_TUNNEL="${NO_TUNNEL:-}"         # 1 = skip tunnel/data-plane probes, keep direct fingerprint only
STUB_DIALER="${STUB_DIALER:-}"     # --stub-dialer: serve a local desync dialerProxy chain with a throwaway plain socks
_STUB_PID=""                       # PID of the stub socks (killed by _cleanup)
XRAY_ONLY="${XRAY_ONLY:-}"   # 1 = --xray-only (run only the Xray-protocol probes 11-26 + routing/egress)
SKIP_PROBES="${SKIP_PROBES:-}"
JSON_MODE="${JSON_MODE:-0}"
# --reveal: print the real offending values (cover SNI, egress IP/org, matched
# keyword) to the TERMINAL so an operator knows exactly what to change. OFF by
# default so normal output stays share-safe; reveal output is never logged,
# never in --json, and (obviously) never committed. NOT safe to paste/share.
REVEAL="${REVEAL:-0}"
WATCH_INTERVAL="${WATCH_INTERVAL:-}"
BATCH_FILE="${BATCH_FILE:-}"
PCAP_FILE="${PCAP_FILE:-}"
PCAP_PID=""
COMPARE_SNI="${COMPARE_SNI:-}"
COMPARE_PORT="${COMPARE_PORT:-}"
PORT_SURVEY=0
XRAY_CONFIG="${XRAY_CONFIG:-}"
XRAY_JSON_CONFIG="${XRAY_JSON_CONFIG:-}"
XRAY_JSON_XRAY_PID=""
XRAY_JSON_PATCHED_PATH=""
XRAY_INLINE_JSON_PATH=""   # temp file for inline/stdin --xray-config-json (EXIT-cleaned)
XRAY_JSON_FORMAT=""        # set to "sing-box"/"non-Xray" if the JSON isn't an Xray-core config

while [ $# -gt 0 ]; do
  case "$1" in
    --log-file)    LOG_FILE="${2:-}"; shift 2 ;;
    --log-file=*)  LOG_FILE="${1#--log-file=}"; shift ;;
    --only)        ONLY_PROBES="${2:-}"; shift 2 ;;
    --only=*)      ONLY_PROBES="${1#--only=}"; shift ;;
    --xray-only)   ONLY_PROBES="xray,xrayjson"; XRAY_ONLY=1; shift ;;
    --scan-covers) case "${2:-}" in ""|-*) XRAY_SCAN_COVERS=default; shift ;; *) XRAY_SCAN_COVERS="$2"; shift 2 ;; esac ;;
    --scan-covers=*) XRAY_SCAN_COVERS="${1#--scan-covers=}"; shift ;;
    --panel-probe) case "${2:-}" in ""|-*) PANEL_PROBE=1; shift ;; *) PANEL_PROBE="$2"; shift 2 ;; esac ;;
    --panel-probe=*) PANEL_PROBE="${1#--panel-probe=}"; shift ;;
    --no-panel-probe) PANEL_PROBE=0; shift ;;
    --censor-sweep) case "${2:-}" in ""|-*) XRAY_CENSOR_SWEEP=default; shift ;; *) XRAY_CENSOR_SWEEP="$2"; shift 2 ;; esac ;;
    --censor-sweep=*) XRAY_CENSOR_SWEEP="${1#--censor-sweep=}"; shift ;;
    --conn-test) case "${2:-}" in ""|-*|*[!0-9]*) CONN_TEST_N=16; shift ;; *) CONN_TEST_N="$2"; shift 2 ;; esac ;;
    --conn-test=*) CONN_TEST_N="${1#--conn-test=}"; case "$CONN_TEST_N" in ''|*[!0-9]*) CONN_TEST_N=16 ;; esac; shift ;;
    --yt-test) YT_TEST_FORCE=1; case "${2:-}" in ""|-*|*[!0-9]*) YT_TEST_N=16; shift ;; *) YT_TEST_N="$2"; shift 2 ;; esac ;;
    --yt-test=*) YT_TEST_FORCE=1; YT_TEST_N="${1#--yt-test=}"; case "$YT_TEST_N" in ''|*[!0-9]*) YT_TEST_N=16 ;; esac; shift ;;
    --no-yt-test) YT_TEST_N=""; shift ;;
    --no-conn-test) CONN_TEST_N=""; shift ;;
    --full|--thorough)
      # Umbrella: turn on the two opt-in scanners (everything else already runs by
      # default for a config). Explicit by design — --censor-sweep fetches
      # known-censored sites from THIS machine, so it must be the operator's call,
      # not a silent default. Doesn't clobber an explicit --scan-covers=LIST etc.
      [ -z "${XRAY_SCAN_COVERS:-}" ]  && XRAY_SCAN_COVERS=default
      [ -z "${XRAY_CENSOR_SWEEP:-}" ] && XRAY_CENSOR_SWEEP=default
      PORT_SURVEY=1   # alt-VPN/proxy port sweep on the target — cheap, own host, finds bypass ports
      printf '%s\n' "note: --full also runs --censor-sweep (fetches known-censored sites from THIS machine to test reachability) — fine on a test box, reconsider on a sensitive / in-region one" >&2
      shift ;;
    --skip)        SKIP_PROBES="${2:-}"; shift 2 ;;
    --skip=*)      SKIP_PROBES="${1#--skip=}"; shift ;;
    --watch)       WATCH_INTERVAL="${2:-}"; shift 2 ;;
    --watch=*)     WATCH_INTERVAL="${1#--watch=}"; shift ;;
    --from-file)   BATCH_FILE="${2:-}"; shift 2 ;;
    --from-file=*) BATCH_FILE="${1#--from-file=}"; shift ;;
    --pcap)        PCAP_FILE="${2:-}"; shift 2 ;;
    --pcap=*)      PCAP_FILE="${1#--pcap=}"; shift ;;
    --compare-sni)    COMPARE_SNI="${2:-}"; shift 2 ;;
    --compare-sni=*)  COMPARE_SNI="${1#--compare-sni=}"; shift ;;
    --compare-port)   COMPARE_PORT="${2:-}"; shift 2 ;;
    --compare-port=*) COMPARE_PORT="${1#--compare-port=}"; shift ;;
    --port-survey)    PORT_SURVEY=1; shift ;;
    --xray-config)    _req_val "$1" "${2:-}"; XRAY_CONFIG="${2:-}"; shift 2 ;;
    --xray-config=*)  XRAY_CONFIG="${1#--xray-config=}"; shift ;;
    --subscription|--sub) SUB_URL="${2:-}"; shift 2 ;;
    --subscription=*)     SUB_URL="${1#--subscription=}"; shift ;;
    --sub-test)    SUB_TEST="${2:-}"; shift 2 ;;
    --sub-test=*)  SUB_TEST="${1#--sub-test=}"; shift ;;
    --sub-ua)      SUB_UA="${2:-}"; shift 2 ;;
    --sub-ua=*)    SUB_UA="${1#--sub-ua=}"; shift ;;
    --sub-jobs)    SUB_JOBS="${2:-}"; shift 2 ;;
    --sub-jobs=*)  SUB_JOBS="${1#--sub-jobs=}"; shift ;;
    --no-tunnel)   NO_TUNNEL=1; shift ;;
    --stub-dialer) STUB_DIALER=1; shift ;;
    --no-stub-dialer) STUB_DIALER=0; shift ;;
    --outbound)    OUTBOUND_TAG="${2:-}"; shift 2 ;;
    --outbound=*)  OUTBOUND_TAG="${1#--outbound=}"; shift ;;
    --xray-config-json)    _req_val "$1" "${2:-}"; XRAY_JSON_CONFIG="${2:-}"; shift 2 ;;
    --xray-config-json=*)  XRAY_JSON_CONFIG="${1#--xray-config-json=}"; shift ;;
    --ovpn-config)    _req_val "$1" "${2:-}"; OVPN_CONFIG="${2:-}"; shift 2 ;;
    --ovpn-config=*)  OVPN_CONFIG="${1#--ovpn-config=}"; shift ;;
    --speedtest)    XRAY_SPEEDTEST=1; XRAY_SPEEDTEST_FORCE=1; shift ;;
    --no-speedtest) XRAY_SPEEDTEST=0; shift ;;
    --no-egress-check) XRAY_EGRESS_CHECK=0; shift ;;
    --stability)    XRAY_STABILITY=1; XRAY_STABILITY_FORCE=1; shift ;;
    --no-stability) XRAY_STABILITY=0; shift ;;
    --fleet)        XRAY_FLEET=1; XRAY_FLEET_FORCE=1; shift ;;
    --no-fleet)     XRAY_FLEET=0; shift ;;
    --no-bufferbloat) XRAY_BUFFERBLOAT=0; shift ;;
    --save-baseline)   SAVE_BASELINE="${2:-}"; shift 2 ;;
    --save-baseline=*) SAVE_BASELINE="${1#--save-baseline=}"; shift ;;
    --diff-baseline)   DIFF_BASELINE="${2:-}"; shift 2 ;;
    --diff-baseline=*) DIFF_BASELINE="${1#--diff-baseline=}"; shift ;;
    --reveal)      REVEAL=1; shift ;;
    --via-tunnel)  VIA_TUNNEL=1; shift ;;
    --localize)    LOCALIZE=1; shift ;;
    --label)       _req_val "$1" "${2:-}"; RUN_LABEL="${2:-}"; shift 2 ;;
    --label=*)     RUN_LABEL="${1#--label=}"; shift ;;
    --quiet|-q)    LOG_QUIET=1; shift ;;
    --json)        JSON_MODE=1; LOG_QUIET=1; shift ;;
    --version|-V)
      printf 'detect_blocking %s\n' "$DETECT_BLOCKING_VERSION"
      exit 0
      ;;
    --help|-h)
      sed -n '2,39p' "$0"
      printf '\nversion: %s\n' "$DETECT_BLOCKING_VERSION"
      printf '\nProbe names (for --only / --skip): env, tunnel, dns, tcp, tls, ua, rst, udp, openvpn, control, whitelist, localize, ipv6, compare, xray, xrayjson\n'
      printf '\nFlags:\n'
      printf '  --json (needs jq)   machine-readable JSON output (compact in batch/watch loops)\n'
      printf '  --quiet, -q         suppress stdout (logging still works)\n'
      printf '  --log-file PATH     append timestamped entries to PATH\n'
      printf '  --only LIST         run only listed probes (comma-separated)\n'
      printf '  --xray-only         only the Xray-protocol probes (11-26 + routing/egress); skips transport probes 0-10 (alias for --only xray,xrayjson; needs --xray-config / --xray-config-json)\n'
      printf '  --scan-covers[=LIST] rank candidate Reality dest/serverName covers (TLSv1.3 + H2 + CA-valid + non-redirect); LIST is comma-separated, or omit for a built-in set\n'
      printf '  --censor-sweep[=LIST] reachability of commonly-censored hosts, direct vs through the tunnel (does the tunnel unblock them?); LIST is comma-separated, or omit for a built-in set\n'
      printf '  --no-panel-probe    the panel audit AUTO-runs when a panel port answers on a non-CDN IP;\n'
      printf '                      --no-panel-probe opts out (--panel-probe [IP] still forces/redirects it)\n'
      printf '  --panel-probe [IP]  audit an ORIGIN IP for an exposed x-ui/3x-ui admin panel (checks the known\n'
      printf '                      panel ports+paths, classifies each login/CDN/web/closed). Point it at the\n'
      printf '                      backend behind the CDN — the fronted domain only reaches the CDN edge\n'
      printf '  --conn-test [N]     open N simultaneous TLS handshakes to the server and report how\n'
      printf '  --no-conn-test      ON BY DEFAULT at N=8 (concurrent, target-only); --no-conn-test opts out\n'
      printf '                      many complete — does it cap / rate-limit / degrade under concurrency (server\n'
      printf '                      robustness; pair with --sub-test N to deep-test one fleet node). Direct probe.\n'
      printf '  --yt-test [N]       YouTube fan-out: open N concurrent connections THROUGH the tunnel to real\n'
      printf '                      YouTube hosts + report how many complete + TTFB (egress quality / buffering).\n'
      printf '                      ON BY DEFAULT for tunnel runs (N=6, auto-skipped in --watch/--from-file loops);\n'
      printf '                      --yt-test [N] forces a thorough run (default 16); --no-yt-test disables it.\n'
      printf '  --full, --thorough  comprehensive run: enable the opt-in scanners (--scan-covers + --censor-sweep);\n'
      printf '                      everything else already runs by default. NOTE: --censor-sweep fetches censored sites from THIS machine\n'
      printf '  --skip LIST         skip listed probes\n'
      printf '  --watch SECONDS     repeat probe every SECONDS, until interrupted\n'
      printf '  --from-file PATH    iterate over hosts in file (one per line, # comments)\n'
      printf '  --pcap PATH         tcpdump probe traffic to PATH (needs root / cap_net_raw)\n'
      printf '  --compare-sni LIST  comma-separated SNI values to test (vs proper / FAKE_SNI)\n'
      printf '  --compare-port LIST comma-separated TCP ports to test (vs VPN_PORT_TCP)\n'
      printf '  --port-survey       scan common alternative VPN/proxy ports (8443, 2083, 2087, ...)\n'
      printf '  --xray-config URL   delegate end-to-end protocol test to xray-knife (optional dep)\n'
      printf '                      accepts vless://, vmess://, trojan://, ss://, hysteria2:// URLs\n'
      printf '                      also accepts a Happ deep link: happ://import/<config-url> (unwrapped\n'
      printf '                      and tested), happ://routing/add/<b64> (routing profile — recognised + linted)\n'
      printf '  --xray-config-json FILE  full-config probe via xray-core + SOCKS5 (covers fragment,\n'
      printf '                      dialerProxy, chained outbounds; needs xray + jq)\n'
      printf '                      also accepts a Hysteria2 client config (YAML or JSON) — runs the\n'
      printf '                      static Hysteria2 analyzer (SNI tell, obfs, QUIC-SNI, UDP/443)\n'
      printf '  --ovpn-config FILE  parse an OpenVPN .ovpn profile — reachability + active-probe\n'
      printf '                      response + control-channel fingerprintability posture (tls-crypt/\n'
      printf '                      tls-auth/obfs); host + inline keys never printed (--reveal to show)\n'
      printf '  --subscription URL  fetch a subscription (cookie-jar + client UA), decode it (JSON array of\n'
      printf '                      Xray configs / single config / base64), inventory the fleet, and run the\n'
      printf '                      full suite on one config (--sub-test N, default 0; --sub-ua to set the UA).\n'
      printf '                      --sub-test all → score EVERY server (fast fingerprint-only fleet table,\n'
      printf '                      probed concurrently; --sub-jobs N sets the batch size, default 8, 1=serial)\n'
      printf '                      --sub-test all --yt-test → also add a per-node YouTube column (spins a\n'
      printf '                      tunnel per node → slower; batch defaults to 3 to avoid xray thrash)\n'
      printf '  --no-tunnel         skip tunnel/data-plane probes (no xray spawn, no throughput); run only the\n'
      printf '                      direct fingerprint probes (cover/active-probe/TLS-parity/detectability)\n'
      printf '  --no-stub-dialer    the local-dialerProxy stub AUTO-starts when one is configured but dead\n'
      printf '                      (otherwise every tunnel probe fails and reads as a dead endpoint)\n'
      printf '  --stub-dialer       if the config dials through a LOCAL dialerProxy (ByeDPI/zapret) that is not\n'
      printf '                      running, serve it with a throwaway PLAIN socks so the tunnel probes run.\n'
      printf '                      Tests carriage + egress/QoE, NOT desync efficacy (that needs a DPI vantage)\n'
      printf '  --outbound TAG      for a multi-outbound JSON config, narrow to the outbound with this\n'
      printf '                      tag and test that server standalone (routing dropped); without it the\n'
      printf '                      full config is tested and the first proxy outbound feeds the probes\n'
      printf '  --speedtest         force probe 14 (multi-stream capacity) even inside --watch/--from-file\n'
      printf '  --no-speedtest      disable probe 14 (it runs by default when probe 12 succeeds)\n'
      printf '  --no-egress-check   disable probe 16 (egress geo/reputation; avoids a 3rd-party IP-info call)\n'
      printf '  --via-tunnel        force the VPN-tunnel-effectiveness probe (auto-runs when your default\n'
      printf '                      route is a tunnel): compares egress through vs around the tunnel\n'
      printf '  --label NAME        name this vantage (e.g. --label lte-megafon); stamped into --json and\n'
      printf '                      shown in the baseline diff header, so an LTE run vs a Wi-Fi run of the\n'
      printf '                      same endpoint is self-describing (pairs with --save/--diff-baseline)\n'
      printf '  --localize          force the censorship-localization probe (auto-runs only when probe 2\n'
      printf '                      MEASURED the target unreachable): bounded traceroute + ASN/geo of the\n'
      printf '                      last hop → ISP edge / transit / near-destination / endpoint\n'
      printf '                      env: LOCALIZE_MAX_HOPS (1-64, default 20) · LOCALIZE_WAIT (1-10s, default 1)\n'
      printf '  --no-stability      disable probe 17 (held-session RST detection; it runs by default)\n'
      printf '  --stability         force probe 17 even inside --watch/--from-file loops\n'
      printf '  --no-fleet          disable probe 21 (it auto-enables on multi-outbound configs; N xray spawns)\n'
      printf '  --fleet             force probe 21 even inside --watch/--from-file loops\n'
      printf '  --no-bufferbloat    disable probe 22 (latency-under-load; saturates the tunnel briefly)\n'
      printf '  --save-baseline FILE  write this run'"'"'s share-safe JSON to FILE (a healthy reference)\n'
      printf '  --diff-baseline FILE  run, then report what changed vs the baseline in FILE (regression mode)\n'
      exit 0
      ;;
    -*) die "unknown option: $1" ;;
    *)  VPN_HOST="${1}"; shift ;;
  esac
done

# --xray-only runs only the Xray-protocol probes, which need a config to test.
if [ "${XRAY_ONLY:-}" = "1" ] && [ -z "$XRAY_CONFIG" ] && [ -z "$XRAY_JSON_CONFIG" ]; then
  printf '%s\n' "note: --xray-only runs the Xray-protocol probes (11-26) but no --xray-config / --xray-config-json was given — nothing to probe" >&2
fi

if [ "$JSON_MODE" = "1" ]; then
  check_cmd jq || die "--json requires jq (install: brew install jq / apt-get install jq)"
fi

# Strip control characters (incl. ESC) from a string before it is printed or
# logged. Config-derived values — host, SNI, tag — are attacker-influenced; a
# crafted value with ANSI/terminal escapes would otherwise execute when the
# output or --log-file is viewed (terminal-escape injection). Defined early so the
# auto-derive notes below can use it. Legit hosts/SNIs have no control chars, so
# this is a no-op on real input.
_safe() { LC_ALL=C printf '%s' "${1-}" | LC_ALL=C tr -d '[:cntrl:]'; }

# Happ deep-link flags (set during normalization below; declared here so they
# exist under `set -u` regardless of the config type).
HAPP_ROUTING=""; HAPP_ROUTING_SRC=""; HAPP_CRYPT=""

# Sanitise --xray-config: terminal paste-wrap is a common source of embedded
# newlines / spaces. Strip all whitespace; if anything was removed, warn
# (to stderr only, not LOG_QUIET-gated) so the operator notices. Then
# verify the scheme is one xray-knife understands before any further work.
if [ -n "$XRAY_CONFIG" ]; then
  _xray_orig="$XRAY_CONFIG"
  XRAY_CONFIG=$(printf '%s' "$XRAY_CONFIG" | tr -d '[:space:]')
  if [ "$XRAY_CONFIG" != "$_xray_orig" ]; then
    printf '%s\n' "warning: --xray-config contained whitespace (terminal paste-wrap?); stripped before use" >&2
  fi
  unset _xray_orig

  # Happ deep-link normalization (BEFORE the scheme check). happ://import/<url>
  # unwraps to the inner config URL so it flows through the normal handlers;
  # happ://routing/add and happ://crypt carry no server, so flag them and clear
  # XRAY_CONFIG (the scheme check + URL derivation below then skip). Helpers
  # aren't defined this early, so base64 / percent-decode is inlined.
  case "$XRAY_CONFIG" in
    happ://import/*)
      _hinner=${XRAY_CONFIG#happ://import/}
      case "$_hinner" in
        *://*) : ;;                                            # already a scheme URL
        *%3[Aa]*) _hinner=$(printf '%b' "${_hinner//%/\\x}") ;; # percent-encoded URL
        *)                                                     # maybe base64-wrapped
          _hdec=$(printf '%s' "$_hinner" | base64 -d 2>/dev/null || printf '%s' "$_hinner" | base64 -D 2>/dev/null)
          case "$_hdec" in *://*) _hinner="$_hdec" ;; esac ;;
      esac
      XRAY_CONFIG="$_hinner"
      printf '%s\n' "note: unwrapped happ://import/ → ${_hinner%%://*}:// config" >&2 ;;
    happ://routing/add/*)
      HAPP_ROUTING=1
      HAPP_ROUTING_SRC=$(printf '%s' "${XRAY_CONFIG#happ://routing/add/}" | base64 -d 2>/dev/null \
                         || printf '%s' "${XRAY_CONFIG#happ://routing/add/}" | base64 -D 2>/dev/null)
      XRAY_CONFIG=""; [ -z "${ONLY_PROBES:-}" ] && ONLY_PROBES="env" ;;
    happ://crypt*)
      HAPP_CRYPT=1; XRAY_CONFIG=""; [ -z "${ONLY_PROBES:-}" ] && ONLY_PROBES="env" ;;
    happ://*)
      die "unrecognized happ:// link — supported: happ://import/<config-url>, happ://routing/add/<b64>, or happ://crypt… (encrypted; paste the decrypted vless:// or sub URL instead)" ;;
  esac
fi

if [ -n "$XRAY_CONFIG" ]; then
  case "$XRAY_CONFIG" in
    vless://*|vmess://*|trojan://*|ss://*|hysteria://*|hysteria2://*|tuic://*) ;;
    *) die "--xray-config: unrecognised scheme; expected one of vless://, vmess://, trojan://, ss://, hysteria://, hysteria2://, tuic:// (got: $(printf '%s' "$XRAY_CONFIG" | head -c 20))" ;;
  esac

  # Auto-derive VPN_HOST from URL when no positional host was given. Keeps
  # probes 0-10 aligned with the protocol probe (11) so cross-referencing
  # (e.g. "TLS works but Xray fails") is meaningful. Skipped for vmess://
  # whose host lives inside a base64-encoded JSON blob.
  if [ -z "${VPN_HOST:-}" ]; then
    case "$XRAY_CONFIG" in
      vless://*|trojan://*|ss://*|hysteria://*|hysteria2://*|tuic://*)
        # Authority = after '@', before '?', '#' or '/'. Split host:port with
        # IPv6-literal awareness ([addr]:port) so a v6 host isn't mangled to
        # "[2001". (The old [^:?#/]+ regex stopped at the first colon.)
        _auth=${XRAY_CONFIG#*://}; _auth=${_auth#*@}; _auth=${_auth%%[?#/]*}
        case "$_auth" in
          \[*\]*)  # IPv6 literal: [addr] or [addr]:port
            _derived_host=${_auth#\[}; _derived_host=${_derived_host%%\]*}
            case "$_auth" in *\]:*) _derived_port=${_auth##*\]:} ;; *) _derived_port="" ;; esac ;;
          *:*)     _derived_host=${_auth%%:*}; _derived_port=${_auth##*:} ;;
          *)       _derived_host=$_auth; _derived_port="" ;;
        esac
        case "$_derived_port" in *[!0-9]*) _derived_port="" ;; esac
        unset _auth
        if [ -n "$_derived_host" ]; then
          _derived_host=$(_safe "$_derived_host"); VPN_HOST="$_derived_host"
          if [ -n "$_derived_port" ] && [ -z "${VPN_PORT_TCP:-}" ]; then
            VPN_PORT_TCP="$_derived_port"
            printf '%s\n' "note: VPN_HOST + VPN_PORT_TCP auto-derived from --xray-config → ${_derived_host}:${_derived_port}" >&2
          else
            printf '%s\n' "note: VPN_HOST auto-derived from --xray-config → $_derived_host" >&2
          fi
        fi
        unset _derived_host _derived_port
        ;;
      vmess://*)
        printf '%s\n' "note: vmess:// URL provided without positional host — host is inside base64 JSON, pass it explicitly to align probes 0-10" >&2
        ;;
    esac
  fi
fi

# --subscription URL: fetch a sub, decode it, inventory the fleet, and run the full
# suite on one selected config. Sub panels commonly 302-to-self with a Set-Cookie
# challenge and gate on the client User-Agent, so we fetch with a cookie jar + a
# Happ-like UA. The response may be a JSON array of full Xray configs, a single
# config object, or a base64 blob wrapping either. Each extracted config is written
# 0600 into a 0700 temp dir (live creds) and EXIT-cleaned. The selected one becomes
# --xray-config-json so it flows through the normal detection + probe pipeline.
if [ -n "$SUB_URL" ]; then
  command -v curl >/dev/null 2>&1 || { printf 'error: --subscription needs curl\n' >&2; exit 1; }
  command -v jq   >/dev/null 2>&1 || { printf 'error: --subscription needs jq\n' >&2; exit 1; }
  SUB_DIR=$(mktemp -d -t detect_blocking.sub.XXXXXX) || { printf 'error: could not create a sub temp dir\n' >&2; exit 1; }
  chmod 700 "$SUB_DIR" 2>/dev/null || true
  _sub_jar="$SUB_DIR/jar"; _sub_raw="$SUB_DIR/raw"
  curl -sS -L -c "$_sub_jar" -b "$_sub_jar" --max-time 30 -A "$SUB_UA" -o "$_sub_raw" "$SUB_URL" 2>/dev/null \
    || { printf 'error: --subscription fetch failed: %s\n' "$SUB_URL" >&2; exit 1; }
  rm -f "$_sub_jar"
  _sub_body=$(cat "$_sub_raw" 2>/dev/null); rm -f "$_sub_raw"
  case "$_sub_body" in
    \[*|\{*) : ;;                                          # already JSON
    *) _sub_dec=$(printf '%s' "$_sub_body" | base64 -d 2>/dev/null || printf '%s' "$_sub_body" | base64 -D 2>/dev/null)
       case "$_sub_dec" in \[*|\{*) _sub_body="$_sub_dec" ;; esac ;;
  esac
  if printf '%s' "$_sub_body" | jq -e 'type=="array"' >/dev/null 2>&1; then
    SUB_COUNT=$(printf '%s' "$_sub_body" | jq 'length' 2>/dev/null)
    _i=0; while [ "$_i" -lt "${SUB_COUNT:-0}" ]; do
      printf '%s' "$_sub_body" | jq -c ".[$_i]" > "$SUB_DIR/$(printf '%03d' "$_i").json" 2>/dev/null
      chmod 600 "$SUB_DIR/$(printf '%03d' "$_i").json" 2>/dev/null || true
      _i=$((_i+1))
    done
  elif printf '%s' "$_sub_body" | jq -e 'type=="object" and (.outbounds!=null)' >/dev/null 2>&1; then
    SUB_COUNT=1; printf '%s' "$_sub_body" | jq -c '.' > "$SUB_DIR/000.json" 2>/dev/null
    chmod 600 "$SUB_DIR/000.json" 2>/dev/null || true
  else
    printf 'error: --subscription: response is not a JSON array/object of Xray configs (a base64 vless:// list is not walked yet — pass one server to --xray-config)\n' >&2
    exit 1
  fi
  [ "${SUB_COUNT:-0}" -ge 1 ] 2>/dev/null || { printf 'error: --subscription: no configs found in the response\n' >&2; exit 1; }
  if [ "$SUB_TEST" = "all" ]; then
    SUB_WALK=1
    if [ "${YT_TEST_FORCE:-0}" = "1" ]; then
      printf 'note: --subscription fetched %s config(s); scoring ALL with a per-node tunnel + YouTube fan-out (slower — one xray per node)\n' "$SUB_COUNT" >&2
    else
      printf 'note: --subscription fetched %s config(s); scoring ALL (fingerprint-only fleet walk, no tunnel)\n' "$SUB_COUNT" >&2
    fi
  else
    case "$SUB_TEST" in ''|*[!0-9]*) SUB_TEST=0 ;; esac
    [ "$SUB_TEST" -ge "$SUB_COUNT" ] && SUB_TEST=0
    XRAY_JSON_CONFIG="$SUB_DIR/$(printf '%03d' "$SUB_TEST").json"
    printf 'note: --subscription fetched %s config(s); inventory printed below; full suite runs on index %s\n' "$SUB_COUNT" "$SUB_TEST" >&2
  fi
fi

# --xray-config-json accepts a file path, INLINE JSON ('{...}'), or '-' (stdin).
# JSON is full of shell-hostile symbols — { } " space : — so inline must be
# single-quoted, and the cleanest symbol-proof way is a quoted heredoc over
# stdin:  --xray-config-json - <<'EOF' … EOF  (the quoted 'EOF' stops the shell
# touching $ / backticks / quotes inside). Inline & stdin JSON is written to a
# 0600 temp file (EXIT-cleaned) so every downstream reader still sees a path.
if [ -n "${XRAY_JSON_CONFIG:-}" ] && [ ! -f "$XRAY_JSON_CONFIG" ]; then
  _raw=""
  if [ "$XRAY_JSON_CONFIG" = "-" ]; then
    _raw=$(cat)                                   # read JSON from stdin
  else
    case "$XRAY_JSON_CONFIG" in *"{"*) _raw="$XRAY_JSON_CONFIG" ;; esac
  fi
  if [ -n "$_raw" ]; then
    XRAY_INLINE_JSON_PATH=$(mktemp -t detect_blocking.inlinecfg.XXXXXX) \
      || { printf 'error: could not create a temp file for inline JSON\n' >&2; exit 1; }
    chmod 600 "$XRAY_INLINE_JSON_PATH" 2>/dev/null || true
    printf '%s' "$_raw" > "$XRAY_INLINE_JSON_PATH"
    if command -v jq >/dev/null 2>&1 && ! jq empty "$XRAY_INLINE_JSON_PATH" >/dev/null 2>&1; then
      rm -f "$XRAY_INLINE_JSON_PATH"; XRAY_INLINE_JSON_PATH=""
      printf 'error: --xray-config-json received invalid JSON.\n' >&2
      printf "       Single-quote inline JSON, or pipe it:  --xray-config-json - <<'EOF' … EOF\n" >&2
      exit 1
    fi
    XRAY_JSON_CONFIG="$XRAY_INLINE_JSON_PATH"
  elif [ "$XRAY_JSON_CONFIG" = "-" ]; then
    printf 'error: --xray-config-json - got empty stdin\n' >&2; exit 1
  fi
fi

# Hysteria2? A QUIC/UDP protocol — a different stack from Xray (no Reality cover,
# no TLS-in-TLS, lives on UDP/443). Accept a YAML or JSON client config via
# --xray-config-json, or a hysteria2:// URI via --xray-config, and route it to the
# static Hysteria2 analyzer (probe_hysteria) instead of the Xray-protocol probes —
# a TCP/TLS probe against a UDP/443 server would falsely read "unreachable".
HYSTERIA_DETECTED=""; HYSTERIA_SRC=""
case "${XRAY_CONFIG:-}" in
  hysteria2://*|hy2://*|hysteria://*) HYSTERIA_DETECTED=1; HYSTERIA_SRC="$XRAY_CONFIG" ;;
esac
if [ -z "$HYSTERIA_DETECTED" ] && [ -n "${XRAY_JSON_CONFIG:-}" ] && [ -r "$XRAY_JSON_CONFIG" ]; then
  if command -v jq >/dev/null 2>&1 && jq empty "$XRAY_JSON_CONFIG" >/dev/null 2>&1; then
    # valid JSON: a Hysteria2 JSON client config has top-level server + auth/obfs
    # and no Xray "outbounds".
    if jq -e '(.server != null) and ((.auth != null) or (.obfs != null)) and (.outbounds == null)' \
         "$XRAY_JSON_CONFIG" >/dev/null 2>&1; then
      HYSTERIA_DETECTED=1; HYSTERIA_SRC="$XRAY_JSON_CONFIG"
    fi
  elif grep -qiE '^[[:space:]]*server:[[:space:]]*[^[:space:]]' "$XRAY_JSON_CONFIG" 2>/dev/null \
       && grep -qiE '^[[:space:]]*(auth|obfs|socks5|http|tls|bandwidth|transport):' "$XRAY_JSON_CONFIG" 2>/dev/null; then
    # not valid JSON → a YAML Hysteria2 client config (server:/auth:/socks5:/…)
    HYSTERIA_DETECTED=1; HYSTERIA_SRC="$XRAY_JSON_CONFIG"
  fi
fi
if [ -n "$HYSTERIA_DETECTED" ]; then
  # Derive the server host so DNS (and the egress note) line up with the tunnel.
  if [ -z "${VPN_HOST:-}" ]; then
    case "$HYSTERIA_SRC" in
      hysteria2://*|hy2://*|hysteria://*)
        _hy_hp=${HYSTERIA_SRC#*://}; _hy_hp=${_hy_hp#*@}; _hy_hp=${_hy_hp%%[/?]*} ;;
      *)
        _hy_hp=$(grep -iE '^[[:space:]]*server:' "$HYSTERIA_SRC" 2>/dev/null | head -1 \
                 | sed -E 's/.*server:[[:space:]]*//; s/^["'\'']//; s/["'\'']$//; s/[[:space:]]*#.*$//') ;;
    esac
    _hy_hp=${_hy_hp#*://}; VPN_HOST=$(_safe "${_hy_hp%%:*}"); unset _hy_hp
  fi
  # The Xray probes don't apply — clear the configs so they skip cleanly, and keep
  # the standard suite to the non-misleading probes (TCP/TLS on a UDP/443 server
  # would falsely read "unreachable"). probe_hysteria does the rest.
  XRAY_JSON_CONFIG=""; XRAY_CONFIG=""
  [ -z "${ONLY_PROBES:-}" ] && ONLY_PROBES="env,dns"
fi

# Is --xray-config-json actually an Xray-core config? Xray outbounds carry a
# "protocol" field; sing-box (and other clients) use "type"/"server"/"route".
# Detect a non-Xray config up front so we can say so plainly and skip the
# Xray-protocol probes (11-26) — which would mis-parse it — instead of failing
# confusingly. (Transport probes 0-10 still run against the server below.)
if [ -n "${XRAY_JSON_CONFIG:-}" ] && [ -r "$XRAY_JSON_CONFIG" ] && command -v jq >/dev/null 2>&1; then
  _xouts=$(jq -r '[.outbounds // [] | .[] | select(.protocol != null)] | length' "$XRAY_JSON_CONFIG" 2>/dev/null)
  _alouts=$(jq -r '(.outbounds // []) | length' "$XRAY_JSON_CONFIG" 2>/dev/null)
  if [ "${_xouts:-0}" = "0" ] && [ "${_alouts:-0}" != "0" ]; then
    if jq -e '(.outbounds[0].type != null) or (.route != null) or ((.inbounds // []) | map(.type // "") | any(. == "tun" or . == "mixed"))' \
         "$XRAY_JSON_CONFIG" >/dev/null 2>&1; then
      XRAY_JSON_FORMAT="sing-box"
    else
      XRAY_JSON_FORMAT="non-Xray"
    fi
  fi
  unset _xouts _alouts
fi

# Multi-outbound configs: a config can hold several proxy outbounds (split-tunnel
# routing, balancer fleets). The full-config probe (12) runs them all with routing
# intact; the single-server fingerprint probes (host, cover cert, active-probe,
# TLS-parity, detectability) target ONE. --outbound TAG narrows the config to that
# outbound (chosen + a freedom direct, routing/balancers dropped) so it's tested
# standalone; without it we leave the full config and just hint that there's more
# than one server. Narrowing puts the chosen outbound at index 0, so every existing
# `.outbounds[0]` read and the first-proxy derivation below target it unchanged.
# Initialized HERE (not with the other state at the top of the state block) because
# the --outbound block below sets it while resolving args, which runs BEFORE that
# block — re-initializing it later would clobber the mktemp path and make _cleanup a
# no-op, leaking the narrowed temp config (which holds live creds) on every run.
XRAY_OUTBOUND_PATH=""
if [ -n "${XRAY_JSON_CONFIG:-}" ] && [ -r "$XRAY_JSON_CONFIG" ] && command -v jq >/dev/null 2>&1 \
   && [ -z "${XRAY_JSON_FORMAT:-}" ] && jq empty "$XRAY_JSON_CONFIG" >/dev/null 2>&1; then
  # _safe: outbound tags come from an operator-supplied (or --subscription-fetched)
  # config — strip control/ANSI so a hostile tag can't inject a terminal escape here.
  _proxy_tags=$(_safe "$(jq -r '[.outbounds[]? | select(.settings.vnext != null or .settings.servers != null) | .tag // "(untagged)"] | join(", ")' "$XRAY_JSON_CONFIG" 2>/dev/null)")
  _proxy_n=$(jq -r '[.outbounds[]? | select(.settings.vnext != null or .settings.servers != null)] | length' "$XRAY_JSON_CONFIG" 2>/dev/null)
  _chained=$(jq -r 'if ([.outbounds[]? | select(.streamSettings.sockopt.dialerProxy != null or .proxySettings != null)] | length) > 0 then 1 else 0 end' "$XRAY_JSON_CONFIG" 2>/dev/null)
  if [ -n "$OUTBOUND_TAG" ]; then
    if ! jq -e --arg t "$OUTBOUND_TAG" 'any(.outbounds[]?; .tag == $t and (.settings.vnext != null or .settings.servers != null))' "$XRAY_JSON_CONFIG" >/dev/null 2>&1; then
      die "--outbound '$OUTBOUND_TAG' is not a proxy outbound in this config. Proxy outbounds: ${_proxy_tags:-<none>}"
    fi
    [ "${_chained:-0}" = "1" ] && printf '%s\n' "note: '${OUTBOUND_TAG}' chains outbounds (dialerProxy) — its dialer chain is kept in the narrowed config so the standalone test reflects it (a local dialer must be running, or pass --stub-dialer)" >&2
    XRAY_OUTBOUND_PATH=$(mktemp -t detect_blocking.obsel.XXXXXX) \
      || die "could not create a temp file for --outbound"
    chmod 600 "$XRAY_OUTBOUND_PATH" 2>/dev/null || true
    if jq --arg t "$OUTBOUND_TAG" '
          .outbounds as $all
          | (reduce range(0;6) as $_ ([$t]; . as $have
               | ($have + [ $all[] | select(.tag as $x | ($have | index($x)))
                            | (.streamSettings.sockopt.dialerProxy // empty), (.proxySettings.tag // empty) ] | unique))) as $keep
          | .outbounds = ([ $all[] | select(.tag == $t) ]
              + [ $all[] | select((.tag != $t) and (.tag as $x | ($keep | index($x)))) ]
              + [ {protocol:"freedom", tag:"direct"} ])
          | del(.routing) | del(.balancers)
        ' "$XRAY_JSON_CONFIG" > "$XRAY_OUTBOUND_PATH" 2>/dev/null && [ -s "$XRAY_OUTBOUND_PATH" ]; then
      XRAY_JSON_CONFIG="$XRAY_OUTBOUND_PATH"
      printf '%s\n' "note: --outbound ${OUTBOUND_TAG} — narrowed the config to that outbound (routing dropped) for a standalone test" >&2
    else
      rm -f "$XRAY_OUTBOUND_PATH"; XRAY_OUTBOUND_PATH=""
      die "--outbound: failed to extract outbound '$OUTBOUND_TAG'"
    fi
  elif [ "${_proxy_n:-0}" -gt 1 ]; then
    printf '%s\n' "note: config has ${_proxy_n} proxy outbounds (${_proxy_tags}); the full config is tested as-is (routing intact), and the single-server probes target the first — pass --outbound TAG to focus another" >&2
  fi
  unset _proxy_tags _proxy_n _chained
fi

# Auto-derive VPN_HOST from --xray-config-json when no positional was given.
# Walks the JSON outbounds for the first vless/vmess/trojan/shadowsocks entry
# and uses its destination address. Keeps probes 0-10 aligned with the same
# server the full-config probe will route through (or the first one in a
# load-balanced fleet, which is still informative).
if [ -n "${XRAY_JSON_CONFIG:-}" ] && [ -z "${VPN_HOST:-}" ] && [ -r "$XRAY_JSON_CONFIG" ] && command -v jq >/dev/null 2>&1; then
  _derived_host=$(jq -r '
    .outbounds // []
    | map(select(.protocol == "vless" or .protocol == "vmess" or .protocol == "trojan"))
    | first
    | (.settings.vnext // [])[0].address // empty
  ' "$XRAY_JSON_CONFIG" 2>/dev/null)
  _derived_port=$(jq -r '
    .outbounds // []
    | map(select(.protocol == "vless" or .protocol == "vmess" or .protocol == "trojan"))
    | first
    | (.settings.vnext // [])[0].port // empty
  ' "$XRAY_JSON_CONFIG" 2>/dev/null)
  # Fallback: shadowsocks outbound shape is settings.servers[0].address/port
  if [ -z "$_derived_host" ]; then
    _derived_host=$(jq -r '
      .outbounds // []
      | map(select(.protocol == "shadowsocks"))
      | first
      | (.settings.servers // [])[0].address // empty
    ' "$XRAY_JSON_CONFIG" 2>/dev/null)
    _derived_port=$(jq -r '
      .outbounds // []
      | map(select(.protocol == "shadowsocks"))
      | first
      | (.settings.servers // [])[0].port // empty
    ' "$XRAY_JSON_CONFIG" 2>/dev/null)
  fi
  # Sing-box / non-Xray shape: the outbound carries top-level server/server_port.
  if [ -z "$_derived_host" ] && [ -n "${XRAY_JSON_FORMAT:-}" ]; then
    _derived_host=$(jq -r '.outbounds // [] | map(select(.server != null)) | first | .server // empty' "$XRAY_JSON_CONFIG" 2>/dev/null)
    _derived_port=$(jq -r '.outbounds // [] | map(select(.server != null)) | first | .server_port // empty' "$XRAY_JSON_CONFIG" 2>/dev/null)
  fi
  if [ -n "$_derived_host" ]; then
    _derived_host=$(_safe "$_derived_host"); VPN_HOST="$_derived_host"
    if [ -n "$_derived_port" ] && [ -z "${VPN_PORT_TCP:-}" ]; then
      VPN_PORT_TCP="$_derived_port"
      printf '%s\n' "note: VPN_HOST + VPN_PORT_TCP auto-derived from --xray-config-json → ${_derived_host}:${_derived_port}" >&2
    else
      printf '%s\n' "note: VPN_HOST auto-derived from --xray-config-json → $_derived_host" >&2
    fi
  fi
  unset _derived_host _derived_port
fi

# --ovpn-config FILE: parse an OpenVPN client profile (.ovpn) for the endpoint
# (remote host/port/proto) and its control-channel FINGERPRINTABILITY posture —
# whether the opcode is wrapped so an anonymous active probe is refused (the
# USENIX'22 "OpenVPN is Open to VPN Fingerprinting" attack). Booleans only: the
# profile also carries the server host and inline CA/cert/key/tls-crypt SECRETS,
# which are never printed (host only under --reveal). PEM/key blocks are stripped
# before the directive scan so we never grep into a key. Sets OPENVPN_* + OVPN_*
# (kept by the `:-` state inits) and scopes to env,dns,openvpn when --only is unset.
if [ -n "${OVPN_CONFIG:-}" ]; then
  [ -r "$OVPN_CONFIG" ] || die "--ovpn-config: cannot read '$OVPN_CONFIG'"
  _ovpn_dirs=$(sed -E '/^[[:space:]]*<(ca|cert|key|tls-auth|tls-crypt|tls-crypt-v2)>/,/^[[:space:]]*<\/(ca|cert|key|tls-auth|tls-crypt|tls-crypt-v2)>/d' "$OVPN_CONFIG" 2>/dev/null)
  _r=$(printf '%s\n' "$_ovpn_dirs" | grep -iE '^[[:space:]]*remote[[:space:]]' | head -1)
  _rhost=$(printf '%s' "$_r" | awk '{print $2}')
  _rport=$(printf '%s' "$_r" | awk '{print $3}')
  _pport=$(printf '%s\n' "$_ovpn_dirs" | grep -iE '^[[:space:]]*port[[:space:]]' | head -1 | awk '{print $2}')
  case "$(printf '%s\n' "$_ovpn_dirs" | grep -iE '^[[:space:]]*proto[[:space:]]' | head -1 | awk '{print tolower($2)}')${_r:+ }$(printf '%s' "$_r" | awk '{print tolower($4)}')" in
    *tcp*) OVPN_PROTO=tcp ;;
    *)     OVPN_PROTO=udp ;;   # OpenVPN default is udp
  esac
  _oport="${_pport:-${_rport:-1194}}"; case "$_oport" in ''|*[!0-9]*) _oport=1194 ;; esac
  if grep -iqE '^[[:space:]]*tls-crypt(-v2)?[[:space:]]|^[[:space:]]*<tls-crypt(-v2)?>' "$OVPN_CONFIG" 2>/dev/null; then OVPN_TLS_CRYPT=1; else OVPN_TLS_CRYPT=0; fi
  if grep -iqE '^[[:space:]]*tls-auth[[:space:]]|^[[:space:]]*<tls-auth>' "$OVPN_CONFIG" 2>/dev/null; then OVPN_TLS_AUTH=1; else OVPN_TLS_AUTH=0; fi
  if printf '%s\n' "$_ovpn_dirs" | grep -iqE '^[[:space:]]*(scramble|xormask|xor-?patch|obfuscate)'; then OVPN_OBFS=1; else OVPN_OBFS=0; fi
  OPENVPN_HOST=$(_safe "${_rhost:-${VPN_HOST:-}}")
  OPENVPN_PORT_UDP="$_oport"; OPENVPN_PORT_TCP="$_oport"
  [ -z "${VPN_HOST:-}" ] && [ -n "$_rhost" ] && VPN_HOST=$(_safe "$_rhost")
  [ -z "${ONLY_PROBES:-}" ] && ONLY_PROBES="env,dns,openvpn"
  printf '%s\n' "note: --ovpn-config parsed — OpenVPN endpoint on ${OVPN_PROTO}/${_oport}; posture tls-crypt=${OVPN_TLS_CRYPT} tls-auth=${OVPN_TLS_AUTH} obfs=${OVPN_OBFS} (inline CA/cert/key/tls-crypt secrets are never printed)" >&2
  unset _ovpn_dirs _r _rhost _rport _pport _oport
fi

# --port-survey: curated list of common alt-VPN/proxy ports, merged into
# COMPARE_PORT so the compare matrix picks them up. Doesn't override an
# explicit --compare-port, just extends it.
if [ "$PORT_SURVEY" = "1" ]; then
  _common_alt_ports="8443 2083 2087 2053 8388 4443 9443 51820 1194 500"
  if [ -z "$COMPARE_PORT" ]; then
    COMPARE_PORT=$(printf '%s' "$_common_alt_ports" | tr ' ' ',')
  else
    COMPARE_PORT="${COMPARE_PORT},$(printf '%s' "$_common_alt_ports" | tr ' ' ',')"
  fi
  unset _common_alt_ports
fi

# Filter --watch / --from-file out of $_ORIGINAL_ARGS for child invocations.
# Used by batch & watch loop drivers to avoid recursing into themselves.
_args_without_loop_flags() {
  local skip_next=0 a
  for a in "${_ORIGINAL_ARGS[@]:-}"; do
    if [ "$skip_next" = "1" ]; then skip_next=0; continue; fi
    case "$a" in
      --watch|--from-file) skip_next=1 ;;
      --watch=*|--from-file=*) : ;;
      *) printf '%s\n' "$a" ;;
    esac
  done
}

# ---------- batch driver: --from-file FILE ----------
# Iterates over host lines, invokes ourselves once per host. Set _BATCH_CHILD=1
# in env so the child doesn't recurse. JSON-mode output is compacted to one
# line per host (ndjson) for stream-processing.
if [ -n "$BATCH_FILE" ] && [ "${_BATCH_CHILD:-0}" != "1" ]; then
  [ -r "$BATCH_FILE" ] || die "--from-file: cannot read $BATCH_FILE"

  # Cache filtered args once (array form, NUL-safe via newline split).
  _batch_args=()
  while IFS= read -r _ba; do
    _batch_args+=("$_ba")
  done < <(_args_without_loop_flags)

  _batch_rc=0
  while IFS= read -r _bh || [ -n "$_bh" ]; do
    case "$_bh" in ''|\#*) continue ;; esac
    if [ "$JSON_MODE" = "1" ]; then
      _BATCH_CHILD=1 bash "$0" "${_batch_args[@]:-}" "$_bh" | jq -c .
    else
      _BATCH_CHILD=1 bash "$0" "${_batch_args[@]:-}" "$_bh"
    fi
    rc=$?
    [ "$rc" -ne 0 ] && _batch_rc=$rc
  done < "$BATCH_FILE"
  exit "$_batch_rc"
fi

# ---------- watch driver: --watch SECONDS ----------
# Re-invokes ourselves on a fixed cadence until SIGINT/SIGTERM. Same recursion
# guard as batch via _WATCH_CHILD=1.
if [ -n "$WATCH_INTERVAL" ] && [ "${_WATCH_CHILD:-0}" != "1" ]; then
  case "$WATCH_INTERVAL" in
    ''|*[!0-9]*) die "--watch: SECONDS must be a positive integer" ;;
  esac
  [ "$WATCH_INTERVAL" -gt 0 ] || die "--watch: SECONDS must be >0"

  _watch_args=()
  while IFS= read -r _wa; do
    _watch_args+=("$_wa")
  done < <(_args_without_loop_flags)

  trap 'exit 0' INT TERM
  while true; do
    if [ "$JSON_MODE" = "1" ]; then
      _WATCH_CHILD=1 bash "$0" "${_watch_args[@]:-}" | jq -c .
    else
      _WATCH_CHILD=1 bash "$0" "${_watch_args[@]:-}"
      printf '\n--- next run in %ss (Ctrl-C to stop) ---\n' "$WATCH_INTERVAL"
    fi
    sleep "$WATCH_INTERVAL"
  done
fi

# Probe gate: --only takes precedence over --skip; comma-separated lists.
_should_run() {
  local name="$1"
  if [ -n "$ONLY_PROBES" ]; then
    case ",$ONLY_PROBES," in *,"$name",*) return 0 ;; *) return 1 ;; esac
  fi
  if [ -n "$SKIP_PROBES" ]; then
    case ",$SKIP_PROBES," in *,"$name",*) return 1 ;; esac
  fi
  return 0
}

# ---------- config defaults ----------

# IANA-reserved real domain. Resolves, always reachable, no association with
# any VPN product — acts as a working demo target so a no-arg run produces a
# clean "no blocking signals" baseline. Override with a real VPN endpoint via
# CLI arg, env var, or detect_blocking.conf.
VPN_HOST="${VPN_HOST:-www.example.com}"
VPN_PORT_TCP="${VPN_PORT_TCP:-443}"
VPN_PORT_UDP="${VPN_PORT_UDP:-443}"

# IPv6-literal endpoints: parsing now handles them, probes that pass host+port
# separately (nc) or split on the last colon (openssl) work, and URL-building
# brackets them — but full support is best-effort, so flag it once up front.
case "$VPN_HOST" in
  *:*:*) printf '%s\n' "note: IPv6-literal endpoint (${VPN_HOST}) — probe support is best-effort; if a probe misbehaves, pass a hostname or use --xray-config-json" >&2 ;;
esac
IKEV2_HOST="${IKEV2_HOST:-$VPN_HOST}"
OPENVPN_HOST="${OPENVPN_HOST:-$VPN_HOST}"
OPENVPN_PORT_UDP="${OPENVPN_PORT_UDP:-1194}"
OPENVPN_PORT_TCP="${OPENVPN_PORT_TCP:-1194}"

BASELINE_DOMAIN="${BASELINE_DOMAIN:-cloudflare.com}"
XRAY_QUIC_BASELINE="${XRAY_QUIC_BASELINE:-cloudflare-quic.com}"   # known QUIC host for the UDP/443 reachability baseline
BASELINE_IPS="${BASELINE_IPS:-${BASELINE_IP:-1.1.1.1} 8.8.8.8 9.9.9.9}"

FAKE_SNI="${FAKE_SNI:-www.microsoft.com}"
CONTROL_SITES="${CONTROL_SITES:-www.protonvpn.com www.torproject.org www.discord.com}"
# Whitelist-restriction probe: "permitted-class" hosts (large public services that a
# restricted mobile path typically still permits) vs neutral controls (ordinary global
# hosts that a captive path drops). Both lists are public services — never infra.
WHITELIST_HOSTS="${WHITELIST_HOSTS:-vk.com mts.ru}"
WHITELIST_CONTROL_HOSTS="${WHITELIST_CONTROL_HOSTS:-www.example.com github.com}"
DOH_URL="${DOH_URL:-https://1.1.1.1/dns-query}"
DOH_PROVIDERS="${DOH_PROVIDERS:-https://1.1.1.1/dns-query https://dns.google/dns-query https://dns.quad9.net/dns-query}"
TIMEOUT="${TIMEOUT:-5}"

# When 0 (default): OpenVPN handshake silence is reported as INCONCLUSIVE
# (could be DPI, but also tls-auth/tls-crypt or non-OpenVPN service on that port).
# Set to 1 to emit a hard verdict on silence — only when you're certain the
# service is plain OpenVPN.
STRICT_OPENVPN_VERDICT="${STRICT_OPENVPN_VERDICT:-0}"

# ---------- state (init so set -u doesn't fire when a probe is skipped) ----------

RESOLVED_IP=""
RESOLVED_SOURCE=""
TCP_OK=0
TCP_TESTED=0        # 1 once probe 2 actually ran — so "never measured" ≠ "measured unreachable"
# --label NAME: a free-text vantage name stamped into --json and shown in the baseline
# diff header. Pairs with .environment.default_interface so a saved run is
# self-describing ("which network was this?") — the point of comparing e.g. an LTE run
# against a Wi-Fi run of the same endpoint.
RUN_LABEL="${RUN_LABEL:-}"
WHITELIST_STATUS=""          # open | restricted | permitted-unreachable | no-network
WHITELIST_PERMITTED_OK=""    # how many permitted-class hosts answered TCP 443
WHITELIST_CONTROL_OK=""      # how many neutral controls answered TCP 443
TARGET_ICMP_OK=""   # 1/0/"" — did the target answer ICMP when TCP 80+443 both failed
OPENVPN_UDP_OK=0
OPENVPN_TCP_OK=0
DOH_INTEGRITY_STATE=""   # one of: "", ok, unreachable, compromised
DOH_INTEGRITY_IPS=""     # what DoH returned for the canary query
DOT_INTEGRITY_STATE=""   # one of: "", ok, unreachable, compromised, skipped
DOT_INTEGRITY_IPS=""     # what DoT returned for the canary query
DOH_MULTI_RESULTS=""     # one " url|state|ips" entry per checked provider
DOH_MULTI_OK=0           # how many providers returned the canonical answer
DOH_MULTI_COMPROMISED=0  # how many returned wrong IPs
DOH_MULTI_UNREACHABLE=0  # how many failed to respond
RST_TMP_OUT=""           # probe-5 temp files; cleaned by EXIT trap on interrupt
RST_TMP_TIME=""

# Structured probe results captured for --json output.
# Each var is initialised so set -u doesn't fire when a probe is skipped.
ENV_DEFAULT_IF=""
ENV_VPN_IFACES=""
ENV_CONNECTED_VPN=""
ENV_ON_VPN=0
DNS_SYS_IPS=""
DNS_DOH_IPS=""
DNS_DIVERGE_CLASS=""     # on system-vs-DoH IP divergence: dns-block|system-ok|both-fail|unchecked
DNS_BLOCK=0              # 1 = system-DNS IP is a dead TLS stub while the DoH IP serves the site
TCP_BASELINE_OK=0
TCP_BASELINE_IP=""
TLS_PROPER_SNI_OK=0
TLS_NO_SNI_OK=0
TLS_FAKE_SNI_OK=0
TLS_FRAG_SNI_OK=-1       # -1 = not tested (proper-SNI worked, no need to probe fragmentation)
UA_DEFAULT_CODE=""
UA_CHROME_CODE=""
UA_IMPERSONATE_CODE=""
UA_IMPERSONATE_BIN=""
RST_ELAPSED=""
RST_HS_OK=0
RST_RC=0
UDP_IKE500_OK=0
UDP_IKE4500_OK=0
UDP_QUIC_CODE=""
UDP_QUIC_BASELINE=""    # QUIC VN result for the known baseline host (vn/response/silent/error/no-perl)
UDP_QUIC_TARGET=""      # QUIC VN result for the target (Hysteria2 server); "" when no UDP endpoint to test
UDP_QUIC_VERDICT=""     # net-blocked / net-ok / target-quic / net-ok-target-silent
OPENVPN_HANDSHAKE=""     # raw 2-hex-byte response or empty
OPENVPN_HS_REPLIED=0     # 1 when the server answered the anonymous reset (opcode 0x40)
# OpenVPN posture from --ovpn-config (parsed EARLIER, before this block) — `:-` so we
# keep the parsed values and don't clobber them (see the v1.5.2 --outbound leak fix).
OVPN_CONFIG="${OVPN_CONFIG:-}"           # path to a .ovpn profile, if given
OVPN_PROTO="${OVPN_PROTO:-}"             # tcp | udp (generic; from the profile)
OVPN_TLS_CRYPT="${OVPN_TLS_CRYPT:-}"     # 1 | 0 | "" (unknown — no config)
OVPN_TLS_AUTH="${OVPN_TLS_AUTH:-}"       # 1 | 0 | ""
OVPN_OBFS="${OVPN_OBFS:-}"               # 1 | 0 | "" (scramble/xor/obfs fork)
OVPN_POSTURE="${OVPN_POSTURE:-}"         # wrapped|probe-resistant|hmac-only|exposed
OVPN_FINGERPRINTABLE="${OVPN_FINGERPRINTABLE:-}"  # yes|partial|no|""
# VPN tunnel effectiveness (probe runs when the default route is a tunnel, or --via-tunnel)
VIA_TUNNEL="${VIA_TUNNEL:-0}"            # 1 = force the tunnel probe even without a tunnel default route
TUNNEL_STATUS=""                         # no-tunnel|captured|leak|captured-unverified|no-exit|skipped
TUNNEL_DEFAULT_IS_TUN=0                  # 1 = default route egresses via a utun/tun/ppp/wg iface
TUNNEL_EXIT_CC=""                        # ISO country of the egress seen THROUGH the tunnel
TUNNEL_EXIT_DIFFERS=""                   # 1 tunnel changes egress · 0 same (leak) · "" unverified
# Censorship localization (where does the block sit?) — auto-runs when the target is
# TCP-unreachable, or forced with --localize. Bounded traceroute + ASN/geo of the last hop.
LOCALIZE="${LOCALIZE:-0}"                 # 1 = force the localization probe
LOCALIZE_STATUS=""                       # ran|ipv6-skip|no-traceroute|"" (not run)
LOCALIZE_CLASS=""                        # endpoint|access-edge|transit|near-destination|unknown
LOCALIZE_LAST_HOP=""                     # hop number of the last responding hop
LOCALIZE_LAST_ASN=""                     # ASN of that hop
LOCALIZE_LAST_CC=""                      # country of that hop
LOCALIZE_REACHED=""                      # 1 = traceroute reached the target IP · 0 = died earlier
CONTROL_PASS=0
CONTROL_TOTAL=0
CONTROL_BLOCKED=""
IPV6_AAAA=""
IPV6_TARGET_OK=0
IPV6_HTTPS_CODE=""
XRAY_TESTER_BIN=""       # discovered binary (xray-knife / xray / sing-box)
XRAY_STATUS=""           # one of "", ok, failed, unavailable, no-config
XRAY_RTT_MS=""           # parsed end-to-end RTT in milliseconds
XRAY_TARGET_IP=""        # echoed Real IP from delegation output
XRAY_TARGET_LOC=""       # echoed location (country) from delegation output
XRAY_URL_DISPLAY=""      # creds-masked URL for human-readable / JSON output
XRAY_FAIL_KIND=""        # on failure: timeout | reset | other (drives verdict)
XRAY_RETRY_USED=0        # 1 if the slow-handshake auto-retry ran

# --xray-config-json (probe 12) state vars
XRAY_JSON_STATUS=""      # ok, failed, xray-missing, jq-missing, no-outbound, config-missing,
                         # config-malformed, no-port, xray-bind-failed, no-config
XRAY_JSON_SOCKS_PORT=""  # actual port the patched config binds (random high)
XRAY_JSON_EGRESS_IP=""   # ip= line from cloudflare trace
XRAY_JSON_EGRESS_LOC=""  # colo= line from cloudflare trace (e.g. AMS, FRA)
XRAY_JSON_RTT_MS=""      # round-trip via the SOCKS tunnel
XRAY_JSON_FAIL_KIND=""   # on failure: timeout | reset | other (drives verdict)
XRAY_JSON_RETRY_USED=0   # 1 if the slow-handshake auto-retry ran
XRAY_JSON_SYNTH_PATH=""  # temp config synthesized from --xray-config URL (cleaned on exit)
# XRAY_OUTBOUND_PATH is initialized EARLIER (before the --outbound block) on purpose —
# see the note there. Do NOT re-init it here; that clobbers the temp path and leaks it.
XRAY_JSON_FROM_URL=0     # 1 when probe 12 ran off a synthesized share-link config

# ---- probe 13: data-plane throughput through the same SOCKS inbound ----
XRAY_THROUGHPUT_STATUS=""   # ok, throttled-severe, throttled-mild, broken, skipped, curl-missing
XRAY_THROUGHPUT_BPS=""      # bytes/sec averaged over the download window
XRAY_THROUGHPUT_BYTES=""    # bytes actually received before EOF / timeout
XRAY_THROUGHPUT_TIME_S=""   # wall-clock seconds the download window spanned
XRAY_THROUGHPUT_TARGET_BYTES="${XRAY_THROUGHPUT_TARGET_BYTES:-10485760}"  # 10 MB default
XRAY_THROUGHPUT_TIMEOUT="${XRAY_THROUGHPUT_TIMEOUT:-20}"                  # seconds
XRAY_THROUGHPUT_URL="${XRAY_THROUGHPUT_URL:-https://speed.cloudflare.com/__down}"

# ---- probe 14: multi-stream / multi-endpoint capacity estimate (opt-in) ----
# Probe 13 is a single-stream shaping FLOOR detector; on a high-RTT tunnel a
# single TCP stream is window-limited and badly under-reports real capacity.
# Probe 14 runs N parallel streams (like a real speedtest) against several
# public CDN backends and reports the best aggregate — the closest honest
# estimate of usable tunnel bandwidth. Opt-in (downloads tens of MB).
XRAY_SPEEDTEST="${XRAY_SPEEDTEST:-1}"                       # 1 = run by default (--no-speedtest opts out)
XRAY_SPEEDTEST_FORCE="${XRAY_SPEEDTEST_FORCE:-0}"           # 1 = run even inside --watch / --from-file loops
XRAY_SPEEDTEST_STREAMS="${XRAY_SPEEDTEST_STREAMS:-4}"       # parallel streams per endpoint
XRAY_SPEEDTEST_MAX_BYTES="${XRAY_SPEEDTEST_MAX_BYTES:-52428800}"  # ~50 MB total budget
XRAY_SPEEDTEST_SECONDS="${XRAY_SPEEDTEST_SECONDS:-5}"       # download window AFTER handshake (per stream)
# Endpoints as space-separated name|url|mode triples. mode=cf → append
# ?bytes=N (Cloudflare); mode=range → cap bytes with an HTTP Range header.
XRAY_SPEEDTEST_URLS="${XRAY_SPEEDTEST_URLS:-cloudflare|https://speed.cloudflare.com/__down|cf datapacket|https://lon.download.datapacket.com/100mb.bin|range ovh|https://proof.ovh.net/files/100Mb.dat|range}"
XRAY_SPEEDTEST_STATUS=""    # ok, skipped, disabled, curl-missing, no-result
XRAY_SPEEDTEST_BEST_BPS=""  # best aggregate bytes/sec across endpoints
XRAY_SPEEDTEST_BEST_NAME="" # endpoint name that produced the best aggregate
XRAY_SPEEDTEST_RESULTS=""   # "name|bps name|bps ..." for JSON / reporting

# ---- probe 15: Reality cover authenticity ----
# A working Reality server relays UNAUTHENTICATED clients (plain TLS, like a
# censor's active probe) to the genuine cover site, so they see a real
# CA-valid cert. A self-signed / mismatched cert means the cover is fake and
# trivially fingerprintable. Output is booleans only — never the cover domain.
XRAY_COVER_STATUS=""        # ok, fake, mismatch, unreachable, skipped, no-sni, openssl-missing
XRAY_COVER_SELFSIGNED=""    # 1 / 0 / "" (issuer == subject)
XRAY_COVER_CHAIN_VALID=""   # 1 / 0 / "" (openssl verify return code 0)
XRAY_COVER_CN_MATCH=""      # 1 / 0 / "" (cert CN/SAN covers the configured serverName)

# ---- probe 16: egress integrity (geo / reputation / DNS) ----
# Runs through the probe-12 tunnel. Reports geo + datacenter/proxy flags so
# you know if the egress is already on the "this is a VPN" lists that streaming
# / banking services block. Sends the egress IP to a 3rd-party IP-info service
# — disable with --no-egress-check. Output: country code + flags, never the IP.
XRAY_EGRESS_CHECK="${XRAY_EGRESS_CHECK:-1}"                 # 1 = run (--no-egress-check opts out)
XRAY_EGRESS_INFO_URL="${XRAY_EGRESS_INFO_URL:-http://ip-api.com/json/?fields=status,countryCode,hosting,proxy,mobile,query}"
XRAY_EGRESS_DNS_URL="${XRAY_EGRESS_DNS_URL:-http://edns.ip-api.com/json}"
# Fallback reputation source with an explicit datacenter / proxy / ASN-type flag
# (the ipinfo/ipwho.is/ifconfig ASN pool has none). Queried through the tunnel
# when ip-api's flags are unavailable (rate-limited), so reputation isn't "n/a".
XRAY_EGRESS_DC_URL="${XRAY_EGRESS_DC_URL:-https://api.ipapi.is/}"
XRAY_EGRESS_STATUS=""       # ok, partial (geo only, no flags), skipped, disabled, curl-missing, no-data
XRAY_EGRESS_COUNTRY=""      # ISO country code seen at the egress
XRAY_EGRESS_HOSTING=""      # 1 / 0 — ip-api: datacenter / hosting IP
XRAY_EGRESS_PROXY=""        # 1 / 0 — ip-api: on a proxy blocklist
XRAY_EGRESS_MOBILE=""       # 1 / 0 — ip-api: mobile carrier IP
XRAY_EGRESS_ASN_HOSTING=""  # 1 / 0 — 2nd source: ASN/org looks like a hosting provider
XRAY_EGRESS_DC=""           # 1 / 0 — 3rd source (fallback): datacenter / hosting-type ASN
XRAY_EGRESS_COLOCATED=""    # same-/24 / same-ASN / different — is the egress co-located with the entry?
XRAY_EGRESS_DNS_COUNTRY=""  # country of the DNS resolver seen through the tunnel (informational)

# ---- cover-SNI scanner (--scan-covers): rank candidate Reality dest/serverNames ----
# A good Reality cover is a foreign site that supports TLSv1.3 + HTTP/2, serves
# real content (no redirect), and has a CA-valid cert. This scans a candidate
# list for those properties so the operator can pick a dest — the diagnostic
# counterpart to "your cover is self-owned/obscure". Opt-in (it probes the
# candidates directly). Default list = neutral, globally-popular CDN/cloud sites.
XRAY_SCAN_COVERS="${XRAY_SCAN_COVERS:-}"   # "" off; "default"/"1" built-in list; or a comma-separated list
PANEL_PROBE="${PANEL_PROBE:-}"             # --panel-probe [IP]: audit an origin IP for an exposed x-ui/3x-ui panel
XRAY_COVER_CANDIDATES="${XRAY_COVER_CANDIDATES:-www.microsoft.com www.apple.com dl.google.com www.amazon.com www.cloudflare.com www.bing.com}"
XRAY_COVER_SCAN_STATUS=""   # ok / skipped
XRAY_COVER_SCAN_BEST=""     # best-ranked candidate domain
XRAY_COVER_SCAN_RESULTS=""  # newline-joined "domain|tls13|h2|cavalid|nonredirect|verdict" for JSON

# ---- connection-limit probe (--conn-test N): server robustness under concurrency ----
# Opt-in. Opens N simultaneous TLS handshakes to the server and reports how many
# complete + the handshake-time spread — i.e. does the server CAP / rate-limit /
# degrade under concurrent connections (a robustness/UX signal, not a censorship one).
# On by default at a modest 8 concurrent handshakes: it probes only the TARGET (your own
# endpoint), runs them concurrently (≈ one probe's worth of wall-clock) and catches
# connection-limit shaping. `-` not `:-` so --no-conn-test (which sets "") survives this
# init, exactly like YT_TEST_N. "" = off; --conn-test N raises it (clamped 1..128).
CONN_TEST_N="${CONN_TEST_N-8}"
CONN_LIMIT_STATUS=""             # disabled / ok / unreachable / curl-missing / error
CONN_LIMIT_REQUESTED=""; CONN_LIMIT_SUCC=""; CONN_LIMIT_FAIL=""
CONN_LIMIT_MINMS=""; CONN_LIMIT_MAXMS=""; CONN_LIMIT_VERDICT=""

# ---- YouTube reachability-under-fan-out (--yt-test N): real-destination concurrency ----
# Opt-in TUNNEL probe. Opens N concurrent connections THROUGH the tunnel to real
# YouTube-infra hosts (the multi-origin fan-out actual playback generates) and reports
# how many complete + TTFB spread — empirically confirms YouTube works through this
# egress under load, vs probe 16 which only INFERS it from the egress IP reputation.
# Egress-quality / QoE signal, not a censorship-of-the-VPN one.
# NOTE: '-' (not ':-') so --no-yt-test, which sets YT_TEST_N="" BEFORE this default
# runs, SURVIVES — ':-' would treat the empty value as unset and re-enable it.
YT_TEST_N="${YT_TEST_N-6}"       # default 6 concurrent conns (on by default for tunnel runs); "" = off (--no-yt-test); clamped 1..128
YT_TEST_FORCE="${YT_TEST_FORCE:-0}"  # 1 = run even inside --watch / --from-file loops (set by explicit --yt-test)
XRAY_YT_HOSTS="${XRAY_YT_HOSTS:-www.youtube.com youtubei.googleapis.com i.ytimg.com yt3.ggpht.com}"
YT_REACH_STATUS=""               # disabled / ok / skipped / curl-missing / error
YT_REACH_REQUESTED=""; YT_REACH_SUCC=""; YT_REACH_FAIL=""
YT_REACH_MINMS=""; YT_REACH_MAXMS=""; YT_REACH_VERDICT=""

# ---- censored-URL sweep (--censor-sweep): OONI-style reachability, direct vs tunnel ----
# Tests a list of commonly-censored hosts DIRECT and (when the tunnel is up)
# THROUGH it, classifying each: reachable-both / blocked-direct-but-tunnel-carries
# (the tunnel is doing its job) / direct-only-not-carried (routing/proxy fault) /
# blocked-both. Reuses _url_reachable + the SOCKS-through-tunnel path. Opt-in.
XRAY_CENSOR_SWEEP="${XRAY_CENSOR_SWEEP:-}"   # "" off; "default"/"1" built-in list; or comma-separated hosts
XRAY_CENSOR_URLS="${XRAY_CENSOR_URLS:-www.bbc.com www.wikipedia.org www.torproject.org www.youtube.com x.com www.reddit.com}"
XRAY_CENSOR_SWEEP_STATUS=""   # ok / skipped
XRAY_CENSOR_SWEEP_TUNNEL=""   # 1 / 0 — whether the through-tunnel pass ran
XRAY_CENSOR_SWEEP_RESULTS=""  # newline-joined "host|direct|tunnel|verdict" for JSON

# ---- probe 17: held-session stability (delayed-RST / volumetric kill-shaping) ----
# Short bursts (13/14) miss the censor tactic of letting the handshake through
# then RST-ing the proven tunnel. Probe 17 pulses an ESCALATING SIZE LADDER
# (tiny → 4 MB) and classifies each pulse by curl exit code: ok / slow-timeout
# / killed-reset. A reset that appears only on the larger pulses is the
# volumetric-shaping signature (small flows allowed, big flows dropped) — which
# trace-only pulses can never reveal. Runs by default; --no-stability opts out;
# auto-skips inside --watch/--from-file loops, --stability forces it there.
XRAY_STABILITY="${XRAY_STABILITY:-1}"                      # 1 = run by default (--no-stability opts out)
XRAY_STABILITY_FORCE="${XRAY_STABILITY_FORCE:-0}"         # 1 = run even inside --watch/--from-file loops
XRAY_STABILITY_SECONDS="${XRAY_STABILITY_SECONDS:-45}"    # overall wall-clock cap for the ladder
XRAY_STABILITY_INTERVAL="${XRAY_STABILITY_INTERVAL:-2}"  # brief pause between pulses
# Pulse size ladder (bytes; 0 = tiny trace request). Escalates to expose kills
# that only trigger past a byte threshold.
XRAY_STABILITY_SIZES="${XRAY_STABILITY_SIZES:-0 262144 1048576 4194304}"
XRAY_STABILITY_STATUS=""    # ok, killed, transient, slow, unstable, skipped, disabled, curl-missing
XRAY_STABILITY_TOTAL=""     # pulses attempted
XRAY_STABILITY_OK=""        # pulses that succeeded
XRAY_STABILITY_KILLED=""    # pulses dropped by a reset-class error (the real kill signal)
XRAY_STABILITY_SLOW=""      # pulses that timed out (slow, not killed)
XRAY_STABILITY_RETRIED=""   # pulses that reset once but PASSED on the inline retry (transient blips, not counted as kills)
XRAY_STABILITY_KILL_BYTES="" # byte size of the first killed pulse
XRAY_STABILITY_FIRST_FAIL_S=""  # seconds into the run when the first non-ok pulse hit
XRAY_STABILITY_RTT_MIN=""   # ms (over ok pulses)
XRAY_STABILITY_RTT_MAX=""   # ms (over ok pulses)
XRAY_STABILITY_RESULTS=""   # "size|state|rtt ..." for JSON

# ---- probe 18: config pre-flight lint (static, no network) ----
# Validates the parsed config for common Reality/VLESS misconfigs BEFORE the
# network probes, so an obvious typo surfaces in milliseconds instead of
# masquerading as DPI. Findings name the protocol knob, never the secret value.
XRAY_LINT_STATUS=""         # ok, warn, skipped
XRAY_CONFIG_VALID=""        # 1 / 0 / "" — config loads in xray-core (dup tags / string ports / xray -test)
XRAY_LINT_FINDINGS=""       # newline-joined short codes for JSON
XRAY_FET_EXPOSED=""         # 1 / 0 / "" — fully-encrypted (no TLS/HTTP framing) → GFW entropy classifier (USENIX'23)
XRAY_VLESS_ENC=""           # none | native | xorpub | random | invalid | "" — VLESS Encryption method (mlkem768x25519plus.*, Xray 2025+)
XRAY_VLESS_ENC_PADDING=""   # 1 / 0 / "" — VLESS Encryption has padding/delay blocks (anti flow-shape analysis)
XRAY_VLESS_FLOW_DEPRECATED="" # 1 / 0 / "" — VLESS without flow= (deprecated upstream, XTLS/Xray-core #5568)
XRAY_DIALER_PROXY=""        # the sockopt.dialerProxy tag the proxy dials through (or "")
XRAY_DESYNC_CHAIN=""        # 1 / 0 / "" — dialerProxy points at a LOCAL socks/http = client-side desync layer (ByeDPI/zapret/GoodbyeDPI)
XRAY_ID_UUID=""             # 1 / 0 / "" — client id is a canonical UUID (vs a hand-assigned/non-UUID string; share-safe: format only)

# ---- probe 19: clock skew (Reality auth is time-windowed) ----
# A client clock off by minutes makes the Reality handshake fail in a way that
# looks exactly like a fingerprint block. Compare local time to a server Date.
XRAY_CLOCK_STATUS=""        # ok, skew, unknown, skipped
XRAY_CLOCK_SKEW_S=""        # signed seconds (local - server)

# ---- probe 20: active-probe resistance ----
# Probe 15 checks the cover CERT; a real censor also checks the cover
# BEHAVIOUR. Send a real HTTPS request to the server using the cover SNI and
# compare the response to the genuine cover site fetched out-of-band. A real
# Reality server relays unauth clients to dest → matching response; a fake one
# returns an error / empty / mismatch. Output: match boolean + status codes.
XRAY_ACTIVE_STATUS=""       # ok, exposed, mismatch, skipped, no-sni, curl-missing, no-baseline
XRAY_ACTIVE_RELAY_CODE=""   # HTTP code seen via the server (unauth)
XRAY_ACTIVE_REAL_CODE=""    # HTTP code from the genuine cover site
XRAY_ACTIVE_MATCH=""        # 1 / 0

# ---- probe 21: per-outbound fleet health matrix (auto on multi-outbound) ----
# For balancer / multi-outbound configs, tunnel-test each outbound and print a
# health table (tag | tunnel | RTT) — N xray spawns. Auto-enables when the JSON
# config has >1 proxy outbound; silent for single-outbound / URL configs.
# --no-fleet disables; --fleet forces it inside --watch/--from-file loops. The
# table shows operator-defined tags only, never addresses or ports.
XRAY_FLEET="${XRAY_FLEET:-1}"        # 1 = auto (self-gates to multi-outbound); 0 = off
XRAY_FLEET_FORCE="${XRAY_FLEET_FORCE:-0}"  # 1 = run even inside --watch / --from-file loops
XRAY_FLEET_STATUS=""        # ok, skipped, disabled, xray-missing, jq-missing, single, no-outbounds
XRAY_FLEET_TOTAL=""         # outbounds tested
XRAY_FLEET_OK=""            # outbounds whose tunnel reached egress
XRAY_FLEET_RESULTS=""       # "tag|state|rtt ..." for JSON

# Routing-coverage probe (split-tunnel): static map+lint, plus a live test when
# the tunnel is up. Set in probe_xray_routing.
XRAY_ROUTING_STATUS=""      # ok, skipped, none, jq-missing
XRAY_ROUTING_DEFAULT=""     # the effective default-route outbound tag
XRAY_ROUTING_UNDEF=""       # outboundTags referenced in rules but not defined
XRAY_ROUTING_PROXY_TAGS=""  # proxy outbound tags that routing sends traffic to
XRAY_ROUTING_LIVE=""        # live split-tunnel test: ok / skipped / partial / failed
XRAY_ROUTING_LIVE_RESULTS="" # "target|state ..." for JSON
XRAY_ROUTING_PID=""         # xray pid for the live test (EXIT-cleaned)
XRAY_ROUTING_DOMAINSTRATEGY="" # routing.domainStrategy (AsIs / IPIfNonMatch / IPOnDemand)
XRAY_ROUTING_DNS_RISK=""    # 1 / 0 — domainStrategy resolves domains locally with no dns block (leak)
XRAY_ROUTING_SNIFF=""       # 1 / 0 — an inbound has sniffing.enabled (domain rules match on the SNI, no local lookup)
XRAY_ROUTING_PROXY_SENSITIVE="" # csv of sensitive categories routed to the proxy (streaming / payment) — cross-checked vs egress reputation
XRAY_ROUTING_DNS_SPLIT=""   # 1 / 0 — dns block uses per-domain servers (split-horizon: tunneled foreign + local domestic); "" when no dns block

# ---- probe 22: bufferbloat / latency-under-load ----
# 13/14 measure bandwidth; this measures the latency a "fast" tunnel adds while
# saturated — the thing that makes calls/gaming laggy. Warm RTT (keep-alive, so
# the handshake is paid once and excluded) idle vs under a saturating download.
XRAY_BUFFERBLOAT="${XRAY_BUFFERBLOAT:-1}"  # 1 = run (--no-bufferbloat opts out)
XRAY_BUFFERBLOAT_STATUS=""  # ok, moderate, heavy, skipped, disabled, curl-missing, no-data
XRAY_BUFFERBLOAT_IDLE_MS="" # warm RTT idle
XRAY_BUFFERBLOAT_LOAD_MS="" # warm RTT under saturating download
XRAY_BUFFERBLOAT_INFLATE_MS="" # load - idle (the queueing delay added under load)
XRAY_BUFFERBLOAT_JITTER_MS=""  # spread of loaded samples

# ---- probe 23: path MTU to the server ----
# A clamped path MTU fragments the Reality ClientHello and causes intermittent
# handshake failures that look like flaky DPI. DF-bit ping sweep finds it.
XRAY_MTU_STATUS=""          # ok, clamped, filtered, skipped, no-ping
XRAY_MTU_PATH=""            # discovered path MTU (bytes)

# ---- probe 24: TLS-negotiation parity (stealth depth-3) ----
# 15 checks the cover cert, 20 the cover HTTP behaviour; this checks the TLS
# NEGOTIATION (version / ALPN / cipher). A real relaying Reality server is
# byte-identical to the genuine cover; a fake / wrong-dest one diverges.
# Output: per-attribute parity booleans + the generic negotiated values only.
XRAY_TLSPAR_STATUS=""       # ok, mismatch, unverified, skipped, no-sni, openssl-missing, unreachable
XRAY_TLSPAR_VER_MATCH=""    # 1 / 0  TLS version parity
XRAY_TLSPAR_ALPN_MATCH=""   # 1 / 0  ALPN parity
XRAY_TLSPAR_CIPHER_MATCH="" # 1 / 0  cipher parity
XRAY_TLSPAR_EXT_MATCH=""    # 1 / 0  ServerHello extension-set parity (JA3S-grade; -tlsextdebug)
XRAY_TLSPAR_SERVER_ALPN=""  # ALPN the SERVER negotiated (h2 / http/1.1 / "" none) — the HTTP version in use
XRAY_TLSPAR_COVER_ALPN=""   # ALPN the genuine COVER negotiated (compare: a divergence is a prober's tell)
XRAY_TLSPAR_COVER_H3=""     # does the cover domain answer QUIC/HTTP-3 on 443? vn|silent|...
XRAY_TLSPAR_H3_PARITY=""    # ok | cover-only (cover serves h3, this IP does not) | n/a
XRAY_TLSPAR_SERVER_FP=""    # short hash of server ServerHello shape (version|cipher|extensions)
XRAY_TLSPAR_COVER_FP=""     # same, for the genuine cover (compare → does the server impersonate it at the JA3S level?)
# ---- host exposure (whole-host disguise: does the server look like only a web host?) ----
XRAY_HOSTEXP_STATUS=""      # ok / skipped
XRAY_HOSTEXP_OPEN=""        # giveaway ports found open beyond 443 (e.g. "22(SSH), 54321(x-ui-panel)")
XRAY_HOSTEXP_CDN=""         # 1 / 0 / "" — the resolved IP is a CDN edge (panel ports are the CDN's, not the origin)
PANEL_STATUS=""             # --panel-probe: ok / skipped
PANEL_FOUND=""              # 1 / 0 / "" — an x-ui/3x-ui panel was found exposed on the target
# ---- Hysteria2 static analysis (QUIC/UDP — set by probe_hysteria) ----
HYSTERIA_STATUS=""          # ok / skipped
HYSTERIA_SNI_KEYWORD=""     # 1/0 — effective TLS SNI carries a protocol/circumvention keyword
HYSTERIA_SNI_EXPLICIT=""    # 1/0 — an explicit tls.sni is set (vs defaulting to the server hostname)
HYSTERIA_OBFS=""            # 1/0 — obfs (salamander) present in the client config
HYSTERIA_INSECURE=""        # 1/0 — tls.insecure=true (cert verification off)

# ---- probe 25: cover-SNI region-throttle ----
# Automates the real incident: the cover domain itself being shaped in-region,
# which the tunnel silently inherits. Measure a DIRECT bulk fetch from the
# genuine cover vs a neutral baseline from the same vantage; a stark slowdown
# means the cover SNI is throttled here. Output: KB/s + ratio, no domain.
XRAY_COVERTHR_STATUS=""     # ok, throttled, inconclusive, skipped, no-sni, curl-missing
XRAY_COVERTHR_COVER_BPS=""  # bytes/sec fetching the cover root
XRAY_COVERTHR_BASE_BPS=""   # bytes/sec fetching the neutral baseline

# ---- probe 26: detectability score (stealth synthesis) ----
# A censor sees one server, not three findings. Fold the stealth signals
# (cover cert / active-probe / TLS-parity) into one 0-100 fingerprintability
# score for at-a-glance triage. Pure synthesis of probes 15/20/24.
XRAY_DETECT_STATUS=""       # ok, skipped
XRAY_DETECT_SCORE=""        # 0-100 (higher = more detectable)
XRAY_DETECT_BAND=""         # low | moderate | high | critical
XRAY_VOLUME_THROTTLE_HINT="" # 1/0 — cross-probe: tunnel worked early but degraded after the heavy pull (possible volume-triggered throttling)

# Passive structural signals folded into probe 26's score (set there): the
# cover SNI served on a non-443 port, and the server IP not on the cover
# domain's network (SNI↔IP ASN mismatch). FP-prone for censors at scale, real.
XRAY_PASSIVE_PORT_STD=""    # 1 / 0 — cover served on the standard 443
XRAY_PASSIVE_ASN_MATCH=""   # 1 / 0 / "" — server IP on the cover's network (or undetermined)
XRAY_PASSIVE_FP_STRONG=""   # 1 / 0 — both passive tells co-occur (the Reality structural signature)
XRAY_PASSIVE_SNI_RESOLVES="" # 1 / 0 / "" — cover SNI publicly resolves (a non-resolving SNI is a tell)
XRAY_PASSIVE_SNI_KEYWORD=""  # 1 / 0 — cover SNI contains a circumvention/antagonistic keyword (cleartext)
XRAY_PASSIVE_UTLS_RARE=""    # 1 / 0 — uTLS fingerprint is uncommon/regional (distinctive JA3)
XRAY_PASSIVE_UTLS_FP=""      # the configured uTLS fp string (chrome/qq/random/…) — for JSON/tells
XRAY_PASSIVE_COVER_OBSCURE="" # 1 / 0 — cover SNI resolves to a hosting/VPS net (self-owned/obscure), not a CDN
XRAY_PASSIVE_VISION=""       # 1 protected / 0 exposed / "" n/a — VLESS-Reality uses xtls-rprx-vision (anti TLS-in-TLS)
XRAY_TRANSPORT_MUX=""        # 1 / 0 / "" — mux.cool enabled on the proxy outbound (shape/correlation note vs vision)
XRAY_DEPLOY_FINGERPRINT=""   # short stable hash of the config's identifying shape (provider match)

# ---- SNI privacy / ECH posture (advisory, after probe 26 — NOT scored) ----
# Orthogonal to probe 26's cover-SNI QUALITY: can the SNI be HIDDEN at all
# (Encrypted ClientHello), and does the transport allow it? Reality forgoes ECH
# by design (cleartext cover IS the mechanism); a TLS-over-CDN transport can use
# it, and major CDNs publish ECH configs in DNS (HTTPS RR ech=).
XRAY_SNIPRIV_STATUS=""       # ok, skipped
XRAY_SNIPRIV_CLEARTEXT=""    # 1 — SNI travels in cleartext today (Reality by design; plain-TLS unless ECH)
XRAY_SNIPRIV_ECH_APPLIES=""  # 1 / 0 — ECH is applicable to this transport (0 for Reality)
XRAY_SNIPRIV_ECH_COVER=""    # 1 / 0 / unknown — the cover/front publishes an ECH config in DNS (HTTPS RR)
XRAY_SNIPRIV_CODE=""         # classifier code: reality | ech-available-unused | ech-unpublished | ech-unknown | na

# ---- baseline / diff mode (longitudinal regression detection) ----
# --save-baseline FILE writes this run's share-safe JSON; --diff-baseline FILE
# runs then reports what changed since that baseline. jq-only, no new deps.
SAVE_BASELINE="${SAVE_BASELINE:-}"
DIFF_BASELINE="${DIFF_BASELINE:-}"

# ---------- colors (TTY-aware, suppressed when --quiet) ----------

if [ -t 1 ] && [ "$LOG_QUIET" = "0" ]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; BLU=$'\033[34m'
  DIM=$'\033[2m'; RST=$'\033[0m'
else
  RED=""; GRN=""; YEL=""; BLU=""; DIM=""; RST=""
fi

# ---------- log + emit helpers ----------

_log_line() {
  [ -n "$LOG_FILE" ] || return 0
  printf '[%s] [%s] %s\n' \
    "$(date -Iseconds 2>/dev/null || date '+%Y-%m-%dT%H:%M:%S%z')" \
    "$1" "$2" >> "$LOG_FILE"
}

_init_log() {
  [ -n "$LOG_FILE" ] || return 0
  local log_dir
  log_dir=$(dirname -- "$LOG_FILE")
  [ -d "$log_dir" ] || mkdir -p -- "$log_dir" 2>/dev/null || true
  if [ -f "$LOG_FILE" ]; then
    local fsize
    fsize=$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
    [ "$fsize" -gt 10485760 ] && mv -f "$LOG_FILE" "${LOG_FILE}.1" 2>/dev/null || true
  fi
  printf '# detect_blocking.sh log @ %s host=%s user=%s vpn_host=%s\n' \
    "$(date -Iseconds 2>/dev/null || date)" \
    "$(hostname 2>/dev/null || echo ?)" \
    "${USER:-${LOGNAME:-?}}" \
    "$VPN_HOST" >> "$LOG_FILE"
}

ok()   { [ "$LOG_QUIET" = "1" ] || printf "  ${GRN}[OK]${RST}    %s\n" "$1"; _log_line OK   "$1"; }
fail() { [ "$LOG_QUIET" = "1" ] || printf "  ${RED}[FAIL]${RST}  %s\n" "$1"; _log_line FAIL "$1"; }
warn() { [ "$LOG_QUIET" = "1" ] || printf "  ${YEL}[WARN]${RST}  %s\n" "$1"; _log_line WARN "$1"; }
info() { [ "$LOG_QUIET" = "1" ] || printf "  ${DIM}        %s${RST}\n" "$1"; _log_line INFO "$1"; }
hdr()  { [ "$LOG_QUIET" = "1" ] || printf "\n${BLU}== %s ==${RST}\n" "$1"; _log_line HDR  "$1"; }

declare -a VERDICTS=()
declare -a VERDICT_CODES=()   # parallel to VERDICTS: stable machine code per verdict ("" = uncoded)
# add_verdict [CODE] "human text"
#
# CODE is a short stable token (no whitespace). Everything that CONSUMES a verdict —
# the false-positive suppressor, the recommendation engine, the fix-class classifier —
# keys off the CODE, never off the prose. That matters because verdict wording is
# explicitly NOT part of the 1.x contract: before codes, rewording a verdict silently
# unhooked its recommendation, or (worse) stopped the suppressor from cancelling a
# false "rotate your endpoint" on a healthy tunnel, with no test able to catch it.
#
# The code is detected by shape (no whitespace) so an uncoded legacy call still works;
# tests/test_verdict_codes.sh asserts that no uncoded call remains.
add_verdict() {
  local code=""
  case "${1-}" in
    ''|*[[:space:]]*) : ;;          # first arg is the human text — no code given
    *) code="$1"; shift ;;
  esac
  VERDICTS+=("$1")
  VERDICT_CODES+=("$code")
  _log_line VERDICT "${code:+[$code] }$1"
}

# Is CODE present among the verdicts raised so far? The code-based replacement for
# globbing verdict prose.
_has_verdict_code() {
  local c want="$1"
  for c in ${VERDICT_CODES[@]+"${VERDICT_CODES[@]}"}; do
    [ "$c" = "$want" ] && return 0
  done
  return 1
}

# QUIC-SNI advisory (gfw.report USENIX'25): since 2024 the GFW decrypts the QUIC
# Initial packet (the key is derived from its header), reads the SNI, and blocks
# a residual list (~3-min 4-tuple drop). Defeated by SNI-slicing across QUIC
# CRYPTO frames — default in quic-go >= 0.52.0, which Hysteria2/TUIC inherited.
# Advisory only (residual + region-specific, can't be tested from a clean vantage).
_quic_sni_note() {
  info "QUIC-based transport → the GFW censors QUIC by SNI (since 2024): it decrypts the QUIC Initial, reads the SNI, and blocks a residual list (~3-min 4-tuple drop). Mitigation: SNI-slicing across QUIC CRYPTO frames — default in quic-go >= 0.52.0, which Hysteria2/TUIC inherited; keep the client current. UDP/443 blocking is a separate risk."
}

# Triage tag for a recommendation: who has to act on it. server-side = the
# operator must change the server / cover / egress / deployment; client-side =
# the user edits their own config or runs a local tool; network = the local
# network / resolver is the problem. Keyword-matched and conservative — anything
# ambiguous returns "" (no tag, no claim). Advisory UX only; the logged rec text
# is unchanged. Matched in priority order (server first).
_rec_side() {
  case "$1" in
    *"Reality 'dest'"*|*"serverNames"*|*"self-signed"*|*"CA-valid cover"*|*"large shared CDN"*|*"CDN-fronting"*|*"self-steal"*|*"residential or clean"*|*"clean-IP egress"*|*"'fallbacks'"*|*"wrap in TLS or switch to REALITY"*|*"recognizable shape"*|*"cover on a large"*|*"serve on 443"*)
      printf 'server-side' ;;
    *'domainStrategy='*|*"split-horizon"*|*"drop them from the proxy"*|*"DPI-desync"*|*"ByeDPI"*|*"GoodbyeDPI"*|*"zapret"*|*"uTLS-mimicked"*|*"curl-impersonate"*|*"UA header in client"*|*"IPv6-preferred"*|*"change flow= variant"*|*"DOH_URL"*)
      printf 'client-side' ;;
    *"DoH"*|*"DoT"*|*"out-of-band resolver"*|*"system resolver"*|*"trusted resolver"*|*"another vantage"*|*"control sites"*|*"resolver/network"*)
      printf 'network' ;;
    *) printf '' ;;
  esac
}

# Operator-only detail (the real cover SNI / egress IP / matched keyword). Goes
# to the TERMINAL ONLY when --reveal is set: it deliberately does NOT call
# _log_line (so it's never in the log file) and is suppressed under --json /
# --quiet (so JSON and piped output stay share-safe). Everything else the tool
# prints remains booleans / codes / country only — this is the one opt-in escape
# hatch, and its output is not safe to paste or share.
reveal() {
  [ "${REVEAL:-0}" = "1" ] || return 0
  [ "$LOG_QUIET" = "1" ] && return 0
  printf "          ${DIM}↳ reveal:${RST} %s\n" "$(_safe "$1")"
}

# ---------- platform-aware helpers ----------

_mktmp() {
  # Portable mktemp: explicit template, 6 X's required by Linux util-linux.
  mktemp "/tmp/detect_blocking.${1}.XXXXXX"
}

_ipv4_lines() {
  awk -F. '
    /^[0-9]+(\.[0-9]+){3}$/ {
      for (i = 1; i <= 4; i++) if ($i < 0 || $i > 255) next
      print
    }' | sort -u
}

_join_words() { tr '\n' ' ' | sed 's/[[:space:]]*$//'; }
_first_word() { awk 'NF { print $1; exit }'; }

_sets_intersect() {
  local left="$1" right="$2" ip
  for ip in $left; do
    case " $right " in *" $ip "*) return 0 ;; esac
  done
  return 1
}

# Bounded ICMP liveness — true (0) if the host answers one ping within ~2s.
# Portable: Linux uses -W <seconds> for the reply timeout; macOS's -W is in
# milliseconds and instead takes -t <seconds> as a whole-run timeout. Try the
# Linux form first (on macOS its short ms-wait just fails and we fall through to
# -t). A "no reply" is only ever false — ICMP may be filtered — so callers must
# weigh it as a hint, not proof of a down host.
_host_pings() {
  local ip="$1"
  [ -n "$ip" ] || return 1
  ping -c 1 -W 2 "$ip" >/dev/null 2>&1 && return 0
  ping -c 1 -t 2 "$ip" >/dev/null 2>&1 && return 0
  return 1
}

# True (0) if an HTTPS URL is reachable. "Reachable" = an HTTP status came back,
# OR the TLS handshake to the target completed (time_appconnect > 0) — the latter
# so a CDN/asset host that serves no root page still counts as reached. $1=url,
# $2=max-time, optional $3="host:port" routes through a SOCKS5 proxy.
_url_reachable() {
  local url="$1" mt="$2" socks="${3:-}" out code appc
  if [ -n "$socks" ]; then
    out=$(curl -sS -k --max-time "$mt" --socks5-hostname "$socks" -o /dev/null \
          -w '%{http_code} %{time_appconnect}' "$url" 2>/dev/null)
  else
    out=$(curl -sS -k --max-time "$mt" -o /dev/null \
          -w '%{http_code} %{time_appconnect}' "$url" 2>/dev/null)
  fi
  code="${out%% *}"; appc="${out##* }"
  [ -n "$code" ] && [ "$code" != "000" ] && return 0
  [ -n "$appc" ] && awk "BEGIN{exit !(${appc:-0}>0)}" 2>/dev/null && return 0
  return 1
}

_is_special_ipv4() {
  awk -v ip="$1" 'BEGIN {
    split(ip, o, ".")
    if (o[1] == 0 || o[1] == 10 || o[1] == 127) exit 0
    if (o[1] == 169 && o[2] == 254) exit 0
    if (o[1] == 172 && o[2] >= 16 && o[2] <= 31) exit 0
    if (o[1] == 192 && o[2] == 168) exit 0
    if (o[1] == 100 && o[2] >= 64 && o[2] <= 127) exit 0
    if (o[1] == 192 && o[2] == 0 && o[3] == 2) exit 0
    if (o[1] == 198 && o[2] == 51 && o[3] == 100) exit 0
    if (o[1] == 203 && o[2] == 0 && o[3] == 113) exit 0
    if (o[1] >= 224) exit 0
    exit 1
  }'
}

_contains_special_ipv4() {
  local ip
  for ip in $1; do
    _is_special_ipv4 "$ip" && return 0
  done
  return 1
}

# True when $1 is a bare IPv4 or IPv6 literal (nothing to resolve). Mirrors the
# short-circuit patterns in _resolve_a_records.
_is_ip_literal() {
  case "$1" in
    *:*:*) case "$1" in *[!0-9A-Fa-f:]*) return 1 ;; *) return 0 ;; esac ;;
  esac
  printf '%s' "$1" | grep -qE '^[0-9]+(\.[0-9]+){3}$'
}

_resolve_a_records() {
  # System DNS A-records, sorted and deduped.
  local host="$1"
  # Short-circuit: if VPN_HOST is already a bare IPv4 literal, no DNS work
  # needed. Avoids the "Domain unresolvable" verdict on hostless targets.
  if printf '%s' "$host" | grep -qE '^[0-9]+(\.[0-9]+){3}$'; then
    printf '%s\n' "$host"
    return
  fi
  # Same for an IPv6 literal (>=2 colons, hex/colon only) — nc and openssl
  # accept it directly, so hand it through instead of failing to "resolve" it.
  case "$host" in
    *:*:*) case "$host" in *[!0-9A-Fa-f:]*) ;; *) printf '%s\n' "$host"; return ;; esac ;;
  esac
  if check_cmd dig; then
    dig +short +time="$TIMEOUT" +tries=1 "$host" A 2>/dev/null | _ipv4_lines
  elif check_cmd host; then
    host -t A "$host" 2>/dev/null | awk '/has address/{print $4}' | _ipv4_lines
  elif check_cmd nslookup; then
    # Skip the resolver's own Server/Address lines that precede the answer;
    # only collect Address lines that come after the first "Name:" block.
    nslookup "$host" 2>/dev/null \
      | awk '/^Name:/{found=1} found && /^Address:/{print $2}' | _ipv4_lines
  fi
}

# Loose IPv6 line filter — accepts canonical, compressed (::), and embedded
# IPv4 forms. We only need format-validity, not RFC-precise parsing.
_ipv6_lines() {
  awk '/:/ && !/^[[:space:]]*$/ {
    # crude validity: must contain at least one ":", no spaces, no commas
    if ($0 ~ /[[:space:],]/) next
    print
  }' | sort -u
}

_resolve_aaaa_records() {
  local host="$1"
  if check_cmd dig; then
    dig +short +time="$TIMEOUT" +tries=1 "$host" AAAA 2>/dev/null | _ipv6_lines
  elif check_cmd host; then
    host -t AAAA "$host" 2>/dev/null | awk '/has IPv6 address/{print $5}' | _ipv6_lines
  elif check_cmd nslookup; then
    nslookup -type=AAAA "$host" 2>/dev/null \
      | awk '/^Name:/{found=1} found && /^Address:/{print $2}' | _ipv6_lines
  fi
}

# True (0) ONLY if DNS authoritatively says the name does not exist (NXDOMAIN),
# as opposed to a transient SERVFAIL / timeout / unreachable-resolver / geo-DNS
# miss — so a from-here lookup hiccup isn't misread as a self-cooked SNI. Needs
# dig (to read the response code); without it we can't confirm, so return false
# (don't flag) — the conservative, low-false-positive choice.
_dns_nxdomain() {
  local host="$1" st=""
  check_cmd dig || return 1
  st=$(dig +time="$TIMEOUT" +tries=1 "$host" A 2>/dev/null \
        | awk -F'status: ' '/->>HEADER<<-/{split($2,a,","); print a[1]; exit}')
  [ "$st" = "NXDOMAIN" ]
}

# Platform-aware TCP connect probe. macOS nc honours `-G` (connect timeout)
# but silently ignores `-w` for SYN-without-response — it waits the full
# Darwin SYN_RETRANSMIT (~75s). Linux nc (openbsd/ncat) uses `-w` for both.
_nc_tcp_probe() {
  local host="$1" port="$2"
  if [[ "$OSTYPE" == darwin* ]]; then
    nc -z -G "$TIMEOUT" "$host" "$port" 2>/dev/null
  else
    nc -z -w "$TIMEOUT" "$host" "$port" 2>/dev/null
  fi
}

# IPv6 TCP probe — same -G/-w split as IPv4, with -6 forced.
_nc6_tcp_probe() {
  local host="$1" port="$2"
  if [[ "$OSTYPE" == darwin* ]]; then
    nc -6 -z -G "$TIMEOUT" "$host" "$port" 2>/dev/null
  else
    nc -6 -z -w "$TIMEOUT" "$host" "$port" 2>/dev/null
  fi
}

_parse_doh_ips() {
  if check_cmd jq; then
    jq -r '.Answer // [] | .[] | select(.type==1) | .data' | _ipv4_lines
  else
    grep -oE '"data"[[:space:]]*:[[:space:]]*"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"' \
      | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | _ipv4_lines
  fi
}

# DoH integrity canary. Resolves "one.one.one.one" — a Cloudflare hostname
# whose A records are deterministically 1.1.1.1 and 1.0.0.1. If the configured
# DoH endpoint returns anything else, the DoH path itself is MITM'd (anycast
# hijack, national-CA TLS interception, transparent DPI proxy, etc.) and its
# answers cannot be trusted for the actual DNS check.
_doh_integrity_check() {
  local json ip
  json=$(curl -sf --max-time "$TIMEOUT" \
    -H 'accept: application/dns-json' \
    "$DOH_URL?name=one.one.one.one&type=A" 2>/dev/null || true)
  DOH_INTEGRITY_IPS=$(printf '%s' "$json" | _parse_doh_ips | _join_words)

  if [ -z "$DOH_INTEGRITY_IPS" ]; then
    DOH_INTEGRITY_STATE="unreachable"
    return
  fi
  for ip in $DOH_INTEGRITY_IPS; do
    case "$ip" in 1.1.1.1|1.0.0.1) DOH_INTEGRITY_STATE="ok"; return ;; esac
  done
  DOH_INTEGRITY_STATE="compromised"
}

# DoT integrity canary (parallels DoH). Queries one.one.one.one over TCP 853
# via `dig +tls` (BIND 9.18+) or `kdig` (knot-utils) when available. Lets us
# distinguish "DoH MITM" from "all encrypted DNS MITM" — operators may then
# fall back to DoT inside their VPN client.
_dot_integrity_check() {
  DOT_INTEGRITY_STATE=""
  DOT_INTEGRITY_IPS=""

  local response ip
  if check_cmd dig && dig -h 2>&1 | grep -qE '[\+\-]tls'; then
    response=$(dig +tls +short +time="$TIMEOUT" +tries=1 \
                 @1.1.1.1 one.one.one.one A 2>/dev/null)
  elif check_cmd kdig; then
    response=$(kdig +tls +short @1.1.1.1 one.one.one.one A 2>/dev/null)
  else
    DOT_INTEGRITY_STATE="skipped"
    return
  fi

  DOT_INTEGRITY_IPS=$(printf '%s' "$response" | _ipv4_lines | _join_words)
  if [ -z "$DOT_INTEGRITY_IPS" ]; then
    DOT_INTEGRITY_STATE="unreachable"
    return
  fi
  for ip in $DOT_INTEGRITY_IPS; do
    case "$ip" in 1.1.1.1|1.0.0.1) DOT_INTEGRITY_STATE="ok"; return ;; esac
  done
  DOT_INTEGRITY_STATE="compromised"
}

# Locate a curl-impersonate binary. Common names across distros:
#   curl-impersonate-chrome  (Debian/Ubuntu)
#   curl_chrome116, curl_chrome120, ...  (Homebrew, upstream releases)
#   curl_chrome  (generic alias users sometimes set up)
_find_curl_impersonate() {
  local c
  for c in curl-impersonate-chrome curl_chrome120 curl_chrome116 curl_chrome curl-impersonate; do
    if command -v "$c" >/dev/null 2>&1; then printf '%s' "$c"; return 0; fi
  done
  return 1
}

# Multi-provider DoH cross-check. Queries one.one.one.one against every URL
# in $DOH_PROVIDERS and records per-provider state. Catches "all-DoH MITM"
# (every provider redirected to the same sinkhole) and "split MITM" (only
# one provider hijacked) cases that single-provider canary cannot see.
_doh_multi_check() {
  DOH_MULTI_RESULTS=""
  DOH_MULTI_OK=0
  DOH_MULTI_COMPROMISED=0
  DOH_MULTI_UNREACHABLE=0

  local p ips ip state
  for p in $DOH_PROVIDERS; do
    ips=$(curl -sf --max-time "$TIMEOUT" \
      -H 'accept: application/dns-json' \
      "$p?name=one.one.one.one&type=A" 2>/dev/null \
      | _parse_doh_ips | _join_words)

    if [ -z "$ips" ]; then
      state="unreachable"
      DOH_MULTI_UNREACHABLE=$((DOH_MULTI_UNREACHABLE + 1))
    else
      state="compromised"
      for ip in $ips; do
        case "$ip" in 1.1.1.1|1.0.0.1) state="ok"; break ;; esac
      done
      case "$state" in
        ok)          DOH_MULTI_OK=$((DOH_MULTI_OK + 1)) ;;
        compromised) DOH_MULTI_COMPROMISED=$((DOH_MULTI_COMPROMISED + 1)) ;;
      esac
    fi

    DOH_MULTI_RESULTS="${DOH_MULTI_RESULTS}${p}|${state}|${ips}
"
  done
}

# Locate a delegation binary for end-to-end Xray-protocol testing.
# Preference order: xray-knife (most ergonomic CLI) > xray (raw core) > sing-box.
_find_xray_tester() {
  local c
  for c in xray-knife xray sing-box; do
    if command -v "$c" >/dev/null 2>&1; then printf '%s' "$c"; return 0; fi
  done
  return 1
}

# Find an unused TCP port in the IANA dynamic range. Used by --xray-config-json
# to patch the SOCKS inbound port so the test doesn't collide with a running
# client (v2rayN/NekoBox/etc. typically squat on 10808-10809).
_find_free_port() {
  local port _i
  for _i in 1 2 3 4 5 6 7 8 9 10; do
    port=$(( 49152 + RANDOM % 16383 ))
    if ! nc -z 127.0.0.1 "$port" 2>/dev/null; then
      printf '%s' "$port"
      return 0
    fi
  done
  return 1
}

# Millisecond-precision wall clock. Tries hires perl, falls back to second-
# precision date * 1000.
_now_ms() {
  if check_cmd perl; then
    perl -MTime::HiRes -e 'printf "%d", Time::HiRes::time*1000' 2>/dev/null && return 0
  fi
  printf '%s000' "$(date +%s)"
}

# Mask credentials in an Xray protocol URL for safe display in logs / JSON.
# vless://uuid@host:port?type=tcp&pbk=KEY&sid=SID#name  →  vless://<creds>@host:port#name
# vmess://BASE64  →  vmess://<base64-config>
# ss://b64@host:port  →  ss://<creds>@host:port
_summarize_xray_url() {
  # Defensive: collapse any whitespace before masking so a stray newline in
  # the input can't push the query/fragment portion through the regex.
  local url scheme
  url=$(printf '%s' "$1" | tr -d '[:space:]')
  scheme=$(printf '%s' "$url" | sed -nE 's|^([a-z0-9]+)://.*|\1|p')
  case "$scheme" in
    vless|trojan|ss|hysteria|hysteria2|tuic)
      # scheme://creds@host:port?...#fragment  →  scheme://<creds>@host:port
      printf '%s' "$url" \
        | sed -E 's|^([a-z0-9]+)://[^@]+@([^?#/]+)([?#].*)?$|\1://<creds>@\2|'
      ;;
    vmess)
      printf 'vmess://<base64-config>'
      ;;
    *)
      printf '%s' "<unknown-scheme>"
      ;;
  esac
}

_target_https_url() {
  # Bracket an IPv6 literal so the URL is valid (https://[2001:db8::1]/).
  local h="$VPN_HOST"
  case "$h" in *:*:*) h="[$h]" ;; esac
  if [ "$VPN_PORT_TCP" = "443" ]; then
    printf 'https://%s/' "$h"
  else
    printf 'https://%s:%s/' "$h" "$VPN_PORT_TCP"
  fi
}

# The SNI a generic TLS/HTTPS probe should present. For a Reality config the
# client sends the cover serverName, not VPN_HOST (often a bare IP) — and a
# Reality server is DESIGNED to drop handshakes whose SNI isn't a configured
# serverName. Using VPN_HOST there makes the generic probes (3-5) misread
# Reality's selective drop as a censor block. Falls back to VPN_HOST for
# non-Reality targets, so their behaviour is unchanged.
_effective_tls_sni() {
  local s
  s=$(_xray_cover_sni 2>/dev/null)
  if [ -n "$s" ] && [ "$s" != "$VPN_HOST" ]; then printf '%s' "$s"; else printf '%s' "$VPN_HOST"; fi
}

# Extract the first value of query-string key $2 from query string $1.
# Keys in share links are plain alnum, so no regex escaping is needed.
_qp() {
  printf '%s' "$1" | tr '&' '\n' | sed -nE "s/^$2=(.*)$/\1/p" | head -1
}

# Minimal percent-decode for share-link path / host-header values
# (e.g. %2F → /). Safe for the small, well-formed values found in URLs.
_urldecode() {
  local s="${1//+/ }"
  printf '%b' "${s//%/\\x}"
}

# Synthesize a minimal xray-core JSON config from a vless:// or trojan://
# share link, so probes 12/13 (which need a full config + xray-core) can run
# from --xray-config URL alone — no hand-written JSON required. Echoes the
# path to a 0600 temp .json file on success; returns 1 for unsupported
# schemes (vmess base64, ss, hysteria, tuic) so the caller skips cleanly.
#
# The config is intentionally minimal: one proxy outbound + a freedom direct,
# a single socks inbound (probe 12 relocates it to a free port). No routing /
# balancer / fragment layers — those only exist in a real --xray-config-json.
_synthesize_xray_json_from_url() {
  local url="$1" scheme rest uuid after hostport host port query
  scheme=${url%%://*}
  case "$scheme" in
    vless|trojan) ;;
    *) return 1 ;;
  esac

  rest=${url#*://}; rest=${rest%%#*}      # drop scheme + fragment
  uuid=${rest%%@*}
  after=${rest#*@}
  hostport=${after%%\?*}; hostport=${hostport%%/*}
  query=""; case "$after" in *\?*) query=${after#*\?} ;; esac
  # IPv6-literal aware host:port split ([addr]:port).
  case "$hostport" in
    \[*\]*)  host=${hostport#\[}; host=${host%%\]*}
             case "$hostport" in *\]:*) port=${hostport##*\]:} ;; *) port="" ;; esac ;;
    *:*)     host=${hostport%%:*}; port=${hostport##*:} ;;
    *)       host=$hostport; port="" ;;
  esac
  case "$port" in ''|*[!0-9]*) port=443 ;; esac
  [ -n "$uuid" ] && [ -n "$host" ] || return 1

  local net sec sni fp pbk sid spx flow alpn path hosthdr svc hdr enc insec mode
  net=$(_qp "$query" type);        [ -z "$net" ] && net=tcp
  sec=$(_qp "$query" security);    [ -z "$sec" ] && sec=none
  sni=$(_qp "$query" sni)
  fp=$(_qp "$query" fp)
  pbk=$(_qp "$query" pbk)
  sid=$(_qp "$query" sid)
  spx=$(_qp "$query" spx)
  flow=$(_qp "$query" flow)
  alpn=$(_urldecode "$(_qp "$query" alpn)")
  path=$(_urldecode "$(_qp "$query" path)")
  hosthdr=$(_urldecode "$(_qp "$query" host)")
  svc=$(_urldecode "$(_qp "$query" serviceName)")
  hdr=$(_qp "$query" headerType)
  mode=$(_qp "$query" mode)        # xhttp transport mode (auto / packet-up / stream-up)
  enc=$(_qp "$query" encryption); [ -z "$enc" ] && enc=none
  # allowInsecure: clients spell it allowInsecure= or insecure=; values 1/true.
  # Carrying it lets us faithfully probe skip-verify WS/TLS configs (which would
  # otherwise fail the handshake on their invalid cert) — and it's a tell in its
  # own right: a config that needs it is masking a cert that won't validate.
  insec=$(_qp "$query" allowInsecure); [ -z "$insec" ] && insec=$(_qp "$query" insecure)
  case "$insec" in 1|true|TRUE|True) insec=1 ;; *) insec="" ;; esac

  # Single temp file — no .json extension needed: probe 12 reads this via jq
  # and writes its own patched .json that xray-core actually loads, so this
  # file is never handed to xray directly. One file → nothing to orphan.
  local out
  out=$(mktemp -t detect_blocking.synthcfg.XXXXXX) || return 1

  if ! jq -n \
      --arg proto "$scheme" --arg host "$host" --argjson port "$port" \
      --arg uuid "$uuid" --arg enc "$enc" --arg flow "$flow" \
      --arg net "$net" --arg sec "$sec" --arg sni "$sni" --arg fp "$fp" \
      --arg pbk "$pbk" --arg sid "$sid" --arg spx "$spx" --arg alpn "$alpn" \
      --arg path "$path" --arg hosthdr "$hosthdr" --arg svc "$svc" --arg hdr "$hdr" \
      --arg insec "$insec" --arg mode "$mode" '
      def nz(s): if s == "" then null else s end;
      def prune: with_entries(select(.value != null));
      def secSettings:
        if $sec == "reality" then
          { realitySettings: ({ show:false, serverName:nz($sni), fingerprint:nz($fp),
                                publicKey:nz($pbk), shortId:nz($sid), spiderX:nz($spx) } | prune) }
        elif $sec == "tls" then
          { tlsSettings: ({ serverName:nz($sni), fingerprint:nz($fp),
                            alpn:(if $alpn=="" then null else ($alpn|split(",")) end),
                            allowInsecure:(if $insec=="1" then true else null end) } | prune) }
        else {} end;
      def transportSettings:
        if $net == "ws" then
          { wsSettings: ({ path:(if $path=="" then "/" else $path end),
                           headers:(if $hosthdr=="" then null else {Host:$hosthdr} end) } | prune) }
        elif ($net == "xhttp" or $net == "splithttp") then
          { xhttpSettings: ({ path:(if $path=="" then "/" else $path end),
                              host:nz($hosthdr), mode:nz($mode) } | prune) }
        elif $net == "grpc" then
          { grpcSettings: { serviceName:(if $svc=="" then "" else $svc end) } }
        elif $net == "tcp" then
          (if $hdr == "http" then { tcpSettings:{ header:{ type:"http" } } } else { tcpSettings:{} } end)
        else {} end;
      def outbound:
        (if $proto == "trojan" then
           { protocol:"trojan",
             settings:{ servers:[ { address:$host, port:$port, password:$uuid } ] }, tag:"proxy" }
         else
           { protocol:"vless",
             settings:{ vnext:[ { address:$host, port:$port,
                                  users:[ ({ id:$uuid, encryption:$enc, flow:nz($flow) } | prune) ] } ] },
             tag:"proxy" }
         end)
        + { streamSettings: ({ network:$net, security:$sec } + secSettings + transportSettings) };
      {
        log: { loglevel:"warning" },
        inbounds: [ { tag:"socks", listen:"127.0.0.1", port:10808, protocol:"socks",
                      settings:{ auth:"noauth", udp:true } } ],
        outbounds: [ outbound, { protocol:"freedom", tag:"direct" } ]
      }' > "$out" 2>/dev/null; then
    rm -f "$out" 2>/dev/null
    return 1
  fi
  chmod 600 "$out" 2>/dev/null
  printf '%s' "$out"
}

# QUIC Version-Negotiation reachability probe (dependency-free, perl UDP). Sends a
# long-header packet with an UNSUPPORTED version; an RFC-9000 server MUST reply
# with a Version Negotiation packet (version field == 0) — so a reply proves
# UDP/443 + a QUIC server are reachable, with no QUIC crypto. The 1200-byte pad
# satisfies QUIC's anti-amplification minimum. Echoes: vn | response | silent |
# error | no-perl.
_quic_vn_probe() {              # host port [timeout]
  check_cmd perl || { printf 'no-perl\n'; return 0; }
  perl - "$1" "$2" "${3:-2}" 2>/dev/null <<'PERL'
use strict; use warnings; use IO::Socket::INET; use IO::Select;
my ($host,$port,$to)=@ARGV; $to||=2;
my $s=IO::Socket::INET->new(Proto=>'udp',PeerHost=>$host,PeerPort=>$port) or do{print "error\n";exit 0};
my $dcid=join('',map{chr(int(rand(256)))}1..8);
my $p=chr(0xC0).pack('N',0x1a2a3a4a).chr(8).$dcid.chr(0); $p.="\x00"x(1200-length($p));
$s->send($p);
my $sel=IO::Select->new($s);
if($sel->can_read($to)){
  my $r=''; $s->recv($r,2048);
  if(length($r)>=5){
    my $b0=ord(substr($r,0,1)); my $v=unpack('N',substr($r,1,4));
    if(($b0&0x80)&&$v==0){print "vn\n"}else{print "response\n"}
    exit 0;
  }
  print "response\n"; exit 0;
}
print "silent\n";
PERL
}

# Pure classifier for the QUIC / UDP-443 probe (unit-testable, no network). The
# baseline is a KNOWN QUIC host's VN result, so its silence = this network blocks
# UDP/443 (not "the host has no QUIC" — most sites run QUIC now). target = the
# server's result, or "" when there is no server UDP endpoint to test.
_classify_udp_quic() {         # baseline target → net-blocked|net-ok|target-quic|net-ok-target-silent
  local b="$1" t="${2:-}"
  [ "$b" = "vn" ] || { printf 'net-blocked\n'; return; }
  [ -n "$t" ] || { printf 'net-ok\n'; return; }
  [ "$t" = "vn" ] && { printf 'target-quic\n'; return; }
  printf 'net-ok-target-silent\n'
}

# Send a minimal-but-valid IKE_SA_INIT initiator header (RFC 7296 §3.1)
# and wait up to TIMEOUT seconds for any reply. Even an INVALID_SYNTAX
# notify proves the service is reachable / not silently filtered.
_ike_probe() {
  local host="$1" port="$2" response
  check_cmd perl || return 2
  # Pipe directly — shell variables can't carry null bytes (truncates at \x00).
  response=$(perl -e '
    my $ispi = join("", map { chr(int(rand(256))) } 1..8);
    print $ispi . ("\x00" x 8)
        . chr(0) . chr(0x20) . chr(34) . chr(0x08)
        . "\x00\x00\x00\x00" . pack("N", 28);
  ' 2>/dev/null | nc -u -w "$TIMEOUT" "$host" "$port" 2>/dev/null | head -c 1)
  [ -n "$response" ]
}

# ---------- transport probes (0-10) ----------

probe_environment() {
  hdr "0. Environment"

  local default_if="" vpn_ifaces="" connected_vpn="" on_vpn=0

  if [[ "$OSTYPE" == darwin* ]]; then
    default_if=$(route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}')
    vpn_ifaces=$(ifconfig -l 2>/dev/null | tr ' ' '\n' \
                  | grep -E '^(utun|ppp|ipsec|tap|tun)[0-9]*$' | _join_words || true)
    connected_vpn=$(scutil --nc list 2>/dev/null \
                    | awk '/\(Connected\)/{print}' | _join_words || true)
  elif [[ "$OSTYPE" == linux* ]]; then
    default_if=$(ip route show default 2>/dev/null \
                  | awk '{for(i=1;i<=NF;i++)if($i=="dev"){print $(i+1);exit}}')
    vpn_ifaces=$(ip -o link show 2>/dev/null \
                  | awk -F': ' '{print $2}' | awk '{print $1}' \
                  | grep -E '^(tun|tap|wg|ppp|ipsec)[0-9]*$' | _join_words || true)
    if check_cmd nmcli; then
      connected_vpn=$(nmcli -t -f NAME,TYPE,STATE con show --active 2>/dev/null \
                       | awk -F: '$2=="vpn" || $2=="wireguard"{print $1}' \
                       | _join_words || true)
    fi
  fi

  info "default route interface: ${default_if:-<unknown>}"
  info "VPN-like interfaces:     ${vpn_ifaces:-<none>}"
  [ -n "$connected_vpn" ] && info "system VPN services:     $connected_vpn"

  case "$default_if" in
    utun*|ppp*|ipsec*|tun*|tap*|wg*) on_vpn=1 ;;
  esac
  [ -n "$connected_vpn" ] && on_vpn=1

  if [ "$on_vpn" -eq 1 ]; then
    warn "VPN appears active – results describe the VPN exit path, not local ISP"
  elif [ -n "$vpn_ifaces" ]; then
    warn "VPN-like interface exists – split-tunnel may affect some probes"
  else
    ok "no active VPN signal detected"
  fi

  ENV_DEFAULT_IF="$default_if"
  ENV_VPN_IFACES="$vpn_ifaces"
  ENV_CONNECTED_VPN="$connected_vpn"
  ENV_ON_VPN="$on_vpn"
}

# TLS reachability: 0 if a TLS handshake to ip:443 with the given SNI returns a
# certificate, 1 otherwise. Bounded by the nc precheck (no ~75s connect hang on a
# dead IP). Used to tell a live host from a dead TLS stub when DNS answers diverge.
# Run a command with a hard wall-clock bound (SIGALRM via perl exec — perl is a
# soft-dep already used by the QUIC / OpenVPN probes). Falls back to running unbounded
# when perl is absent (identical to prior behaviour). Used to cap `openssl s_client`,
# whose TLS *handshake* has no native timeout and can hang on a TCP-open-but-stalling
# host even after the nc connect precheck passes. (macOS has no `timeout`/`gtimeout`.)
_bounded() {
  local t="$1"; shift
  if command -v perl >/dev/null 2>&1; then
    perl -e 'alarm shift; exec @ARGV' "$t" "$@"
  else
    "$@"
  fi
}

_tls_reachable() {
  local ip="$1" sni="$2"
  [ -n "$ip" ] || return 1
  _nc_tcp_probe "$ip" 443 || return 1
  echo Q | _bounded "$(( ${TIMEOUT:-10} + 2 ))" openssl s_client -connect "$ip:443" -servername "$sni" 2>/dev/null \
    | grep -q 'BEGIN CERTIFICATE' && return 0
  return 1
}

# Pure: classify a system-vs-DoH IP divergence by which side completes TLS.
#   dns-block   system IP fails TLS, DoH IP serves it → DNS-layer block / poisoning
#               (censored domain hosted abroad; the local resolver hands out a dead
#               domestic IP while the real host answers via encrypted DNS)
#   system-ok   the system IP serves TLS → benign CDN/geo divergence
#   both-fail   neither serves TLS → real IP block / dead host, not DNS-selective
_dns_block_verdict() {
  local sys_tls="$1" doh_tls="$2"
  if [ "$sys_tls" = "0" ] && [ "$doh_tls" = "1" ]; then echo "dns-block"; return 0; fi
  if [ "$sys_tls" = "1" ]; then echo "system-ok"; return 0; fi
  echo "both-fail"
}

probe_dns() {
  hdr "1. DNS resolution"

  _doh_integrity_check
  case "$DOH_INTEGRITY_STATE" in
    ok)
      info "DoH integrity:    ok ($DOH_INTEGRITY_IPS for one.one.one.one)"
      ;;
    unreachable)
      warn "DoH integrity:    $DOH_URL unreachable – DoH not usable as cross-check"
      ;;
    compromised)
      fail "DoH integrity:    canary returned $DOH_INTEGRITY_IPS for one.one.one.one (expected 1.1.1.1/1.0.0.1)"
      add_verdict "DoH path is compromised – network intercepts/poisons DoH responses"
      ;;
  esac

  # Multi-DoH cross-check — broader picture than the single-provider canary.
  _doh_multi_check
  local total_providers=$((DOH_MULTI_OK + DOH_MULTI_COMPROMISED + DOH_MULTI_UNREACHABLE))
  if [ "$total_providers" -gt 1 ]; then
    info "DoH cross-check:  ${DOH_MULTI_OK}/${total_providers} providers honest, ${DOH_MULTI_COMPROMISED} compromised, ${DOH_MULTI_UNREACHABLE} unreachable"
    if [ "$DOH_MULTI_OK" -eq 0 ] && [ "$DOH_MULTI_COMPROMISED" -gt 0 ]; then
      fail "all reachable DoH providers return wrong IPs — encrypted DNS is uniformly MITM'd"
      add_verdict "All DoH providers compromised – network does universal DoH interception"
    elif [ "$DOH_MULTI_COMPROMISED" -gt 0 ]; then
      warn "${DOH_MULTI_COMPROMISED} provider(s) return wrong IPs — split MITM"
      add_verdict "Split DoH MITM – ${DOH_MULTI_COMPROMISED} of ${total_providers} providers compromised"
    fi
  fi

  _dot_integrity_check
  case "$DOT_INTEGRITY_STATE" in
    ok)
      info "DoT integrity:    ok ($DOT_INTEGRITY_IPS via TLS:853)"
      ;;
    unreachable)
      info "DoT integrity:    1.1.1.1:853 silent – DoT may also be blocked"
      ;;
    compromised)
      fail "DoT integrity:    canary returned $DOT_INTEGRITY_IPS for one.one.one.one (TLS:853 also MITM'd)"
      add_verdict "DoT path is compromised – TLS:853 cannot be trusted as DNS fallback"
      ;;
    skipped)
      info "DoT integrity:    no \`dig +tls\` or \`kdig\` available – skipped"
      ;;
  esac

  local sys_ips doh_json doh_ips is_ip=0
  sys_ips=$(_resolve_a_records "$VPN_HOST" | _join_words)
  _is_ip_literal "$VPN_HOST" && is_ip=1
  if [ "$is_ip" = "1" ]; then
    # Target is a bare IP — there is no name to DoH-resolve, so skip the lookup
    # and the comparison entirely (otherwise it emits a spurious "DoH returned
    # no A records" warning on every IP-literal target).
    doh_ips=""
  else
    doh_json=$(curl -sf --max-time "$TIMEOUT" \
      -H 'accept: application/dns-json' \
      "$DOH_URL?name=$VPN_HOST&type=A" 2>/dev/null || true)
    doh_ips=$(printf '%s' "$doh_json" | _parse_doh_ips | _join_words)
    # If DoH is MITM'd, drop its answer — treating compromised data as ground
    # truth would mask real DNS poisoning when system + DoH agree on a fake IP.
    if [ "$DOH_INTEGRITY_STATE" = "compromised" ]; then
      info "ignoring DoH answer for $VPN_HOST (was: ${doh_ips:-<empty>})"
      doh_ips=""
    fi
  fi

  info "system resolver A: ${sys_ips:-<empty>}"
  if [ "$is_ip" = "1" ]; then
    info "DoH resolver A:    n/a (target is an IP literal — no name to resolve)"
  else
    info "DoH resolver A:    ${doh_ips:-<empty>}"
  fi

  DNS_SYS_IPS="$sys_ips"
  DNS_DOH_IPS="$doh_ips"

  if [ "$is_ip" = "1" ]; then
    ok "target is an IP literal — DNS-leak / poisoning checks N/A"
    RESOLVED_IP=$(printf '%s\n' "$sys_ips" | _first_word)
    RESOLVED_SOURCE="IP literal"
  elif [ -z "$sys_ips" ] && [ -n "$doh_ips" ]; then
    fail "system resolver returns no A records, but DoH works"
    add_verdict "System DNS failure while DoH works"
    RESOLVED_IP=$(printf '%s\n' "$doh_ips" | _first_word)
    RESOLVED_SOURCE="DoH fallback"
  elif [ -n "$sys_ips" ] && [ -z "$doh_ips" ]; then
    warn "DoH returned no A records; using system DNS result"
    RESOLVED_IP=$(printf '%s\n' "$sys_ips" | _first_word)
    RESOLVED_SOURCE="system DNS"
  elif [ -z "$sys_ips" ] && [ -z "$doh_ips" ]; then
    fail "no DNS answer from either source → domain dead or fully blocked"
    add_verdict "Domain unresolvable (DoH also blocked or domain offline)"
    return 1
  elif _contains_special_ipv4 "$sys_ips" && ! _contains_special_ipv4 "$doh_ips"; then
    fail "system DNS returned private/special IPs while DoH returned public IPs"
    add_verdict "DNS sinkhole / local resolver interception suspected"
    RESOLVED_IP=$(printf '%s\n' "$doh_ips" | _first_word)
    RESOLVED_SOURCE="DoH fallback"
  elif _sets_intersect "$sys_ips" "$doh_ips"; then
    ok "system DNS and DoH share at least one A record"
    RESOLVED_IP=$(printf '%s\n' "$sys_ips" | _first_word)
    RESOLVED_SOURCE="system DNS"
  else
    # System DNS and DoH disagree on the public IP. Usually benign CDN/geo — BUT a
    # censored domain hosted abroad classically shows a DEAD domestic IP from the
    # system resolver while the DoH IP serves the site: that's DNS-layer blocking.
    # Probe TLS on both to tell them apart instead of guessing "CDN/geo".
    local _sys1 _doh1 _st=1 _dt=1
    _sys1=$(printf '%s\n' "$sys_ips" | _first_word)
    _doh1=$(printf '%s\n' "$doh_ips" | _first_word)
    if check_cmd openssl; then
      _tls_reachable "$_sys1" "$VPN_HOST" && _st=1 || _st=0
      _tls_reachable "$_doh1" "$VPN_HOST" && _dt=1 || _dt=0
      DNS_DIVERGE_CLASS=$(_dns_block_verdict "$_st" "$_dt")
    else
      DNS_DIVERGE_CLASS="unchecked"
    fi
    case "$DNS_DIVERGE_CLASS" in
      dns-block)
        fail "DNS-level block: the system-DNS IP refuses TLS while the DoH IP serves the site"
        add_verdict "DNS-level block / poisoning — the system resolver returns an IP that refuses TLS, while the DoH-resolved IP serves the site normally (valid cert). The domain is blocked at the plaintext-DNS layer; the real host is reachable over encrypted DNS. Switch the client to DoH/DoT to bypass it"
        RESOLVED_IP="$_doh1"; RESOLVED_SOURCE="DoH (system-DNS IP is a dead TLS stub)"; DNS_BLOCK=1 ;;
      both-fail)
        warn "system DNS and DoH gave different public A sets and NEITHER completes TLS — a real IP block or a dead host, not a DNS-selective block"
        RESOLVED_IP="$_sys1"; RESOLVED_SOURCE="system DNS" ;;
      *)
        warn "system DNS and DoH returned different public A sets – common with CDN/geo DNS$( [ "$DNS_DIVERGE_CLASS" = "system-ok" ] && printf ' (both sides serve TLS)' )"
        RESOLVED_IP="$_sys1"; RESOLVED_SOURCE="system DNS" ;;
    esac
  fi

  info "target IP for transport probes: ${RESOLVED_IP:-<none>} (${RESOLVED_SOURCE:-none})"
}

probe_tcp_reachability() {
  hdr "2. TCP reachability"
  TCP_TESTED=1   # distinguishes "measured unreachable" (TCP_OK=0) from "never measured"

  local baseline_ok=0 ok_ip=""
  for ip in $BASELINE_IPS; do
    if _nc_tcp_probe "$ip" 443; then
      baseline_ok=1; ok_ip=$ip; break
    fi
  done
  TCP_BASELINE_OK="$baseline_ok"
  TCP_BASELINE_IP="$ok_ip"
  if [ "$baseline_ok" -eq 1 ]; then
    ok "baseline TCP $ok_ip:443 reachable (network is up)"
  else
    fail "all baseline IPs ($BASELINE_IPS) fail – network broken or all blocked"
    add_verdict "Network connectivity broken (or all baseline IPs blocked)"
    return 1
  fi

  if [ -z "$RESOLVED_IP" ]; then
    warn "skipping target TCP probe – no resolved IP available from DNS step"
    add_verdict "Target TCP reachability not testable (no resolved IP)"
    return 0
  fi

  if _nc_tcp_probe "$RESOLVED_IP" "$VPN_PORT_TCP"; then
    ok "VPN host TCP $VPN_PORT_TCP reachable"
    TCP_OK=1
  else
    fail "VPN host TCP $VPN_PORT_TCP UNREACHABLE"
    TCP_OK=0
    if _nc_tcp_probe "$RESOLVED_IP" 80; then
      warn "but TCP 80 to same IP works → PORT-SPECIFIC block on 443"
      add_verdict "Port 443 blocked, port 80 open → port-specific filtering"
    else
      # Both TCP ports dead. Don't assert censorship here: whether this is an
      # IP-level block or a downed / null-routed server depends on the vantage,
      # which the recommendation weighs against the control-site result (probe
      # 8). ICMP narrows it further — a host that pings but refuses TCP is up
      # and filtered; total silence means it's unreachable.
      if _host_pings "$RESOLVED_IP"; then
        TARGET_ICMP_OK=1
        warn "TCP 80 + 443 both fail, but the host answers ICMP → up but TCP-filtered"
        add_verdict "Target host responds to ICMP but TCP 80/443 are filtered — the host is up; a targeted port/route block, or the service isn't listening"
      else
        TARGET_ICMP_OK=0
        warn "TCP 80 + 443 fail and no ICMP reply → host unreachable (down, null-routed, or route blocked)"
        add_verdict "Target host is unreachable — no TCP (80/443) and no ICMP reply"
      fi
    fi
  fi
}

probe_tls_handshake() {
  hdr "3. TLS handshake behaviour"
  [ "$TCP_OK" -ne 1 ] && { warn "skipping – TCP unreachable"; return; }

  local with_sni no_sni fake_sni frag_sni=0
  with_sni=$(echo Q | openssl s_client -connect "$RESOLVED_IP:$VPN_PORT_TCP" \
    -servername "$VPN_HOST" -brief 2>&1 \
    | grep -cE 'Protocol version|Verification' || true)

  no_sni=$(echo Q | openssl s_client -connect "$RESOLVED_IP:$VPN_PORT_TCP" \
    -brief 2>&1 \
    | grep -cE 'Protocol version|Verification' || true)

  fake_sni=$(echo Q | openssl s_client -connect "$RESOLVED_IP:$VPN_PORT_TCP" \
    -servername "$FAKE_SNI" -brief 2>&1 \
    | grep -cE 'Protocol version|Verification' || true)

  info "TLS with proper SNI ($VPN_HOST):    $([ "$with_sni" -gt 0 ] && echo OK || echo FAIL)"
  info "TLS without SNI:                   $([ "$no_sni" -gt 0 ] && echo OK || echo FAIL)"
  info "TLS with innocent SNI ($FAKE_SNI): $([ "$fake_sni" -gt 0 ] && echo OK || echo FAIL)"

  TLS_PROPER_SNI_OK=$([ "$with_sni" -gt 0 ] && echo 1 || echo 0)
  TLS_NO_SNI_OK=$([ "$no_sni" -gt 0 ] && echo 1 || echo 0)
  TLS_FAKE_SNI_OK=$([ "$fake_sni" -gt 0 ] && echo 1 || echo 0)

  # Reality: the SNI the client actually sends is the cover serverName, not
  # VPN_HOST (often a bare IP). A Reality server is DESIGNED to drop handshakes
  # whose SNI isn't a configured serverName — so the IP / no-SNI / innocent-SNI
  # failures above are Reality working, NOT a censor. Judge the block on the
  # real serverName and skip the generic DPI verdicts (which would misread that
  # selective drop as DPI).
  local reality_sni
  reality_sni=$(_xray_cover_sni 2>/dev/null)
  if [ -n "$reality_sni" ] && [ "$reality_sni" != "$VPN_HOST" ]; then
    local real_sni
    real_sni=$(echo Q | openssl s_client -connect "$RESOLVED_IP:$VPN_PORT_TCP" \
      -servername "$reality_sni" -brief 2>&1 \
      | grep -cE 'Protocol version|Verification' || true)
    info "TLS with Reality serverName:       $([ "$real_sni" -gt 0 ] && echo OK || echo FAIL)"
    TLS_PROPER_SNI_OK=$([ "$real_sni" -gt 0 ] && echo 1 || echo 0)
    if [ "$real_sni" -gt 0 ]; then
      ok "Reality serverName handshake completes → TLS layer not blocked (the IP / no-SNI / innocent-SNI failures above are the Reality server dropping non-matching SNIs by design, not a censor)"
    else
      warn "even the Reality serverName handshake fails → either a block, or a server that refuses unauthenticated TLS probes (some do)"
      add_verdict "Reality serverName TLS probe failed — inconclusive: a censor block OR a server that refuses bare unauthenticated TLS. Cross-check probe 11 (xray-knife): if it tunnels, the transport is NOT blocked"
    fi
    return
  fi

  # If proper-SNI handshake failed, probe TLS-record fragmentation as a
  # bypass test. `-max_send_frag 64` splits the ClientHello across many
  # tiny TLS records — DPIs that don't reassemble records can be evaded.
  # Skipped on the happy path to avoid unnecessary network noise.
  if [ "$with_sni" -eq 0 ]; then
    frag_sni=$(echo Q | openssl s_client -connect "$RESOLVED_IP:$VPN_PORT_TCP" \
      -servername "$VPN_HOST" -brief -max_send_frag 64 2>&1 \
      | grep -cE 'Protocol version|Verification' || true)
    info "TLS with 64-byte record fragments: $([ "$frag_sni" -gt 0 ] && echo OK || echo FAIL)"
    TLS_FRAG_SNI_OK=$([ "$frag_sni" -gt 0 ] && echo 1 || echo 0)
  fi

  if [ "$with_sni" -eq 0 ] && [ "$frag_sni" -gt 0 ]; then
    fail "fragmented TLS bypasses block → DPI does not reassemble TLS records"
    add_verdict "DPI bypassable via TLS-record fragmentation — run a client-side DPI-desync proxy (see recommendation)"
  elif [ "$with_sni" -eq 0 ] && [ "$no_sni" -gt 0 ]; then
    fail "DPI dies only when our SNI is sent → SNI-BASED BLOCKING"
    add_verdict "SNI-based DPI block – server name is in censor blacklist"
  elif [ "$with_sni" -eq 0 ] && [ "$fake_sni" -gt 0 ]; then
    fail "TLS works with fake SNI but not ours → SNI inspection confirmed"
    add_verdict "SNI-based DPI block (confirmed via fake-SNI control)"
  elif [ "$with_sni" -eq 0 ] && [ "$no_sni" -eq 0 ] && [ "$fake_sni" -eq 0 ]; then
    fail "all TLS handshakes to this IP fail → TLS-LEVEL DPI or IP block"
    add_verdict "TLS DPI rejects any handshake to this IP"
  else
    ok "TLS handshake completes – TCP/TLS layer not blocked"
  fi
}

# Probe 4: distinguishes three filtering classes that all manifest as HTTP
# failures from a vanilla curl but pass through a real browser:
#   1) UA filtering only       — header alone is enough to be allowed
#   2) JA3/TLS-fp filtering    — needs full browser-grade ClientHello (curl-impersonate)
#   3) Block-page UA filtering — 403/451 with custom block page for default UA
# Real JA3 testing requires curl-impersonate-chrome (auto-detected, optional).
probe_request_filter() {
  hdr "4. Request-header / TLS-fingerprint filtering"
  [ "$TCP_OK" -ne 1 ] && { warn "skipping – TCP unreachable"; return; }

  local curl_default curl_chrome curl_impersonate="" http2_opt="" target_url impersonate_cmd eff_host eff_url_host
  # Reality configs: present the cover serverName as SNI/host, not the bare-IP
  # VPN_HOST (which a Reality server drops by design) — otherwise this probe
  # false-warns "HTTPS layer entirely cut". Identical to VPN_HOST for
  # non-Reality targets, so their behaviour is unchanged.
  eff_host=$(_effective_tls_sni)
  eff_url_host="$eff_host"; case "$eff_url_host" in *:*:*) eff_url_host="[$eff_url_host]" ;; esac
  if [ "$VPN_PORT_TCP" = "443" ]; then target_url="https://$eff_url_host/"; else target_url="https://$eff_url_host:$VPN_PORT_TCP/"; fi
  curl --version 2>/dev/null | grep -qiE 'HTTP2|HTTP/2' && http2_opt="--http2"

  curl_default=$(curl -sk --max-time "$TIMEOUT" \
    --resolve "$eff_host:$VPN_PORT_TCP:$RESOLVED_IP" \
    -o /dev/null -w '%{http_code}' "$target_url" 2>/dev/null)
  [ -n "$curl_default" ] || curl_default="000"

  # shellcheck disable=SC2086
  curl_chrome=$(curl -sk --max-time "$TIMEOUT" $http2_opt \
    --resolve "$eff_host:$VPN_PORT_TCP:$RESOLVED_IP" \
    -H 'user-agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36' \
    -o /dev/null -w '%{http_code}' "$target_url" 2>/dev/null)
  [ -n "$curl_chrome" ] || curl_chrome="000"

  info "curl default UA:    HTTP $curl_default"
  info "Chrome-like UA:     HTTP $curl_chrome"

  UA_DEFAULT_CODE="$curl_default"
  UA_CHROME_CODE="$curl_chrome"

  # Optional 3rd probe: real JA3 via curl-impersonate. Mimics full Chrome
  # ClientHello (ciphers, extensions, curve order, signature algorithms).
  if impersonate_cmd=$(_find_curl_impersonate); then
    curl_impersonate=$("$impersonate_cmd" -sk --max-time "$TIMEOUT" \
      --resolve "$eff_host:$VPN_PORT_TCP:$RESOLVED_IP" \
      -o /dev/null -w '%{http_code}' "$target_url" 2>/dev/null)
    [ -n "$curl_impersonate" ] || curl_impersonate="000"
    info "Impersonate Chrome: HTTP $curl_impersonate  ($impersonate_cmd)"
    UA_IMPERSONATE_CODE="$curl_impersonate"
    UA_IMPERSONATE_BIN="$impersonate_cmd"
  else
    info "Impersonate Chrome: skipped (no curl-impersonate-chrome installed)"
  fi

  # Order matters: check JA3-only first (most specific), then UA, then 000-fail.
  if [ -n "$impersonate_cmd" ] \
     && [ "$curl_impersonate" != "000" ] \
     && [ "$curl_default" = "000" ] && [ "$curl_chrome" = "000" ]; then
    fail "only real-JA3 client reaches the server → TLS-fingerprint (JA3) DPI"
    add_verdict "TLS fingerprint (JA3/JA4) filtering — only browser-grade ClientHello accepted"
  elif [ -n "$impersonate_cmd" ] \
       && [ "$curl_impersonate" != "000" ] \
       && [ "$curl_default" = "000" ] && [ "$curl_chrome" != "000" ]; then
    info "all three pass at the fingerprint level — UA-only filter (see below)"
    warn "Chrome-UA works, default-UA fails (connection) → User-Agent filtering (not TLS-fp)"
    add_verdict "User-Agent based filtering (not JA3 — same TLS stack)"
  elif [ "$curl_default" = "000" ] && [ "$curl_chrome" != "000" ]; then
    warn "Chrome-UA works, default-UA fails (connection) → User-Agent filtering (not TLS-fp)"
    add_verdict "User-Agent based filtering (not JA3 — same TLS stack)"
  elif [ "$curl_default" = "000" ] && [ "$curl_chrome" = "000" ] \
       && { [ -z "$impersonate_cmd" ] || [ "$curl_impersonate" = "000" ]; }; then
    warn "all requests fail – HTTPS layer entirely cut"
  elif printf '%s' "$curl_default" | grep -qE '^(403|451)$' \
       && ! printf '%s' "$curl_chrome" | grep -qE '^(403|451)$'; then
    warn "default-UA gets HTTP $curl_default block page, Chrome-UA gets $curl_chrome → UA filtering via block page"
    add_verdict "User-Agent based filtering (not JA3 — same TLS stack)"
  else
    ok "HTTPS responds (HTTP $curl_default) – no UA / fingerprint filtering detected"
  fi
}

probe_rst_injection() {
  hdr "5. Mid-handshake RST detection"
  [ "$TCP_OK" -ne 1 ] && { warn "skipping – TCP unreachable"; return; }

  local rc=0 elapsed hs_ok=0 rst_sni
  RST_TMP_OUT=$(_mktmp tls)
  RST_TMP_TIME=$(_mktmp time)

  # Use the Reality serverName when present (see _effective_tls_sni): a bare-IP
  # SNI is dropped by a Reality server by design, which would otherwise look
  # like a DPI-injected RST.
  rst_sni=$(_effective_tls_sni)
  { time -p openssl s_client -connect "$RESOLVED_IP:$VPN_PORT_TCP" \
       -servername "$rst_sni" -brief </dev/null >"$RST_TMP_OUT" 2>&1
    rc=$?
  } 2>"$RST_TMP_TIME"

  elapsed=$(awk '/^real/{print $2}' "$RST_TMP_TIME")
  elapsed="${elapsed:-0}"
  grep -qE 'Protocol version|Verification' "$RST_TMP_OUT" && hs_ok=1
  rm -f "$RST_TMP_OUT" "$RST_TMP_TIME"
  RST_TMP_OUT="" RST_TMP_TIME=""

  RST_ELAPSED="$elapsed"
  RST_HS_OK="$hs_ok"
  RST_RC="$rc"

  info "TLS attempt took ${elapsed}s (rc=$rc, handshake=$([ "$hs_ok" -eq 1 ] && echo OK || echo FAIL))"

  if [ "$hs_ok" -eq 1 ]; then
    ok "handshake completes cleanly – no RST injection"
  elif awk "BEGIN{exit !($elapsed < 1.0)}"; then
    fail "handshake dies fast (${elapsed}s) → likely DPI-injected RST"
    add_verdict "Active RST injection by DPI mid-handshake"
  elif awk "BEGIN{exit !($elapsed >= $TIMEOUT - 1)}"; then
    fail "handshake hangs full timeout (${elapsed}s) → silent drop (no RST, blackhole)"
    add_verdict transport-silent-drop "Silent packet drop (firewall blackhole, not DPI reset)"
  else
    warn "handshake failed at ${elapsed}s – inconclusive timing"
  fi
}

probe_udp_protocols() {
  hdr "6. UDP-based protocols (IKEv2 / QUIC)"

  if _ike_probe "$IKEV2_HOST" 500; then
    ok "UDP 500 (IKEv2) replies to IKE_SA_INIT – service alive"
    UDP_IKE500_OK=1
  else
    info "UDP 500 (IKEv2) silent – DPI block, no service, or no perl available"
  fi

  if _ike_probe "$IKEV2_HOST" 4500; then
    ok "UDP 4500 (IPsec NAT-T) replies to IKE_SA_INIT – service alive"
    UDP_IKE4500_OK=1
  else
    info "UDP 4500 silent – DPI block, no service, or no perl available"
  fi

  # QUIC / UDP-443 reachability. Primary path is a dependency-free Version-
  # Negotiation probe (perl UDP): a long-header packet with an unsupported version
  # → an RFC-9000 server MUST reply with a VN packet, proving UDP/443 + QUIC reach
  # with no crypto. The baseline is a KNOWN QUIC host, so silence = this network
  # blocks UDP/443 (an arbitrary host can't be a "no-QUIC" control — most run it).
  # A Hysteria2 server is itself a QUIC endpoint → probe it too; a Reality/TCP
  # server has no UDP listener, so only the network baseline applies there.
  if check_cmd perl; then
    local qbase qtarget="" qport=""
    qbase=$(_quic_vn_probe "$XRAY_QUIC_BASELINE" 443 "$TIMEOUT")
    if [ -n "${HYSTERIA_DETECTED:-}" ] && [ -n "${VPN_HOST:-}" ] && [ "$VPN_HOST" != "www.example.com" ]; then
      qport="${VPN_PORT_TCP:-443}"
      qtarget=$(_quic_vn_probe "$VPN_HOST" "$qport" "$TIMEOUT")
    fi
    UDP_QUIC_BASELINE="$qbase"; UDP_QUIC_TARGET="$qtarget"
    UDP_QUIC_VERDICT=$(_classify_udp_quic "$qbase" "$qtarget")
    case "$UDP_QUIC_VERDICT" in
      net-blocked)
        warn "UDP/443 + QUIC unreachable even to the known baseline (${XRAY_QUIC_BASELINE}: ${qbase}) — UDP/443 looks blocked or throttled in this network"
        add_verdict "UDP/443 appears blocked in this network — QUIC-based transports (Hysteria2, QUIC covers, and Reality's xtls-rprx-vision-udp443 passthrough) won't work here. Single-vantage: re-test from the target region to confirm it's the network, not a one-off" ;;
      target-quic)
        ok "UDP/443 reachable — QUIC baseline replies and the target answers QUIC on ${qport}" ;;
      net-ok-target-silent)
        ok "UDP/443 usable here (QUIC baseline replies)"
        info "target gave no QUIC reply on ${qport} — expected for an obfs'd Hysteria2 (salamander ignores unauth packets) or a TCP server; not a block" ;;
      net-ok)
        ok "UDP/443 usable here (QUIC baseline replies) — relevant to QUIC covers and the -udp443 passthrough" ;;
    esac
  elif curl --version 2>/dev/null | grep -qiE 'HTTP3|HTTP/3'; then
    # Fallback: a real HTTP/3 GET (baseline only) when there's no perl but curl
    # has h3 — rarer, but a stronger positive signal where available.
    local quic_code
    quic_code=$(curl -sk --max-time "$TIMEOUT" --http3 -o /dev/null -w '%{http_code}' \
      "https://${XRAY_QUIC_BASELINE}/" 2>/dev/null || echo "000")
    UDP_QUIC_CODE="$quic_code"
    if [ "$quic_code" != "000" ]; then
      UDP_QUIC_BASELINE="vn"; ok "UDP 443 (QUIC/HTTP3) to baseline works"
    else
      UDP_QUIC_BASELINE="silent"
      warn "UDP 443 (QUIC) to baseline fails – QUIC may be blocked network-wide"
      add_verdict "UDP 443 / QUIC blocked – common in restrictive networks"
    fi
    UDP_QUIC_VERDICT=$(_classify_udp_quic "$UDP_QUIC_BASELINE" "")
  else
    info "no perl and no curl HTTP/3 — skipping QUIC / UDP-443 probe"
  fi
}

# Pure: is this network only letting through a permitted (whitelisted) set of
# destinations? Compares reach of "permitted-class" hosts vs neutral controls.
#   restricted    permitted-class reachable, ALL controls fail → captive/whitelist-only
#                 path (the zero-balance / restricted-LTE state where only the
#                 operator's permitted list resolves and connects)
#   open          controls reachable → the network is not whitelist-restricted
#   permitted-unreachable  controls fine but permitted-class hosts are not — NOT a
#                 restriction: normal when probing from outside their region (those
#                 services often refuse foreign clients)
#   no-network    nothing reachable at all → no connectivity, nothing to conclude
_classify_whitelist() {
  local perm_ok="$1" ctl_ok="$2"
  if [ "${ctl_ok:-0}" -gt 0 ] 2>/dev/null; then
    [ "${perm_ok:-0}" -gt 0 ] 2>/dev/null && { echo "open"; return 0; }
    echo "permitted-unreachable"; return 0
  fi
  [ "${perm_ok:-0}" -gt 0 ] 2>/dev/null && { echo "restricted"; return 0; }
  echo "no-network"
}

# Whitelist-restriction probe. Some mobile networks (notably in restricted/zero-balance
# states) permit only a curated list of destinations; a VPN then fails for a reason that
# has nothing to do with DPI — the whole path is captive. Distinguishing that from a
# block matters, because the fix is different (use an entry host inside the permitted
# ranges, not a stealthier transport). TCP-only and bounded: no HTTP fetch, no new deps.
probe_whitelist() {
  local perm_ok=0 perm_n=0 ctl_ok=0 ctl_n=0 h
  # This is a coarse reach/no-reach question over ~4 hosts, so cap the per-host wait:
  # at the default TIMEOUT=10 a fully dark network would otherwise cost ~40s in a run
  # where this probe is on by default. `local TIMEOUT` is seen by _nc_tcp_probe (bash
  # dynamic scoping) and restored on return; never RAISE a user's lower timeout.
  local TIMEOUT="${TIMEOUT:-10}"
  [ "$TIMEOUT" -gt 3 ] 2>/dev/null && TIMEOUT=3
  # shellcheck disable=SC2086
  for h in $WHITELIST_HOSTS; do
    perm_n=$((perm_n+1)); _nc_tcp_probe "$h" 443 && perm_ok=$((perm_ok+1))
  done
  # shellcheck disable=SC2086
  for h in $WHITELIST_CONTROL_HOSTS; do
    ctl_n=$((ctl_n+1)); _nc_tcp_probe "$h" 443 && ctl_ok=$((ctl_ok+1))
  done
  WHITELIST_STATUS=$(_classify_whitelist "$perm_ok" "$ctl_ok")
  WHITELIST_PERMITTED_OK="$perm_ok"; WHITELIST_CONTROL_OK="$ctl_ok"

  case "$WHITELIST_STATUS" in
    restricted)
      hdr "Whitelist-restricted network"
      fail "this network reaches ${perm_ok}/${perm_n} permitted-list hosts but 0/${ctl_n} neutral controls — the PATH is whitelist-restricted, not DPI-blocked"
      add_verdict "Network is whitelist-restricted (captive): permitted-list destinations connect while every neutral control fails, so the whole path — not your protocol — is the constraint. A stealthier transport will not help. Place the entry host inside the permitted ranges (an operator-permitted network/CDN), or test from an unrestricted path. Typical on a zero-balance / restricted mobile state" ;;
    permitted-unreachable)
      info "whitelist check: controls reachable, permitted-list hosts are not (${perm_ok}/${perm_n}) — not a restriction, expected when probing from outside their region" ;;
    no-network)
      info "whitelist check: nothing reachable (0/${perm_n} permitted, 0/${ctl_n} controls) — no connectivity, see probe 2" ;;
    *)
      info "whitelist check: network reaches both permitted-list (${perm_ok}/${perm_n}) and neutral controls (${ctl_ok}/${ctl_n}) — not whitelist-restricted" ;;
  esac
}

# ASN + ISO country for an IP in one lookup: echoes "ASxxxx\t<CC>" (either may be empty).
# HTTPS-first (an on-path censor could spoof plaintext ip-api), ip-api HTTP as fallback.
_hop_info() {
  local ip="$1" j as cc
  [ -n "$ip" ] || return 0
  # a private/reserved hop (LAN gateway, CGN, etc.) has no public ASN/geo — don't
  # ship it to a third-party reputation service, and don't waste the round-trip.
  _is_special_ipv4 "$ip" && return 0
  j=$(_curl "https://ipinfo.io/${ip}/json" 2>/dev/null)
  as=$(printf '%s' "$j" | sed -nE 's/.*"org":[[:space:]]*"(AS[0-9]+).*/\1/p' | head -1)
  cc=$(printf '%s' "$j" | sed -nE 's/.*"country":[[:space:]]*"([A-Z][A-Z])".*/\1/p' | head -1)
  if [ -z "$as" ] && [ -z "$cc" ]; then
    j=$(_curl "http://ip-api.com/json/${ip}?fields=as,countryCode" 2>/dev/null)
    as=$(printf '%s' "$j" | sed -nE 's/.*"as":"(AS[0-9]+).*/\1/p' | head -1)
    cc=$(printf '%s' "$j" | sed -nE 's/.*"countryCode":"([A-Z][A-Z])".*/\1/p' | head -1)
  fi
  printf '%s\t%s' "${as:-}" "${cc:-}"
}

# Bounded traceroute to an IPv4 target; echoes "<last_responding_hop>\t<last_ip>\t<reached>"
# where reached=1 iff the trace hit the target itself. Uses UDP (unprivileged) + numeric
# (-n) so it needs no DNS and no root. Worst case ~max_hops * wait seconds (all hops dark).
_traceroute_scan() {
  local target="$1" maxh="$2" out line hop ip last_hop="" last_ip="" reached=0
  # Clamp the per-hop wait: traceroute rejects -w 0 ("wait time must be > 0") and the
  # failure is swallowed by 2>/dev/null, which would surface as a misleading
  # "no usable hops (ICMP filtered)". Same guard as LOCALIZE_MAX_HOPS.
  local w="${LOCALIZE_WAIT:-1}"
  case "$w" in ''|*[!0-9]*) w=1 ;; esac
  [ "$w" -lt 1 ]  2>/dev/null && w=1
  [ "$w" -gt 10 ] 2>/dev/null && w=10
  out=$(traceroute -n -w "$w" -q 1 -m "$maxh" "$target" 2>/dev/null)
  while IFS= read -r line; do
    hop=$(printf '%s' "$line" | awk '{print $1}')
    case "$hop" in ''|*[!0-9]*) continue ;; esac       # skip the banner / non-hop lines
    ip=$(printf '%s' "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
    [ -z "$ip" ] && continue                           # a "* * *" (no reply) hop
    last_hop="$hop"; last_ip="$ip"
    [ "$ip" = "$target" ] && reached=1
  done <<EOF
$out
EOF
  printf '%s\t%s\t%s' "${last_hop:-0}" "${last_ip:-}" "$reached"
}

# Pure: where does the block sit, from the trace result + reachability + hop budget?
#   endpoint          reached the target → path is clear, block is at the endpoint/DPI
#   incomplete        target is REACHABLE (TCP ok) or the trace hit the hop budget →
#                     the trace just didn't finish; this is NOT a block
#   access-edge       genuinely died within the first 3 hops → your ISP / access edge
#   near-destination  genuinely died in the target's own country → at/near destination
#   transit           genuinely died mid-path elsewhere → a national/transit filter
#   unknown           no usable hops (ICMP filtered/rate-limited)
# `reachable`=1 (target answers TCP) and last_hop>=max_hops both mean "didn't complete",
# NOT "blocked" — traceroute's final hops are frequently ICMP-filtered even to live hosts.
_localize_class() {
  local reached="$1" reachable="$2" last_hop="$3" max_hops="$4" last_cc="$5" target_cc="$6"
  if [ "$reached" = "1" ]; then echo "endpoint"; return 0; fi
  # Claim a block ONLY when unreachability was actually MEASURED (reachable="0").
  # reachable="1" → target answers TCP, so it's not a block whatever the trace shows.
  # reachable=""  → the TCP probe never ran (e.g. --skip tcp / --only without tcp):
  #                 "not measured" is NOT evidence of a block — stay at `incomplete`.
  if [ "$reachable" != "0" ]; then echo "incomplete"; return 0; fi
  case "$last_hop" in ''|0|*[!0-9]*) echo "unknown"; return 0 ;; esac
  case "$max_hops" in ''|*[!0-9]*) : ;; *) [ "$last_hop" -ge "$max_hops" ] && { echo "incomplete"; return 0; } ;; esac
  if [ "$last_hop" -le 3 ]; then echo "access-edge"; return 0; fi
  if [ -n "$last_cc" ] && [ "$last_cc" = "$target_cc" ]; then echo "near-destination"; return 0; fi
  echo "transit"
}

# Censorship localization — when the target is blocked, WHERE is the block? A bounded
# traceroute finds the last responding hop; its ASN/country (+ whether the trace reached
# the target) localizes the apparatus: your ISP edge, a transit/national filter, or the
# destination side. Runs only when the target is TCP-unreachable or --localize is given.
# Share-safe: ASN / country / hop-number only; raw hop IPs solely under --reveal.
probe_localize() {
  # Auto-run ONLY on measured unreachability (probe 2 ran AND the target failed);
  # `--localize` forces a run regardless. A skipped probe 2 must not look like a block.
  if ! { [ "${TCP_TESTED:-0}" = "1" ] && [ "${TCP_OK:-0}" = "0" ]; } && [ "${LOCALIZE:-0}" != "1" ]; then
    return 0   # silent no-op
  fi
  [ -n "${RESOLVED_IP:-}" ] || return 0
  case "$RESOLVED_IP" in *:*) LOCALIZE_STATUS="ipv6-skip"; return 0 ;; esac          # IPv4 only for now
  if ! check_cmd traceroute; then LOCALIZE_STATUS="no-traceroute"; return 0; fi

  hdr "Censorship localization (path)"
  # Sanitize the hop budget: it's a user env knob, so guard 0 / negative / non-numeric /
  # absurd values (traceroute -m 0 probes nothing → a misleading "no hops" read).
  local _mh_raw="${LOCALIZE_MAX_HOPS:-}" mh="${LOCALIZE_MAX_HOPS:-20}"
  case "$mh" in ''|*[!0-9]*) mh=20 ;; esac
  [ "$mh" -lt 1 ]  2>/dev/null && mh=20
  [ "$mh" -gt 64 ] 2>/dev/null && mh=64
  [ -n "$_mh_raw" ] && [ "$_mh_raw" != "$mh" ] && info "LOCALIZE_MAX_HOPS='${_mh_raw}' is out of range (1-64) — using ${mh}"
  info "tracing the path to the target to locate where the block sits (bounded, ~${mh}s worst case)"
  local scan last_hop last_ip reached hopinfo asn cc target_cc
  scan=$(_traceroute_scan "$RESOLVED_IP" "$mh")
  last_hop=${scan%%$'\t'*}; scan=${scan#*$'\t'}; last_ip=${scan%%$'\t'*}; reached=${scan##*$'\t'}
  hopinfo=$(_hop_info "$last_ip"); asn=${hopinfo%%$'\t'*}; cc=${hopinfo##*$'\t'}
  target_cc=""; [ "$reached" != "1" ] && { target_cc=$(_hop_info "$RESOLVED_IP"); target_cc=${target_cc##*$'\t'}; }
  # tri-state: 1 = reachable · 0 = measured unreachable · "" = probe 2 never ran (unknown)
  local reachable=""
  if [ "${TCP_TESTED:-0}" = "1" ]; then reachable=0; [ "${TCP_OK:-0}" = "1" ] && reachable=1; fi
  LOCALIZE_STATUS="ran"; LOCALIZE_LAST_HOP="$last_hop"; LOCALIZE_LAST_ASN="$asn"
  LOCALIZE_LAST_CC="$cc"; LOCALIZE_REACHED="$reached"
  LOCALIZE_CLASS=$(_localize_class "$reached" "$reachable" "$last_hop" "$mh" "$cc" "$target_cc")
  case "$LOCALIZE_CLASS" in
    endpoint)
      if [ "$reachable" = "1" ]; then
        ok "the target is fully reachable — the trace completes and TCP is up, so there's no block to localize"
      else
        ok "the trace REACHES the target's IP but the service isn't answering — the block is at the endpoint / DPI, not a network-path drop (consistent with SNI or protocol filtering, or a stateful reset)"
      fi ;;
    incomplete)
      if [ "$reachable" = "1" ]; then
        ok "the target is REACHABLE (TCP ok) — no block to localize; the trace just didn't reach it (its final hops are ICMP-filtered, common even for live hosts)"
      elif [ -z "$reachable" ]; then
        info "probe 2 (TCP reachability) did not run, so there is no evidence the target is blocked — the trace alone can't tell a block from an ICMP-filtered path. Include the tcp probe (drop --skip tcp / add it to --only) for a localization verdict"
      else
        info "the trace ran out of hop budget at hop ${last_hop} (raise LOCALIZE_MAX_HOPS) — didn't reach the target, so localization is inconclusive, NOT a confirmed block"
      fi ;;
    access-edge)
      fail "the path dies after only ${last_hop} hop(s) — the block is very close to you (your access network / ISP edge)"
      add_verdict "Block localized to the access edge: the path to the target dies after ${last_hop} hop(s)$( [ -n "$asn" ] && printf ' at %s' "$asn")$( [ -n "$cc" ] && printf ' (%s)' "$cc") — the filtering is in your local/ISP network, not upstream" ;;
    near-destination)
      warn "the path dies at hop ${last_hop} inside the destination's own network${asn:+ ($asn${cc:+, $cc})} — the block is at/near the destination side" ;;
    transit)
      warn "the path dies at hop ${last_hop} in transit${asn:+ ($asn${cc:+, $cc})} — a mid-path drop, consistent with a national / transit-level filter"
      add_verdict "Block localized to transit: the path dies mid-route at hop ${last_hop}${asn:+ ($asn${cc:+, $cc})}, before reaching the target — consistent with an upstream (national / transit) filter rather than a local or endpoint block" ;;
    unknown)
      info "traceroute returned no usable hops (ICMP likely rate-limited or filtered) — localization inconclusive" ;;
  esac
  reveal "last responding hop = ${last_ip:-?} (hop ${last_hop:-?}), reached_target=${reached}"
}

# Best-effort ACTIVE physical NIC to probe AROUND a full tunnel (echoes "" if none).
# Requires a live carrier + a routable (non-link-local) IPv4 so we don't pick a
# stale/self-assigned interface.
_physical_iface() {
  local i ip4
  if [ "$(uname 2>/dev/null)" = "Darwin" ]; then
    for i in $(ifconfig -l 2>/dev/null); do
      case "$i" in
        en*|bridge*)
          ifconfig "$i" 2>/dev/null | grep -q 'status: active' || continue
          ip4=$(ifconfig "$i" 2>/dev/null | awk '/inet /{print $2; exit}')
          case "$ip4" in ''|169.254.*) continue ;; esac
          printf '%s' "$i"; return 0 ;;
      esac
    done
  else
    ip -o -4 addr show up scope global 2>/dev/null | awk '{print $2}' \
      | grep -Ev '^(utun|tun|tap|ppp|wg|ipsec|lo|docker|veth|br-)' | head -1
  fi
}

# Public egress IP + ISO country on a given interface ("" = default path / through the
# tunnel). Echoes "<ip>\t<cc>" or nothing. Uses HTTPS so an on-path censor can't spoof it.
_egress_ip_cc() {
  local j ip cc
  command -v jq >/dev/null 2>&1 || return 0
  if [ -n "${1:-}" ]; then j=$(_curl --interface "$1" https://ipinfo.io/json 2>/dev/null)
  else                     j=$(_curl https://ipinfo.io/json 2>/dev/null); fi
  ip=$(printf '%s' "$j" | jq -r '.ip // empty' 2>/dev/null)
  cc=$(printf '%s' "$j" | jq -r '.country // empty' 2>/dev/null)
  if [ -z "$ip" ]; then
    if [ -n "${1:-}" ]; then j=$(_curl --interface "$1" https://ifconfig.co/json 2>/dev/null)
    else                     j=$(_curl https://ifconfig.co/json 2>/dev/null); fi
    ip=$(printf '%s' "$j" | jq -r '.ip // empty' 2>/dev/null)
    cc=$(printf '%s' "$j" | jq -r '.country_iso // empty' 2>/dev/null)
  fi
  [ -n "$ip" ] && printf '%s\t%s' "$ip" "$cc"
}

# Pure: does the tunnel actually change our egress? through_ip vs around_ip →
#   captured             (different IPs → tunnel carries our traffic)
#   leak                 (same IP → traffic is NOT going through the tunnel)
#   captured-unverified  (got the through-IP but couldn't probe the physical NIC)
#   no-exit              (couldn't determine the egress at all)
_tunnel_effect() {
  local t="$1" a="$2"
  [ -z "$t" ] && { echo "no-exit"; return 0; }
  [ -z "$a" ] && { echo "captured-unverified"; return 0; }
  [ "$t" = "$a" ] && { echo "leak"; return 0; }
  echo "captured"
}

# VPN tunnel effectiveness — the "run detect-blocking while your VPN is up" probe.
# When the default route egresses via a tunnel (or --via-tunnel is forced), it compares
# the public egress THROUGH the tunnel vs AROUND it (bound to the physical NIC). Different
# egress = the tunnel is really carrying your traffic (and where it exits); same egress =
# a leak / split-tunnel / dead tunnel. No OpenVPN dependency, no root — just the routing
# and the tunnel you already have up. Silent (no header) when there's no tunnel to report.
probe_tunnel() {
  local def_if is_tun=0 phys through around t_ip t_cc a_ip a_cc
  def_if=$(route -n get default 2>/dev/null | awk '/interface:/{print $2; exit}')
  [ -z "$def_if" ] && def_if=$(ip -o -4 route show default 2>/dev/null | awk '{print $5; exit}')
  case "$def_if" in utun*|tun*|tap*|ppp*|wg*|ipsec*) is_tun=1 ;; esac
  TUNNEL_DEFAULT_IS_TUN="$is_tun"

  if [ "$is_tun" != "1" ] && [ "$VIA_TUNNEL" != "1" ]; then
    TUNNEL_STATUS="no-tunnel"; return 0   # common case: stay silent, JSON still records it
  fi

  hdr "VPN tunnel effectiveness"
  if ! command -v jq >/dev/null 2>&1; then
    warn "jq not available — skipping tunnel effectiveness"; TUNNEL_STATUS="skipped"; return 0
  fi

  phys="$def_if"
  case "$phys" in utun*|tun*|tap*|ppp*|wg*|ipsec*|'') phys=$(_physical_iface) ;; esac

  through=$(_egress_ip_cc "")
  t_ip=${through%%$'\t'*}; t_cc=${through#*$'\t'}; [ "$t_cc" = "$t_ip" ] && t_cc=""
  around=""; [ -n "$phys" ] && around=$(_egress_ip_cc "$phys")
  a_ip=${around%%$'\t'*}; a_cc=${around#*$'\t'}; [ "$a_cc" = "$a_ip" ] && a_cc=""

  TUNNEL_EXIT_CC="$t_cc"
  TUNNEL_STATUS=$(_tunnel_effect "$t_ip" "$a_ip")
  case "$TUNNEL_STATUS" in
    captured)
      TUNNEL_EXIT_DIFFERS=1
      ok "traffic exits THROUGH the tunnel — exit country ${t_cc:-?}$( [ -n "$a_cc" ] && printf ' (physical NIC would exit %s)' "$a_cc" )"
      info "probes here run through the tunnel, so they see the EXIT's network, not your local one — to test your local blocking, probe around it (physical NIC)" ;;
    leak)
      TUNNEL_EXIT_DIFFERS=0
      fail "your public IP is IDENTICAL with and without the tunnel — traffic is NOT going through it"
      add_verdict "VPN tunnel is present but egress is unchanged vs the physical NIC — traffic is bypassing the tunnel (leak / split-tunnel / dead tunnel). Verify redirect-gateway and that the tunnel actually established" ;;
    captured-unverified)
      TUNNEL_EXIT_DIFFERS=""
      info "current exit country: ${t_cc:-?}$( [ "$is_tun" = "1" ] && printf ' (default route is a tunnel)' )"
      info "couldn't probe the physical NIC to compare (bind failed — likely policy routing or a nested VPN), so whether a tunnel is responsible is UNVERIFIED" ;;
    no-exit)
      warn "couldn't determine the public egress (no network, or the IP-echo lookup was blocked)" ;;
  esac
  reveal "exit IP = ${t_ip:-?} (through) | physical NIC IP = ${a_ip:-?} (${phys:-?})"
}

# Pure: OpenVPN control-channel fingerprintability from its posture knobs, ordered
# most-hardened first. Echoes a class the probe maps to a verdict/recommendation.
#   wrapped          obfuscation layer (scramble/xor/stunnel) — opcode AND the
#                    handshake traffic-shape are hidden; best against DPI.
#   probe-resistant  tls-crypt(-v2) — control channel encrypted, so the opcode is
#                    hidden and an anonymous active probe is refused. Residual: the
#                    opening handshake's packet length/timing burst is still a tell.
#   hmac-only        tls-auth — the HMAC drops an anonymous probe, but the opcode
#                    is still CLEARTEXT, so a passive opcode fingerprint still flags it.
#   exposed          neither — cleartext opcode AND the server answers an anonymous
#                    reset → trivial passive + active fingerprint (USENIX'22).
_ovpn_fingerprintability() {
  local tls_crypt="$1" tls_auth="$2" obfs="$3"
  if [ "$obfs" = "1" ];      then echo "wrapped";         return 0; fi
  if [ "$tls_crypt" = "1" ]; then echo "probe-resistant"; return 0; fi
  if [ "$tls_auth" = "1" ];  then echo "hmac-only";       return 0; fi
  echo "exposed"
}

probe_openvpn() {
  hdr "7. OpenVPN reachability + posture"

  if nc -uz -w "$TIMEOUT" "$OPENVPN_HOST" "$OPENVPN_PORT_UDP" 2>/dev/null; then
    ok "UDP $OPENVPN_PORT_UDP (OpenVPN UDP) port accessible"
    OPENVPN_UDP_OK=1
  else
    info "UDP $OPENVPN_PORT_UDP no response (UDP probes often inconclusive)"
    OPENVPN_UDP_OK=0
  fi

  if _nc_tcp_probe "$OPENVPN_HOST" "$OPENVPN_PORT_TCP"; then
    ok "TCP $OPENVPN_PORT_TCP (OpenVPN TCP) reachable"
    OPENVPN_TCP_OK=1
  else
    fail "TCP $OPENVPN_PORT_TCP unreachable"
    OPENVPN_TCP_OK=0
  fi

  # Active OpenVPN handshake probe. Random session id (zero SID is itself a
  # discriminable fingerprint). Honest verdict: silence is INCONCLUSIVE —
  # could be DPI, but also tls-auth/tls-crypt or a non-OpenVPN service on
  # that port. Opt into STRICT_OPENVPN_VERDICT=1 for a hard verdict.
  if check_cmd perl && check_cmd xxd; then
    local response
    # Pipe directly — shell variables can't carry null bytes (truncates at \x00).
    response=$(perl -e '
      print "\x38";                              # opcode P_CONTROL_HARD_RESET_CLIENT_V2 << 3
      print chr(int(rand(256))) for 1..8;        # random session id
    ' 2>/dev/null | nc -u -w "$TIMEOUT" "$OPENVPN_HOST" "$OPENVPN_PORT_UDP" 2>/dev/null \
      | xxd -p | head -c 4)
    OPENVPN_HANDSHAKE="$response"
    if [ -n "$response" ]; then
      if [ "${response:0:2}" = "40" ]; then
        OPENVPN_HS_REPLIED=1
        # A reply to an UNAUTHENTICATED reset means no tls-crypt/tls-auth is enforced
        # on this port: reachability is GOOD, but stealth is BAD — the endpoint is
        # confirmable by the exact active probe a censor uses (USENIX'22) and
        # enumerable by anyone. The old wording ("handshake replied = good") missed this.
        ok "OpenVPN server replied to an anonymous reset (opcode 0x40) — reachable"
        info "but answering an unauthenticated probe means the endpoint is active-probe fingerprintable"
        [ "${OVPN_TLS_CRYPT:-}" = "1" ] && warn "the profile declares tls-crypt, yet this port answered an unauthenticated reset — tls-crypt may not be active here"
        add_verdict "OpenVPN answers an unauthenticated HARD_RESET (no tls-crypt/tls-auth in force) — a censor's active prober confirms it is OpenVPN on sight and anyone can enumerate the endpoint (USENIX'22 'OpenVPN is Open to VPN Fingerprinting'). Enable tls-crypt-v2 to encrypt the control channel and refuse anonymous probes"
      else
        warn "got data back but not OpenVPN-shaped: $response"
      fi
    else
      if [ "$OPENVPN_UDP_OK" = "1" ]; then
        # Silence with the port open is AMBIGUOUS. If the profile carries an auth
        # layer, silence is EXPECTED (tls-crypt/tls-auth correctly drops the
        # unauthenticated probe) — the probe-resistant posture, NOT a block.
        if [ "${OVPN_TLS_CRYPT:-}" = "1" ] || [ "${OVPN_TLS_AUTH:-}" = "1" ]; then
          ok "no reply to the anonymous probe — EXPECTED: the profile's tls-crypt/tls-auth refuses it (probe-resistant, not a block)"
        else
          warn "no OpenVPN handshake reply – inconclusive (DPI, no service, or an undeclared tls-auth/tls-crypt)"
          if [ "$STRICT_OPENVPN_VERDICT" = "1" ]; then
            add_verdict "OpenVPN handshake silently dropped – protocol-signature DPI"
          fi
        fi
      else
        info "no reply (UDP port likely blocked, see above)"
      fi
    fi
  else
    info "perl or xxd missing – skipping active OpenVPN handshake probe"
  fi

  if [ "$OPENVPN_TCP_OK" = "1" ] && [ "$TCP_OK" = "0" ]; then
    add_verdict "OpenVPN TCP port open but main port blocked → port/protocol-targeted"
  fi

  # ---- config fingerprintability posture (only when --ovpn-config was parsed) ----
  if [ -n "${OVPN_CONFIG:-}" ]; then
    OVPN_POSTURE=$(_ovpn_fingerprintability "${OVPN_TLS_CRYPT:-0}" "${OVPN_TLS_AUTH:-0}" "${OVPN_OBFS:-0}")
    info "config posture: proto=${OVPN_PROTO:-?}/${OPENVPN_PORT_UDP} · tls-crypt=${OVPN_TLS_CRYPT:-?} · tls-auth=${OVPN_TLS_AUTH:-?} · obfs=${OVPN_OBFS:-?} → fingerprintability: ${OVPN_POSTURE}"
    case "$OVPN_POSTURE" in
      exposed)
        OVPN_FINGERPRINTABLE="yes"
        fail "control channel is unwrapped — cleartext opcode + answers active probes"
        add_verdict "OpenVPN control channel is unwrapped (no tls-crypt/tls-auth): both the passive opcode fingerprint AND active probing identify it on sight (USENIX'22). Enable tls-crypt-v2 (encrypts the control channel, refuses active probes); in hostile-DPI regions wrap it in an obfuscation layer (stunnel / openvpn-scramble) or move to a Reality/Xray transport" ;;
      hmac-only)
        OVPN_FINGERPRINTABLE="yes"
        warn "tls-auth only — refuses active probes, but the opcode is still cleartext"
        add_verdict "OpenVPN uses tls-auth (HMAC): it refuses active probes, but the control-channel opcode is still sent in CLEARTEXT, so a passive opcode fingerprint still flags it. Upgrade tls-auth → tls-crypt-v2 to encrypt the control channel" ;;
      probe-resistant)
        OVPN_FINGERPRINTABLE="partial"
        ok "tls-crypt encrypts the control channel — active-probe resistant"
        info "residual tell: the opening handshake's packet length/timing burst is still OpenVPN-shaped to a passive classifier; an obfuscation wrapper (stunnel/scramble) removes it" ;;
      wrapped)
        OVPN_FINGERPRINTABLE="no"
        ok "obfuscation layer present — control-channel opcode and handshake shape are hidden" ;;
    esac
    [ "$OPENVPN_PORT_UDP" = "1194" ] && info "port 1194 is the OpenVPN default → trivially port-blocked; 443/tcp blends with HTTPS"
    [ "${OVPN_PROTO:-}" = "udp" ] && info "UDP is the first thing dropped in networks that block wholesale UDP — a 443/tcp fallback survives more restrictive vantages"
    reveal "OpenVPN endpoint = ${OPENVPN_HOST}:${OPENVPN_PORT_UDP}/${OVPN_PROTO:-udp}"
    # Honest scope (mirrors the Xray probes): one clean vantage sees port-blocks,
    # active-drops, and config posture — NOT passive DPI classification or volumetric
    # throttling, which need an in-region vantage or a live tunnel.
    info "scope: one clean vantage reads reachability + active-probe response + config posture; passive DPI/throttling needs an in-region vantage"
  fi
}

probe_known_blocked() {
  hdr "8. Control: known-censored reachability"

  # shellcheck disable=SC2086
  set -- $CONTROL_SITES
  local control_total=$#
  local control_pass=0
  local blocked_list=""
  for domain in "$@"; do
    if curl -sk --max-time "$TIMEOUT" -o /dev/null -w '' "https://$domain/" 2>/dev/null; then
      control_pass=$((control_pass+1))
    else
      blocked_list="$blocked_list $domain"
    fi
  done
  info "$control_pass/$control_total known-sensitive domains reachable"

  CONTROL_PASS="$control_pass"
  CONTROL_TOTAL="$control_total"
  CONTROL_BLOCKED="$(printf '%s' "$blocked_list" | sed 's/^[[:space:]]*//')"

  if [ "$control_pass" -eq 0 ]; then
    warn "no sensitive domains reachable → broad censorship environment"
    add_verdict "Broad censorship – none of the control sites reachable"
  elif [ "$control_pass" -eq "$control_total" ]; then
    ok "all control domains reachable – no broad censorship signal"
  else
    warn "partial reachability – blocked/unreachable:${blocked_list}"
    add_verdict "Selective control-site failures (possible filtering or transient issue)"
  fi
}

COMPARE_MATRIX=""        # rows of "sni|port|tls_state|tcp_state"

# Compare matrix: SNI × port. Useful when single-SNI probe fails — operator
# wants to know "does ANY (SNI, port) combo bypass the DPI?".
# Skipped unless --compare-sni or --compare-port is given.
probe_compare_matrix() {
  [ -z "$COMPARE_SNI" ] && [ -z "$COMPARE_PORT" ] && return 0

  hdr "9b. Compare matrix (SNI × port)"
  [ -z "$RESOLVED_IP" ] && { warn "skipping – no resolved IP"; return; }

  local sni_list port_list sni port tls_ok tcp_ok
  # Always include the canonical pair so the matrix is self-comparable.
  sni_list="$VPN_HOST $(printf '%s' "$COMPARE_SNI" | tr ',' ' ')"
  port_list="$VPN_PORT_TCP $(printf '%s' "$COMPARE_PORT" | tr ',' ' ')"

  printf '  %-30s' "SNI \\ Port"
  for port in $port_list; do printf '%-12s' "$port"; done
  printf '\n'

  COMPARE_MATRIX=""
  for sni in $sni_list; do
    [ -z "$sni" ] && continue
    printf '  %-30s' "$sni"
    for port in $port_list; do
      [ -z "$port" ] && continue
      # TCP gate first — skip TLS if port is dead.
      if _nc_tcp_probe "$RESOLVED_IP" "$port"; then
        tcp_ok=1
        if echo Q | openssl s_client -connect "$RESOLVED_IP:$port" \
             -servername "$sni" -brief 2>&1 \
             | grep -qE 'Protocol version|Verification'; then
          tls_ok=1
          printf "%-12s" "TLS✓"
        else
          tls_ok=0
          printf "%-12s" "TCP✓"
        fi
      else
        tcp_ok=0; tls_ok=0
        printf "%-12s" "—"
      fi
      COMPARE_MATRIX="${COMPARE_MATRIX}${sni}|${port}|${tls_ok}|${tcp_ok}
"
    done
    printf '\n'
  done

  # Heuristic verdict: if a non-canonical combo works but the canonical fails,
  # surface as bypass candidate.
  local canonical_failed=0 alt_works=0
  # m_tcp_unused: we recorded TCP state in the matrix for JSON consumers but
  # the heuristic only needs the TLS column. Read into _ to satisfy shellcheck.
  while IFS='|' read -r m_sni m_port m_tls _; do
    [ -z "$m_sni" ] && continue
    if [ "$m_sni" = "$VPN_HOST" ] && [ "$m_port" = "$VPN_PORT_TCP" ]; then
      [ "$m_tls" = "0" ] && canonical_failed=1
    else
      [ "$m_tls" = "1" ] && alt_works=1
    fi
  done <<EOF
$COMPARE_MATRIX
EOF

  if [ "$canonical_failed" = "1" ] && [ "$alt_works" = "1" ]; then
    fail "canonical (host:port) blocked but at least one alt combo works"
    add_verdict "Bypass candidate found in compare matrix — switch client SNI/port"
  elif [ "$canonical_failed" = "1" ]; then
    info "no working alt-combo — blocked uniformly across the tested set"
  else
    ok "canonical pair works; alt combos for reference only"
  fi
}

# Classify a failed tunnel attempt from the tester/curl output. The
# distinction matters for the verdict: a *timeout* on an otherwise-clean
# transport usually means a slow / high-RTT / multi-hop tunnel (raise the
# budget), NOT active interference — whereas a *reset* (RST, closed pipe,
# refused, SSL error) is the real protocol-fingerprint-DPI / config-drift
# signature. Echoes one of: timeout | reset | other.
#
# Covers both xray-knife phrasing (Go net/http: "context deadline
# exceeded", "Client.Timeout", "i/o timeout", "reset by peer", "closed
# pipe", "EOF") and curl phrasing (exit 28 "timed out"; 35/52/56 "reset",
# "Empty reply", "Recv failure", "SSL_ERROR").
_classify_tunnel_failure() {
  local o="$1"
  if printf '%s' "$o" | grep -qiE 'deadline exceeded|i/o timeout|client\.timeout|timeout exceeded|timed out|operation timed out|\(28\)'; then
    printf 'timeout'
  elif printf '%s' "$o" | grep -qiE 'reset by peer|closed pipe|broken pipe|connection refused|empty reply|recv failure|ssl_error|no route to host|unexpected eof|\bEOF\b|\(3[56]\)|\(52\)'; then
    printf 'reset'
  else
    printf 'other'
  fi
}

# ---------- Xray-protocol probes (11-26) + opt-in scanners ----------

# Probe 11 — end-to-end Xray-protocol test via delegation to xray-knife
# (or fallback to xray/sing-box if available). Only runs when --xray-config
# is provided. Reads success/RTT/echoed-IP from the tester's stdout.
#
# WHY NOT NATIVE BASH PROBES: Reality is by-design indistinguishable from
# the fallback target's TLS; Shadowsocks-2022 requires PSK-derived AEAD to
# trigger any protocol-specific behaviour; VLESS-with-fallback proxies bad
# UUIDs to a decoy site. Blind active probing produces false-positives;
# the only honest end-to-end test is an *authenticated* client connection,
# which is exactly what xray-knife does.
probe_xray_protocol() {
  if [ -z "$XRAY_CONFIG" ]; then
    XRAY_STATUS="no-config"
    return 0
  fi

  hdr "11. Xray-protocol end-to-end test"

  if ! XRAY_TESTER_BIN=$(_find_xray_tester); then
    XRAY_STATUS="unavailable"
    warn "skipping — no xray-knife / xray / sing-box in PATH"
    info "install: go install github.com/lilendian0x00/xray-knife@latest"
    return 0
  fi

  XRAY_URL_DISPLAY=$(_summarize_xray_url "$XRAY_CONFIG")
  info "config: $XRAY_URL_DISPLAY"
  info "delegating to: $XRAY_TESTER_BIN"

  # Only xray-knife has the "net http" sub-command we depend on; for raw xray
  # or sing-box we currently can't run the test in one CLI call. Skip clean.
  if [ "$XRAY_TESTER_BIN" != "xray-knife" ]; then
    info "only xray-knife is currently supported for one-shot end-to-end probing"
    info "see https://github.com/lilendian0x00/xray-knife"
    XRAY_STATUS="unavailable"
    return 0
  fi

  # Detect xray-knife API. v10+ exposes `xray-knife http -c URL -d MS` at the
  # top level. Older v9 had `xray-knife net http -c URL -m 1 -d MS` with -m
  # meaning "attempts"; in v10 -m is HTTP method (default GET).
  local out xk_layout
  if "$XRAY_TESTER_BIN" http --help >/dev/null 2>&1; then
    xk_layout="v10"
  elif "$XRAY_TESTER_BIN" net http --help >/dev/null 2>&1; then
    xk_layout="legacy"
  else
    XRAY_STATUS="unavailable"
    warn "xray-knife in PATH doesn't expose http subcommand — unsupported version"
    return 0
  fi

  # Run the probe, then — if it times out on an otherwise-clean transport —
  # retry ONCE with a 4× budget. High-RTT / multi-hop tunnels (e.g. a
  # RU-ingress → EU-egress chain) routinely need 5-8s to complete the
  # Reality handshake; the default 5s budget produces a false "handshake
  # fails" verdict that reads like DPI but is really just latency.
  local _attempt_ms=$(( TIMEOUT * 1000 ))
  local _retry_ms=$(( TIMEOUT * 4 * 1000 ))
  while : ; do
    if [ "$xk_layout" = "v10" ]; then
      out=$("$XRAY_TESTER_BIN" http -c "$XRAY_CONFIG" \
            -d "$_attempt_ms" 2>&1 || true)
    else
      out=$("$XRAY_TESTER_BIN" net http -c "$XRAY_CONFIG" \
            -m 1 -d "$_attempt_ms" 2>&1 || true)
    fi

    # Defensive parsing — xray-knife output evolves between versions.
    # 1) RTT: any "HTTP delay: NNN" / "Delay: NNN" / "delay: NNN" pattern.
    XRAY_RTT_MS=$(printf '%s' "$out" \
                  | grep -ioE 'http delay:[[:space:]]*[0-9]+' | head -1 \
                  | grep -oE '[0-9]+')
    [ -z "$XRAY_RTT_MS" ] && XRAY_RTT_MS=$(printf '%s' "$out" \
                  | grep -ioE '(^|[^a-z])delay:[[:space:]]*[0-9]+' | head -1 \
                  | grep -oE '[0-9]+')

    # 2) Echoed Real IP / location, if the tester resolves them.
    XRAY_TARGET_IP=$(printf '%s' "$out" \
                     | grep -ioE 'real ip:[[:space:]]*[0-9.]+' | head -1 \
                     | grep -oE '[0-9.]+')
    XRAY_TARGET_LOC=$(printf '%s' "$out" \
                      | grep -ioE 'location:[[:space:]]*[A-Z]{2,}' | head -1 \
                      | awk '{print $NF}')

    # 3) Verdict: explicit error words win; otherwise RTT presence implies ok.
    # v10 uses ❌ prefix + "closed pipe" / "EOF" / "reset by peer". Legacy uses
    # "Error:" / "FAILED" / "TIMEOUT".
    if printf '%s' "$out" \
         | grep -qE '❌|closed pipe|EOF|reset by peer|timeout|connection refused|i/o timeout|invalid|error 50|unable to connect|no route to host'; then
      XRAY_STATUS="failed"
    elif [ -n "$XRAY_RTT_MS" ]; then
      XRAY_STATUS="ok"
    else
      XRAY_STATUS="failed"
    fi

    # Auto-retry exactly once on a timeout-class failure. A timeout while
    # "awaiting headers" proves the connection was established (you'd get
    # 'refused' / 'no route' otherwise), so the timeout classification alone
    # is sufficient evidence the tunnel is reachable-but-slow — no need to
    # gate on probe 2 (which --only xray skips anyway).
    if [ "$XRAY_STATUS" = "failed" ] && [ "$XRAY_RETRY_USED" = "0" ] \
       && [ "$(_classify_tunnel_failure "$out")" = "timeout" ]; then
      XRAY_RETRY_USED=1
      _attempt_ms="$_retry_ms"
      warn "handshake exceeded ${TIMEOUT}s — retrying once at $(( TIMEOUT * 4 ))s (high-RTT / multi-hop tunnel?)"
      continue
    fi
    break
  done

  if [ "$XRAY_STATUS" = "ok" ]; then
    if [ "$XRAY_RETRY_USED" = "1" ]; then
      ok "tunnel established on retry, RTT ${XRAY_RTT_MS} ms${XRAY_TARGET_LOC:+ (egress: $XRAY_TARGET_LOC)} — slow handshake, not blocked"
      info "tip: this path needs TIMEOUT≥$(( TIMEOUT * 4 )); set 'TIMEOUT=$(( TIMEOUT * 4 ))' to avoid the first-attempt timeout"
    else
      ok "tunnel established, RTT ${XRAY_RTT_MS} ms${XRAY_TARGET_LOC:+ (egress: $XRAY_TARGET_LOC)}"
    fi
    # Cross-reference: tunnel works despite our other probes seeing DPI.
    if [ "${TLS_PROPER_SNI_OK:-1}" = "0" ] || [ "${DOH_INTEGRITY_STATE:-ok}" = "compromised" ]; then
      add_verdict "Xray protocol bypasses local DPI/DNS-MITM despite environment signals"
    fi
  else
    XRAY_FAIL_KIND=$(_classify_tunnel_failure "$out")
    fail "Xray-protocol end-to-end test failed"
    # Surface a 1-line excerpt of the delegation output to help triage
    # parse/config errors vs network errors. Trim leading whitespace,
    # take the first non-empty line that looks informative.
    local _diag
    _diag=$(printf '%s\n' "$out" \
            | grep -iE 'error|failed|timeout|invalid|refused|unable' \
            | head -1 | sed 's|^[[:space:]│|]*||' | head -c 200)
    [ -n "$_diag" ] && info "$XRAY_TESTER_BIN says: $_diag"
    if [ "$XRAY_FAIL_KIND" = "timeout" ]; then
      # Timed out even after the 4× retry — latency/egress, not DPI.
      # (Timeout class implies the connection was established, so this
      #  verdict stands regardless of whether probe 2 ran.)
      add_verdict "Xray-protocol handshake timed out (even at $(( TIMEOUT * 4 ))s) — slow or throttled tunnel egress, not a fingerprint block. Raise TIMEOUT, or check the server's own upstream/egress health"
    elif [ "${TCP_OK:-1}" = "1" ] && [ "${TLS_PROPER_SNI_OK:-0}" = "1" ]; then
      # TCP + TLS to the server work but the protocol is actively refused.
      add_verdict "Xray-protocol handshake rejected (reset / closed pipe) while plain TLS to the same host succeeds — protocol-fingerprint DPI or config error (verify UUID / keys / flow / target SNI)"
    elif [ "${TCP_OK:-1}" = "1" ]; then
      add_verdict "Xray-protocol handshake fails — see probes 2-3 for root cause"
    else
      info "transport probes were skipped or already blocked; protocol failure is consistent"
    fi
  fi
}

# Probe 12 — full-config end-to-end test via xray-core + SOCKS5.
# Covers what URL-based probe 11 cannot: chained outbounds (dialerProxy),
# fragment, noises, custom routing rules — the entire client config.json
# is executed as-is in a sandboxed background xray process, and we probe
# end-to-end through its SOCKS inbound. Compared to probe 11:
#   probe 11: URL → minimal generated config → test    (fast, lossy)
#   probe 12: your config.json → run xray → SOCKS test (slow, full-fidelity)
# Both can run in the same invocation for comparison.
probe_xray_json() {
  # If only a share-link URL was given (no --xray-config-json FILE),
  # synthesize a minimal config from it so probes 12/13 still run. Needs jq;
  # if synthesis isn't possible the probe skips quietly (probe 11 already
  # exercised the same URL via xray-knife).
  if [ -z "$XRAY_JSON_CONFIG" ] && [ -n "$XRAY_CONFIG" ] && command -v jq >/dev/null 2>&1; then
    local _synth
    if _synth=$(_synthesize_xray_json_from_url "$XRAY_CONFIG"); then
      XRAY_JSON_CONFIG="$_synth"
      XRAY_JSON_SYNTH_PATH="$_synth"
      XRAY_JSON_FROM_URL=1
    fi
  fi

  if [ -z "$XRAY_JSON_CONFIG" ]; then
    XRAY_JSON_STATUS="no-config"
    return 0
  fi

  hdr "12. Xray full-config (json) end-to-end test"

  if [ "$XRAY_JSON_FROM_URL" = "1" ]; then
    info "config synthesized from --xray-config share link (minimal: 1 outbound, no routing/balancer)"
  fi

  if [ ! -r "$XRAY_JSON_CONFIG" ]; then
    fail "config file not readable: $XRAY_JSON_CONFIG"
    XRAY_JSON_STATUS="config-missing"
    return 0
  fi

  if ! check_cmd xray; then
    warn "skipping — 'xray' binary not in PATH"
    info "install: go install github.com/xtls/xray-core/main@latest (rename to 'xray')"
    info "or download: https://github.com/XTLS/Xray-core/releases"
    XRAY_JSON_STATUS="xray-missing"
    return 0
  fi

  if ! check_cmd jq; then
    warn "skipping — jq required for config port-patching"
    XRAY_JSON_STATUS="jq-missing"
    return 0
  fi

  # Pre-check: a config with no proxy outbound (vnext / servers) can't tunnel
  # anything — without this it launches xray, gets no route, and reports the
  # misleading "tunnel did not reach Cloudflare". Catch it with a clear message.
  local _n_out
  _n_out=$(jq '[.outbounds // [] | .[] | select(.settings.vnext != null or .settings.servers != null)] | length' "$XRAY_JSON_CONFIG" 2>/dev/null)
  case "$_n_out" in
    ''|0)
      fail "config has no proxy outbound (vless/vmess/trojan/ss) — nothing to tunnel through"
      info "check the config: an empty or freedom-only 'outbounds' can't carry a tunnel"
      XRAY_JSON_STATUS="no-outbound"
      return 0 ;;
  esac

  # 1) Reserve a free local port — avoid clashing with a running client
  #    sitting on 10808 / 10809.
  local socks_port
  if ! socks_port=$(_find_free_port); then
    fail "no free local port available in dynamic range"
    XRAY_JSON_STATUS="no-port"
    return 0
  fi
  XRAY_JSON_SOCKS_PORT="$socks_port"
  info "allocating socks5 inbound on 127.0.0.1:$socks_port"

  # 2) Patch the json: keep only socks-protocol inbounds, force them to
  #    127.0.0.1:$socks_port. If none exist, synthesise a minimal one.
  # NB: xray-core determines config format by file extension — without a
  # .json suffix it logs "Failed to get format" and refuses to start.
  # mktemp -t prefix appends random chars (no extension), so we rename.
  local _tmpbase
  _tmpbase=$(mktemp -t detect_blocking.xrayjson.XXXXXX)
  XRAY_JSON_PATCHED_PATH="${_tmpbase}.json"
  mv "$_tmpbase" "$XRAY_JSON_PATCHED_PATH"
  unset _tmpbase
  if ! jq --argjson p "$socks_port" '
       (.inbounds // []) as $orig
       | .inbounds = (
           [$orig[] | select(.protocol == "socks")
             | .listen = "127.0.0.1"
             | .port = $p
             | .settings = ((.settings // {}) | .auth = "noauth" | .udp = true)
           ]
         )
       | (if (.inbounds | length) == 0 then
           .inbounds = [{
             tag: "detect-blocking-probe",
             listen: "127.0.0.1",
             port: $p,
             protocol: "socks",
             settings: { auth: "noauth", udp: true }
           }]
         else . end)
       # Neutralise device-specific log file paths. Mobile clients (iOS /
       # Android) bake an app-sandbox path into .log.access/.error that does
       # not exist on this machine, so xray-core fails to open its logger and
       # never starts. Drop the paths; let it log to stderr (which we capture).
       | .log = { loglevel: "warning" }
     ' "$XRAY_JSON_CONFIG" > "$XRAY_JSON_PATCHED_PATH" 2>/dev/null; then
    fail "jq failed to patch config (malformed json?)"
    XRAY_JSON_STATUS="config-malformed"
    return 0
  fi

  # 3) Launch xray with the patched config. Stderr → temp file so we can
  #    surface a diagnostic line on failure.
  local xray_log
  xray_log=$(mktemp -t detect_blocking.xraylog.XXXXXX)
  xray run -c "$XRAY_JSON_PATCHED_PATH" >"$xray_log" 2>&1 &
  XRAY_JSON_XRAY_PID=$!
  info "xray-core started (pid $XRAY_JSON_XRAY_PID)"

  # 4) Poll for SOCKS readiness — up to TIMEOUT seconds, 200ms granularity.
  local ready=0 _i poll_max
  poll_max=$(( TIMEOUT * 5 ))
  [ "$poll_max" -lt 10 ] && poll_max=10
  for _i in $(seq 1 "$poll_max"); do
    if nc -z 127.0.0.1 "$socks_port" 2>/dev/null; then
      ready=1; break
    fi
    if ! kill -0 "$XRAY_JSON_XRAY_PID" 2>/dev/null; then
      break
    fi
    sleep 0.2
  done

  if [ "$ready" -ne 1 ]; then
    fail "xray did not bind 127.0.0.1:$socks_port within ~${TIMEOUT}s"
    local _diag
    _diag=$(grep -iE 'error|failed|fatal|panic|cannot' "$xray_log" | head -1 | head -c 200)
    [ -n "$_diag" ] && info "xray says: $_diag"
    rm -f "$xray_log"
    XRAY_JSON_STATUS="xray-bind-failed"
    return 0
  fi

  rm -f "$xray_log"
  info "tunnel inbound ready → probing through it"

  # 5) HTTP GET through SOCKS5 to cloudflare.com/cdn-cgi/trace (returns
  #    line-based key=value text; includes egress 'ip=' and colo).
  #    --socks5-hostname is the long form of --socks5h, supported since curl
  #    7.18.0 (2008). The short form --socks5h needs 7.21.7+ (2011) and
  #    is missing from some bundled-with-macOS curl builds.
  #
  #    As in probe 11, retry ONCE at a 4× budget when the first attempt
  #    times out — the xray-core process is still running, so we just
  #    re-issue curl through the same SOCKS port. High-RTT / multi-hop
  #    tunnels need the extra budget; a timeout here is latency, not DPI.
  local t0 t1 trace _max="$TIMEOUT"
  while : ; do
    t0=$(_now_ms)
    trace=$(curl -sS --max-time "$_max" \
            --socks5-hostname "127.0.0.1:$socks_port" \
            https://cloudflare.com/cdn-cgi/trace 2>&1)
    t1=$(_now_ms)
    XRAY_JSON_RTT_MS=$(( t1 - t0 ))

    XRAY_JSON_EGRESS_IP=$(printf '%s' "$trace" | awk -F= '/^ip=/{print $2; exit}')
    XRAY_JSON_EGRESS_LOC=$(printf '%s' "$trace" | awk -F= '/^colo=/{print $2; exit}')

    # Success = Cloudflare host marker AND an egress IP.
    if [ -n "$XRAY_JSON_EGRESS_IP" ] && printf '%s' "$trace" | grep -q '^h=cloudflare\.com'; then
      XRAY_JSON_STATUS="ok"
      break
    fi
    if [ "$XRAY_JSON_RETRY_USED" = "0" ] \
       && [ "$(_classify_tunnel_failure "$trace")" = "timeout" ]; then
      XRAY_JSON_RETRY_USED=1
      _max=$(( TIMEOUT * 4 ))
      warn "tunnel timed out at ${TIMEOUT}s — retrying once at ${_max}s (high-RTT / multi-hop tunnel?)"
      continue
    fi
    XRAY_JSON_STATUS="failed"
    break
  done

  # 6) Verdict.
  if [ "$XRAY_JSON_STATUS" = "ok" ]; then
    if [ "$XRAY_JSON_RETRY_USED" = "1" ]; then
      ok "full-config tunnel works on retry, egress $XRAY_JSON_EGRESS_IP${XRAY_JSON_EGRESS_LOC:+ ($XRAY_JSON_EGRESS_LOC)}, RTT ${XRAY_JSON_RTT_MS} ms — slow handshake, not blocked"
      info "tip: this path needs TIMEOUT≥$(( TIMEOUT * 4 )); set 'TIMEOUT=$(( TIMEOUT * 4 ))' to avoid the first-attempt timeout"
    else
      ok "full-config tunnel works, egress $XRAY_JSON_EGRESS_IP${XRAY_JSON_EGRESS_LOC:+ ($XRAY_JSON_EGRESS_LOC)}, RTT ${XRAY_JSON_RTT_MS} ms"
    fi
    # Cross-reference: tunnel works despite transport-layer DPI signals.
    if [ "${TLS_PROPER_SNI_OK:-1}" = "0" ] || [ "${DOH_INTEGRITY_STATE:-ok}" = "compromised" ]; then
      add_verdict "Xray full-config bypasses local DPI/DNS-MITM despite environment signals"
    fi
    # Cross-reference with probe 11 (URL-based, lossy): if URL probe failed
    # but full json succeeded, the lost pieces (fragment, dialerProxy, etc.)
    # are the bypass mechanism.
    if [ "${XRAY_STATUS:-}" = "failed" ]; then
      add_verdict "Fragment / chained-outbound layer is the bypass — share-link form alone is not enough"
    fi
  else
    XRAY_JSON_FAIL_KIND=$(_classify_tunnel_failure "$trace")
    fail "tunnel did not reach Cloudflare cdn-cgi/trace"
    local _curl_diag
    _curl_diag=$(printf '%s\n' "$trace" | grep -iE 'curl:|error|refused|timed out|unreachable' | head -1 | head -c 200)
    [ -n "$_curl_diag" ] && info "curl says: $_curl_diag"
    # dialerProxy caveat: if the tunnel dials through a LOCAL desync proxy that
    # isn't running, the failure is the chain, not the endpoint — say so before
    # the generic "check keys/flow" verdict misdirects.
    if [ "$(_dialer_is_local_desync)" = "1" ]; then
      local _dpd; _dpd=$(_dialer_proxy_target | sed 's/^[^|]*|//')
      warn "this config dials through a LOCAL dialerProxy ($_dpd) — a client-side desync proxy (ByeDPI/ciadpi/zapret). If it isn't running, THIS failure is the chain, not the endpoint: start it and re-test before trusting the verdict below"
    fi
    if [ "$XRAY_JSON_FAIL_KIND" = "timeout" ]; then
      # Timeout class implies the SOCKS connect succeeded → reachable-but-slow.
      add_verdict "Xray full-config tunnel timed out (even at $(( TIMEOUT * 4 ))s) — slow or throttled tunnel egress, not a fingerprint block. Raise TIMEOUT, or check the server's upstream/egress health"
    elif [ "${TCP_OK:-1}" = "1" ] && [ "${TLS_PROPER_SNI_OK:-0}" = "1" ]; then
      add_verdict "Xray full-config tunnel rejected (reset / closed pipe) while plain TLS to server works — protocol-fingerprint DPI or config drift (verify UUID / keys / flow / target SNI)"
    fi
  fi
}

probe_xray_throughput() {
  # Depends on probe 12 having successfully brought up the SOCKS inbound
  # — the xray-core process is left running until _cleanup, so we can
  # reuse its SOCKS port for a bulk download without spawning xray twice.
  if [ "$XRAY_JSON_STATUS" != "ok" ]; then
    XRAY_THROUGHPUT_STATUS="skipped"
    return 0
  fi

  hdr "13. Xray tunnel throughput (data-plane shaping detection)"

  if ! check_cmd curl; then
    warn "skipping — curl not available"
    XRAY_THROUGHPUT_STATUS="curl-missing"
    return 0
  fi

  # Cloudflare's speed-test backend (speed.cloudflare.com/__down?bytes=N)
  # streams arbitrary bytes from /dev/zero-equivalent — it's the public
  # endpoint behind speed.cloudflare.com's browser tool, no auth, no rate
  # limit at this size. We pick 10 MB by default: enough to escape TCP
  # slow-start and any small-burst exemption (TSPU/RKN typically exempts
  # the first 16-64 KB to keep HTTPS handshakes responsive), but small
  # enough to keep the test under a few seconds on a healthy 10+ Mbps link.
  local target_bytes="$XRAY_THROUGHPUT_TARGET_BYTES"
  local target_url="${XRAY_THROUGHPUT_URL}?bytes=${target_bytes}"
  local max_time="$XRAY_THROUGHPUT_TIMEOUT"

  info "downloading ${target_bytes} bytes via tunnel (max ${max_time}s)"

  # -w gives us size_download, time_total, speed_download in one line —
  # curl's own measurement, more accurate than wrapping with time(1).
  # We deliberately don't echo the SOCKS port (already shown in probe 12)
  # and don't echo target IP (Cloudflare anycast, not endpoint-specific).
  local stats rc
  stats=$(curl -sS --max-time "$max_time" -o /dev/null \
          --socks5-hostname "127.0.0.1:$XRAY_JSON_SOCKS_PORT" \
          -w '%{size_download} %{time_total} %{speed_download}\n' \
          "$target_url" 2>/dev/null)
  rc=$?

  local bytes time_s bps
  bytes=$(printf '%s' "$stats" | awk '{print $1+0}')
  time_s=$(printf '%s' "$stats" | awk '{print $2+0}')
  bps=$(printf '%s' "$stats" | awk '{print int($3)}')

  XRAY_THROUGHPUT_BYTES="$bytes"
  XRAY_THROUGHPUT_TIME_S="$time_s"
  XRAY_THROUGHPUT_BPS="$bps"

  # Human-readable speed for the verdict line. Avoid floating point — we
  # only need ballpark units (B/s, KB/s, MB/s) for diagnostic context.
  local human
  if [ "$bps" -ge 1048576 ]; then
    human="$(( bps / 1048576 )).$(( (bps % 1048576) * 10 / 1048576 )) MB/s"
  elif [ "$bps" -ge 1024 ]; then
    human="$(( bps / 1024 )) KB/s"
  else
    human="${bps} B/s"
  fi

  # Verdict bands (bytes/sec). Tuned against real-world Reality + cover-SNI
  # shaping: TSPU/RKN-style throttling typically drops to ~12-37 KB/s (the
  # signature seen on throttled YouTube/Bilibili since 2024). Healthy
  # tunneled traffic with high RTT (Reality + cross-region hop) sits in the
  # 300 KB/s — several MB/s band depending on upstream bandwidth and
  # TCP-window scaling.
  #
  #   < 1024      → tunnel pipe collapsed after handshake (RST mid-stream,
  #                 kill-shaping post-detection, MTU clamp causing stalls)
  #   < 51200     → severe throttling (≤ 50 KB/s ≈ 400 kbps) — cover-SNI
  #                 shaping signature (RKN/TSPU/CN-style traffic-identifier hit)
  #   < 256000    → degraded (< 250 KB/s ≈ 2 Mbps) — partial shaping,
  #                 cross-region congestion, or upstream-bottlenecked egress
  #   ≥ 256000    → healthy
  #
  # No sensitive details in the verdict text — keep mitigations generic
  # so logs are safe to share publicly.
  if [ "$bps" -lt 1024 ]; then
    fail "tunnel throughput collapsed: ${human} (${bytes} bytes in ${time_s}s, curl rc=$rc)"
    XRAY_THROUGHPUT_STATUS="broken"
    add_verdict data-plane-dead "Reality tunnel handshakes successfully but data plane is unusable — payload doesn't flow (mid-stream RST, MTU clamp, or post-detection kill-shaping). Inspect with --pcap and look for RST flags arriving shortly after the first MB"
  elif [ "$bps" -lt 51200 ]; then
    fail "tunnel throughput severely throttled: ${human}"
    XRAY_THROUGHPUT_STATUS="throttled-severe"
    add_verdict "Reality tunnel works at TLS layer but data plane throttled to dial-up speeds — classic cover-SNI traffic-shaping signature. Mitigation: change Reality cover destination (both 'dest' on server and 'serverName' on client) to a host that is NOT under throttling in the affected region. Pick a high-traffic CDN endpoint reachable from the test region — verify out-of-band with a plain curl from that region before deploying"
  elif [ "$bps" -lt 256000 ]; then
    warn "tunnel throughput degraded: ${human}"
    XRAY_THROUGHPUT_STATUS="throttled-mild"
    add_verdict "Reality tunnel throughput under 250 KB/s — partial shaping, cross-region congestion, or upstream-bottlenecked egress. Re-test against a different cover-SNI to disambiguate"
  else
    ok "tunnel throughput healthy: ${human} (${bytes} bytes in ${time_s}s)"
    XRAY_THROUGHPUT_STATUS="ok"
  fi
}

# Format bytes/sec as "X.Y MB/s (Z Mbps)" without floating point.
_fmt_speed() {
  local bps="$1" mbps_x10 mb_x10
  mbps_x10=$(( bps * 8 * 10 / 1000000 ))   # megabits/sec ×10
  mb_x10=$(( bps * 10 / 1048576 ))          # MB/sec ×10
  printf '%d.%d MB/s (%d.%d Mbps)' \
    "$(( mb_x10 / 10 ))" "$(( mb_x10 % 10 ))" \
    "$(( mbps_x10 / 10 ))" "$(( mbps_x10 % 10 ))"
}

# Run $streams parallel downloads of one endpoint through the SOCKS tunnel and
# echo the aggregate bytes/sec (sum of per-stream speed_download). $1=url
# $2=mode(cf|range) $3=per-stream bytes $4=max secs $5=streams $6=socks port.
_speedtest_one_endpoint() {
  local url="$1" mode="$2" perstream="$3" secs="$4" streams="$5" port="$6"
  local tmpd i agg=0 v
  tmpd=$(mktemp -d -t detect_blocking.spd.XXXXXX) || return 1
  for i in $(seq 1 "$streams"); do
    (
      if [ "$mode" = "cf" ]; then
        curl -sS --max-time "$secs" \
          --socks5-hostname "127.0.0.1:$port" \
          -o /dev/null -w '%{speed_download}' \
          "${url}?bytes=${perstream}" 2>/dev/null > "$tmpd/$i"
      else
        # Range-cap bytes on a static file; falls back to time cap if the
        # server ignores Range (curl still measures whatever it pulled).
        curl -sS --max-time "$secs" -r "0-$(( perstream - 1 ))" \
          --socks5-hostname "127.0.0.1:$port" \
          -o /dev/null -w '%{speed_download}' \
          "$url" 2>/dev/null > "$tmpd/$i"
      fi
    ) &
  done
  wait
  for i in $(seq 1 "$streams"); do
    v=$(cat "$tmpd/$i" 2>/dev/null); v=${v%%.*}
    case "$v" in ''|*[!0-9]*) v=0 ;; esac
    agg=$(( agg + v ))
  done
  rm -rf "$tmpd" 2>/dev/null
  printf '%d' "$agg"
}

# Probe 14 — multi-stream / multi-endpoint capacity estimate.
# Runs by default whenever probe 12 brought up a tunnel; reuses its SOCKS
# inbound. Reports the best aggregate across endpoints as the usable-bandwidth
# estimate — single-endpoint or single-stream numbers under-report on high-RTT
# tunnels, which is the whole point of 13→14. Opt out with --no-speedtest.
probe_xray_speedtest() {
  if [ "$XRAY_SPEEDTEST" != "1" ]; then
    XRAY_SPEEDTEST_STATUS="disabled"
    return 0
  fi
  if [ "$XRAY_JSON_STATUS" != "ok" ]; then
    XRAY_SPEEDTEST_STATUS="skipped"
    return 0
  fi

  hdr "14. Xray tunnel capacity (multi-stream / multi-endpoint)"

  # Auto-skip inside --watch / --from-file loops: pulling tens of MB on every
  # iteration would hammer the metered egress. Force with --speedtest.
  if [ "${XRAY_SPEEDTEST_FORCE:-0}" != "1" ] \
     && { [ "${_WATCH_CHILD:-0}" = "1" ] || [ "${_BATCH_CHILD:-0}" = "1" ]; }; then
    info "skipped in watch/batch loop to avoid repeated ~$(( XRAY_SPEEDTEST_MAX_BYTES / 1048576 )) MB downloads — pass --speedtest to force"
    XRAY_SPEEDTEST_STATUS="skipped-loop"
    return 0
  fi

  if ! check_cmd curl; then
    warn "skipping — curl not available"
    XRAY_SPEEDTEST_STATUS="curl-missing"
    return 0
  fi

  local streams="$XRAY_SPEEDTEST_STREAMS"
  local n_ep perstream secs hs_s
  n_ep=$(printf '%s' "$XRAY_SPEEDTEST_URLS" | wc -w | tr -d ' ')
  [ "$n_ep" -ge 1 ] || { XRAY_SPEEDTEST_STATUS="no-result"; return 0; }
  # Split the total byte budget across all (endpoint × stream) downloads.
  perstream=$(( XRAY_SPEEDTEST_MAX_BYTES / (n_ep * streams) ))
  [ "$perstream" -lt 1048576 ] && perstream=1048576   # floor 1 MB/stream

  # Each stream opens a FRESH tunnel connection, so its curl budget must
  # clear the Reality handshake (≈ probe-12 RTT) before bytes flow — a fixed
  # short timeout would kill every stream mid-handshake on a high-RTT tunnel.
  # Budget = ceil(handshake) + download window + margin.
  hs_s=$(( ( ${XRAY_JSON_RTT_MS:-3000} + 999 ) / 1000 ))
  [ "$hs_s" -lt 3 ] && hs_s=3
  secs=$(( hs_s + XRAY_SPEEDTEST_SECONDS + 2 ))

  info "${streams} parallel streams × ${n_ep} endpoint(s), ≤$(( XRAY_SPEEDTEST_MAX_BYTES / 1048576 )) MB total, ${secs}s/stream (~${hs_s}s handshake + ${XRAY_SPEEDTEST_SECONDS}s window)"

  local triple name url mode agg best=0 best_name=""
  for triple in $XRAY_SPEEDTEST_URLS; do
    name=${triple%%|*}
    url=${triple#*|}; mode=${url##*|}; url=${url%|*}
    agg=$(_speedtest_one_endpoint "$url" "$mode" "$perstream" "$secs" "$streams" "$XRAY_JSON_SOCKS_PORT")
    case "$agg" in ''|*[!0-9]*) agg=0 ;; esac
    XRAY_SPEEDTEST_RESULTS="${XRAY_SPEEDTEST_RESULTS}${XRAY_SPEEDTEST_RESULTS:+ }${name}|${agg}"
    if [ "$agg" -gt 0 ]; then
      info "  ${name}: $(_fmt_speed "$agg")"
    else
      info "  ${name}: no data (endpoint unreachable through tunnel)"
    fi
    if [ "$agg" -gt "$best" ]; then best="$agg"; best_name="$name"; fi
  done

  XRAY_SPEEDTEST_BEST_BPS="$best"
  XRAY_SPEEDTEST_BEST_NAME="$best_name"

  if [ "$best" -le 0 ]; then
    fail "no endpoint returned data through the tunnel"
    XRAY_SPEEDTEST_STATUS="no-result"
    return 0
  fi

  XRAY_SPEEDTEST_STATUS="ok"
  ok "best capacity: $(_fmt_speed "$best") via ${best_name} (${streams} streams)"
  # Honesty note: with a small byte budget on a fast link the streams finish
  # inside TCP slow-start, so this reads as a FLOOR, not a ceiling.
  if [ "$perstream" -le 5242880 ]; then
    info "note: $(( perstream / 1048576 )) MB/stream is small for a fast link — raise XRAY_SPEEDTEST_MAX_BYTES for a fuller reading (this is a floor)"
  fi
}

# Extract the Reality cover serverName from --xray-config URL or
# --xray-config-json. Echoes the SNI (empty if not a reality config). Kept
# out of probe output — only used internally to drive the cover check.
_xray_cover_sni() {
  if [ -n "$XRAY_CONFIG" ]; then
    case "$XRAY_CONFIG" in
      *security=reality*)
        _safe "$(printf '%s' "$XRAY_CONFIG" | sed -nE 's|.*[?&]sni=([^&#]*).*|\1|p' | head -1)"
        return 0 ;;
    esac
  fi
  if [ -n "$XRAY_JSON_CONFIG" ] && [ -r "$XRAY_JSON_CONFIG" ] && command -v jq >/dev/null 2>&1; then
    # sanitise: the serverName is attacker-influenced and feeds both printed output
    # (reveal / SNI-quality) and openssl/curl args — strip control chars.
    _safe "$(jq -r '
      .outbounds // []
      | map(select(.streamSettings.security == "reality"))
      | first | .streamSettings.realitySettings.serverName // empty
    ' "$XRAY_JSON_CONFIG" 2>/dev/null)"
  fi
}

# The configured uTLS fingerprint (fp=) — the browser whose ClientHello Reality
# mimics. Lower-cased; empty if unset. From the share-link or the JSON.
_xray_utls_fp() {
  local v=""
  if [ -n "$XRAY_CONFIG" ]; then
    v=$(printf '%s' "$XRAY_CONFIG" | sed -nE 's|.*[?&]fp=([^&#]*).*|\1|p' | head -1)
  elif [ -n "$XRAY_JSON_CONFIG" ] && [ -r "$XRAY_JSON_CONFIG" ] && command -v jq >/dev/null 2>&1; then
    v=$(jq -r '.outbounds // []
        | map(select(.streamSettings.security == "reality" or .streamSettings.security == "tls"))
        | first
        | (.streamSettings.realitySettings.fingerprint // .streamSettings.tlsSettings.fingerprint) // empty
      ' "$XRAY_JSON_CONFIG" 2>/dev/null)
  fi
  printf '%s' "$v" | tr '[:upper:]' '[:lower:]'
}

# Probe 15 — Reality cover authenticity. Connects plain-TLS (unauthenticated,
# exactly what a GFW/TSPU active prober does) with the configured serverName
# and inspects the presented certificate. A genuine Reality server relays such
# clients to the real cover site → CA-valid cert chaining to that name. A
# self-signed or mismatched cert means the cover is fake and trivially
# fingerprinted. Output is booleans only — the cover domain is never printed.
probe_xray_cover() {
  local sni
  sni=$(_xray_cover_sni)
  if [ -z "$sni" ]; then
    XRAY_COVER_STATUS="skipped"   # not a reality config (or no config)
    return 0
  fi

  hdr "15. Reality cover authenticity"
  info "unauthenticated TLS probe (what an active prober sees)"

  if ! check_cmd openssl; then
    warn "skipping — openssl not available"
    XRAY_COVER_STATUS="openssl-missing"
    return 0
  fi

  # Bound the connect: a dead / null-routed VPN_HOST makes openssl s_client block
  # on the OS TCP connect timeout (~75s) — `echo Q` only quits AFTER the handshake,
  # so it does NOT bound the connect (and `timeout`/`gtimeout` aren't on stock macOS).
  # Precheck with a $TIMEOUT-bounded nc, the same guard the fleet walk / probes 1-2 use.
  if ! _nc_tcp_probe "$VPN_HOST" "$VPN_PORT_TCP"; then
    fail "no TLS certificate returned — cover unreachable (see probes 2-3)"
    XRAY_COVER_STATUS="unreachable"
    return 0
  fi
  local out subject issuer verify
  out=$(echo Q | openssl s_client -connect "$VPN_HOST:$VPN_PORT_TCP" \
        -servername "$sni" 2>/dev/null)
  subject=$(printf '%s' "$out" | sed -nE 's/^subject=(.*)/\1/p' | head -1)
  issuer=$(printf '%s'  "$out" | sed -nE 's/^issuer=(.*)/\1/p'  | head -1)
  verify=$(printf '%s'  "$out" | sed -nE 's/.*Verify return code: ([0-9]+).*/\1/p' | head -1)

  if [ -z "$subject" ]; then
    fail "no TLS certificate returned — cover unreachable (see probes 2-3)"
    XRAY_COVER_STATUS="unreachable"
    return 0
  fi

  # Self-signed: issuer == subject, or verify code 18/19.
  if [ "$subject" = "$issuer" ] || [ "$verify" = "18" ] || [ "$verify" = "19" ]; then
    XRAY_COVER_SELFSIGNED=1
  else
    XRAY_COVER_SELFSIGNED=0
  fi
  [ "$verify" = "0" ] && XRAY_COVER_CHAIN_VALID=1 || XRAY_COVER_CHAIN_VALID=0

  # Does the cert cover the configured serverName? Modern certs carry the names
  # in the SAN, not the CN — a cert with CN=example.com and SAN *.example.com
  # legitimately covers host.example.com, but a CN-only check would call that a
  # mismatch (the false "auth fails fleet-wide" a wildcard-SAN report exposed).
  # So check the full SAN list (one-level wildcard logic) and fall back to the
  # CN. Compare case-insensitively. Booleans only — no cert names are emitted.
  local cn lc_cn lc_sni parent sans
  cn=$(printf '%s' "$subject" | sed -nE 's/.*CN ?= ?([^,/]+).*/\1/p' | head -1)
  lc_cn=$(printf '%s' "$cn"  | tr '[:upper:]' '[:lower:]')
  lc_sni=$(printf '%s' "$sni" | tr '[:upper:]' '[:lower:]')
  parent="${lc_sni#*.}"
  # SAN DNS names from the leaf cert (the s_client output carries its PEM),
  # lower-cased and space-joined so a glob membership test stays bash-3.2 safe.
  sans=$(printf '%s' "$out" | openssl x509 -noout -ext subjectAltName 2>/dev/null \
         | tr '[:upper:]' '[:lower:]' | tr ',' '\n' | sed -nE 's/.*dns:([^ ]+).*/\1/p' | tr '\n' ' ')
  XRAY_COVER_CN_MATCH=0
  if [ -n "$lc_cn" ] && { [ "$lc_cn" = "$lc_sni" ] || [ "$lc_cn" = "*.$parent" ]; }; then
    XRAY_COVER_CN_MATCH=1
  else
    case " $sans " in
      *" $lc_sni "*|*" *.$parent "*) XRAY_COVER_CN_MATCH=1 ;;
    esac
  fi

  info "cover cert: self-signed=${XRAY_COVER_SELFSIGNED}, chain-valid=${XRAY_COVER_CHAIN_VALID}, CN-matches-serverName=${XRAY_COVER_CN_MATCH}"
  reveal "serverName = \"$sni\" | cert subject = ${subject:-?}"

  if [ "$XRAY_COVER_SELFSIGNED" = "1" ]; then
    fail "cover certificate is self-signed → fake cover, trivially fingerprinted"
    XRAY_COVER_STATUS="fake"
    add_verdict "Reality cover is fake — the server presents a self-signed certificate to unauthenticated clients instead of relaying them to the genuine cover site. An active prober (GFW/TSPU) flags this as a censorship-circumvention server immediately. Fix on the server: point Reality 'dest' at the real cover host:443 and list it in 'serverNames'"
  elif [ "$XRAY_COVER_CHAIN_VALID" = "1" ] && [ "$XRAY_COVER_CN_MATCH" = "1" ]; then
    ok "cover certificate is CA-valid and matches the configured serverName → authentic cover"
  elif [ "$XRAY_COVER_CHAIN_VALID" = "1" ]; then
    warn "cover cert is CA-valid but for a different host than the configured serverName"
    XRAY_COVER_STATUS="mismatch"
    add_verdict "Reality cover/serverName mismatch — the cover host serves a valid cert, but not for the serverName your client sends. The handshake's SNI won't match what the server steals, so authentication fails fleet-wide. Align client serverName with the server's Reality 'dest'/'serverNames'"
  else
    warn "cover cert neither self-signed nor cleanly CA-valid (verify code ${verify:-?})"
    XRAY_COVER_STATUS="mismatch"
  fi
  [ -z "$XRAY_COVER_STATUS" ] && XRAY_COVER_STATUS="ok"
}

# Query a POOL of free HTTPS IP-info sources for the egress ASN/org + country,
# returning the FIRST that responds as "<countryCode>\t<org>". Multiple sources
# means one being rate-limited / blocked doesn't blank the cross-check. Needs
# jq (shapes differ per source). $1 = socks port, $2 = per-call max-time.
_egress_asn() {
  local port="$1" maxt="$2" j cc org
  command -v jq >/dev/null 2>&1 || return 0
  # ipinfo.io → .org ("AS24940 Hetzner Online GmbH"), .country
  j=$(curl -sS --max-time "$maxt" --socks5-hostname "127.0.0.1:$port" https://ipinfo.io/json 2>/dev/null)
  org=$(printf '%s' "$j" | jq -r '.org // empty' 2>/dev/null)
  cc=$(printf '%s' "$j"  | jq -r '.country // empty' 2>/dev/null)
  [ -n "$org" ] && { printf '%s\t%s' "$cc" "$org"; return 0; }
  # ipwho.is → .connection.org / .connection.isp, .country_code
  j=$(curl -sS --max-time "$maxt" --socks5-hostname "127.0.0.1:$port" https://ipwho.is/ 2>/dev/null)
  org=$(printf '%s' "$j" | jq -r '(.connection.org // .connection.isp) // empty' 2>/dev/null)
  cc=$(printf '%s' "$j"  | jq -r '.country_code // empty' 2>/dev/null)
  [ -n "$org" ] && { printf '%s\t%s' "$cc" "$org"; return 0; }
  # ifconfig.co → .asn_org, .country_iso
  j=$(curl -sS --max-time "$maxt" --socks5-hostname "127.0.0.1:$port" https://ifconfig.co/json 2>/dev/null)
  org=$(printf '%s' "$j" | jq -r '.asn_org // empty' 2>/dev/null)
  cc=$(printf '%s' "$j"  | jq -r '.country_iso // empty' 2>/dev/null)
  [ -n "$org" ] && { printf '%s\t%s' "$cc" "$org"; return 0; }
  return 0
}

# Cover-SNI scanner (--scan-covers) — rank candidate Reality dest/serverNames.
# A good cover is a foreign site with TLSv1.3 + HTTP/2, a CA-valid cert, and no
# redirect (serves real content). Probes each candidate directly (curl bounds
# the TLS reachability via --max-time; openssl only runs on a candidate curl
# could reach, so a dead/hanging host can't stall the loop). Standalone — does
# not need a config or the tunnel.
probe_cover_scan() {
  [ -n "$XRAY_SCAN_COVERS" ] || { XRAY_COVER_SCAN_STATUS="skipped"; return 0; }
  if ! check_cmd openssl || ! check_cmd curl; then XRAY_COVER_SCAN_STATUS="skipped"; return 0; fi
  hdr "Cover-SNI scan (Reality dest / serverName candidates)"
  local cands
  case "$XRAY_SCAN_COVERS" in
    default|1) cands="$XRAY_COVER_CANDIDATES" ;;
    *)         cands=$(printf '%s' "$XRAY_SCAN_COVERS" | tr ',' ' ') ;;
  esac
  info "per candidate: TLSv1.3 + HTTP/2 (ALPN) + CA-valid cert + non-redirect (HTTP 200)"
  local d best="" best_score=-1 results="" cw code httpver out vc
  for d in $cands; do
    [ -n "$d" ] || continue
    local tls13=no h2=no cav=no nr=no score=0 verdict
    # curl first (bounded) — gives the redirect status AND the negotiated HTTP
    # version (h2 detection; openssl -brief omits the ALPN line). 000 = unreachable.
    cw=$(curl -sS --http2 -o /dev/null -w '%{http_code} %{http_version}' --max-time "$TIMEOUT" "https://$d/" 2>/dev/null)
    code=${cw%% *}; httpver=${cw##* }
    if [ "${code:-000}" = "000" ]; then
      info "$(printf '%-26s unreachable / TLS failed' "$d")"
      results="${results}
${d}|no|no|no|no|unreachable"
      continue
    fi
    case "$code" in 200) nr=yes; score=$((score+1)) ;; esac
    case "$httpver" in 2|2.0|2.*) h2=yes; score=$((score+1)) ;; esac
    out=$(openssl s_client -connect "$d:443" -servername "$d" -brief </dev/null 2>&1)
    printf '%s' "$out" | grep -qiE 'Protocol version: TLSv1.3' && { tls13=yes; score=$((score+1)); }
    vc=$(printf '%s' "$out" | grep -iE 'Verification' | head -1)
    case "$vc" in *OK*) cav=yes; score=$((score+1)) ;; esac
    # Region-risk: a cover that's intrinsically great HERE but commonly
    # blocked/throttled in a major censored region is a DEAD cover there (the
    # cover SNI itself is censored → the whole Reality flow dies). We can't test
    # from the target region (single vantage), so we flag the well-known cases
    # and de-prioritise them in the pick — the operator must verify in-region.
    local region_risk="" rank="$score"
    case "$d" in
      *cloudflare*|*google*|*gstatic*|*youtube*|*facebook*|*instagram*|*fbcdn*)
        region_risk=" [region-risk: commonly blocked/throttled in RU/CN]"; rank=$((score-2)) ;;
    esac
    if   [ "$score" -ge 4 ]; then verdict="good cover"
    elif [ "$score" -ge 2 ]; then verdict="usable"
    else verdict="poor"; fi
    verdict="${verdict}${region_risk}"
    info "$(printf '%-26s tls1.3=%-3s h2=%-3s ca-valid=%-3s non-redirect=%-3s → %s' "$d" "$tls13" "$h2" "$cav" "$nr" "$verdict")"
    results="${results}
${d}|${tls13}|${h2}|${cav}|${nr}|${verdict}"
    [ "$rank" -gt "$best_score" ] && { best_score=$rank; best="$d"; }
  done
  XRAY_COVER_SCAN_RESULTS="$results"
  XRAY_COVER_SCAN_BEST="$best"
  XRAY_COVER_SCAN_STATUS="ok"
  if [ -n "$best" ] && [ "$best_score" -ge 2 ]; then
    ok "best candidate: $best — set it as Reality 'dest'/'serverNames'"
  else
    warn "no strong cover among the candidates — none cleared TLSv1.3 + H2 + CA-valid; try a different list (--scan-covers d1,d2,...)"
  fi
  info "this checks PROTOCOL suitability + region-risk only — it can't measure a site's traffic rank from here. A good cover is ALSO high-traffic/popular: blocking it then costs the censor collateral, and your tunnel's volume blends into the site's normal traffic (a low-traffic cover makes your throughput stick out — lots of TLS to a site that normally sees little). Pick a genuinely popular site."
  info "the cover's OWN speed does not limit your tunnel — authenticated traffic goes to the proxy backend, not the cover, so throughput is set by the server + egress (probes 13/14), not by which cover you pick here"
  warn "scores are from THIS vantage only — a cover that's blocked/throttled in your TARGET region (e.g. Cloudflare in RU, Google in CN) is a dead cover there regardless of the score above; verify the chosen SNI is reachable FROM the region, and confirm the SERVER can reach it. For SNI↔IP stealth prefer a cover on the server's own network, or self-steal (a global CDN cover still mismatches the server's IP)"
}

# Censored-URL sweep (--censor-sweep) — OONI-web_connectivity-style reachability.
# Fetches each host DIRECT and (when probe 12's tunnel is up) THROUGH it, then
# classifies: does the tunnel unblock a censored host, or fail to carry one that
# works direct? Reuses _url_reachable for both paths. Opt-in (external fetches).
probe_censor_sweep() {
  [ -n "$XRAY_CENSOR_SWEEP" ] || { XRAY_CENSOR_SWEEP_STATUS="skipped"; return 0; }
  check_cmd curl || { XRAY_CENSOR_SWEEP_STATUS="skipped"; return 0; }
  hdr "Censored-URL sweep (reachability: direct vs through the tunnel)"
  local hosts via=0 sp=""
  case "$XRAY_CENSOR_SWEEP" in
    default|1) hosts="$XRAY_CENSOR_URLS" ;;
    *)         hosts=$(printf '%s' "$XRAY_CENSOR_SWEEP" | tr ',' ' ') ;;
  esac
  if [ "${XRAY_JSON_STATUS:-}" = "ok" ] && [ -n "${XRAY_JSON_SOCKS_PORT:-}" ]; then
    via=1; sp="127.0.0.1:${XRAY_JSON_SOCKS_PORT}"
    info "each host fetched DIRECT and through the tunnel → does the tunnel carry a censored host (and not drop one that works direct)?"
  else
    info "no live tunnel (probe 12 not ok) — DIRECT reachability only (like probe 8, for your list)"
  fi
  XRAY_CENSOR_SWEEP_TUNNEL="$via"
  local h dirok tunok verdict results="" unblocked=0 dropped=0
  for h in $hosts; do
    [ -n "$h" ] || continue
    dirok=no; _url_reachable "https://$h/" "$TIMEOUT" && dirok=yes
    if [ "$via" = "1" ]; then
      tunok=no; _url_reachable "https://$h/" "$TIMEOUT" "$sp" && tunok=yes
      if   [ "$dirok" = yes ] && [ "$tunok" = yes ]; then verdict="reachable (both)"
      elif [ "$dirok" = no ]  && [ "$tunok" = yes ]; then verdict="blocked direct → tunnel carries it"; unblocked=$((unblocked+1))
      elif [ "$dirok" = yes ] && [ "$tunok" = no ];  then verdict="direct only → tunnel does NOT carry it (routing/proxy fault)"; dropped=$((dropped+1))
      else verdict="blocked both (tunnel doesn't help / host down)"; fi
      info "$(printf '%-24s direct=%-3s tunnel=%-3s → %s' "$h" "$dirok" "$tunok" "$verdict")"
      results="${results}
${h}|${dirok}|${tunok}|${verdict}"
    else
      [ "$dirok" = yes ] && verdict="reachable direct" || verdict="blocked direct"
      info "$(printf '%-24s direct=%-3s → %s' "$h" "$dirok" "$verdict")"
      results="${results}
${h}|${dirok}|na|${verdict}"
    fi
  done
  XRAY_CENSOR_SWEEP_RESULTS="$results"
  XRAY_CENSOR_SWEEP_STATUS="ok"
  if [ "$via" = "1" ]; then
    [ "$unblocked" -gt 0 ] && ok "tunnel unblocks ${unblocked} host(s) that are blocked direct — it's doing its job"
    if [ "$dropped" -gt 0 ]; then
      warn "${dropped} host(s) reachable direct but NOT carried through the tunnel — a routing/proxy fault (check the routing rules / outbound)"
    elif [ "$unblocked" -eq 0 ]; then
      info "nothing in the list is censored at this vantage — run from the affected region to see the tunnel unblock"
    fi
  fi
}

# Is <ip> a CDN edge? Reuses the probe-26 org-keyword approach (HTTPS-first, ip-api
# fallback). A CDN edge is shared and answers many ports BY DESIGN, so "panel ports
# open" there is the CDN's own alt-ports, not the origin's panel. Returns 0 = CDN.
# Is this endpoint a CDN edge? TRI-STATE by exit code:
#   0 = yes, a CDN edge   1 = no, not a CDN   2 = COULD NOT DETERMINE
#
# The third state matters. Callers use "not a CDN" to justify a hard finding (an open
# 8080/2053 on your own origin is a takeover risk; on a CDN edge those are the CDN's
# own ports, served by design). Before 1.12.1 a failed lookup collapsed into "not a
# CDN", so a CDN-fronted host got a false takeover verdict — and the lookup failed
# routinely, because the caller passes VPN_HOST when probe 1 has not run, and the
# IP-info APIs 404 on a hostname ("Please provide a valid IP address").
#
# So: resolve a hostname to an address first, and report 2 when the answer is unknown.
_is_cdn_ip() {
  local ip="$1" info
  [ -n "$ip" ] || return 2
  check_cmd curl || return 2
  if ! _is_ip_literal "$ip"; then
    ip=$(_resolve_a_records "$ip" 2>/dev/null | _first_word)
    [ -n "$ip" ] || return 2          # cannot resolve → unknown, NOT "no"
  fi
  info=$(_curl "https://ipinfo.io/${ip}/json" 2>/dev/null)
  [ -z "$info" ] && info=$(_curl "http://ip-api.com/json/${ip}?fields=org,as,isp" 2>/dev/null)
  # An error body (404 / rate-limit) carries no org field — treat as unknown, not "no".
  case "$info" in
    ''|*'"status": 404'*|*'"status":404'*|*'Wrong ip'*|*'rate limit'*|*'"status":"fail"'*) return 2 ;;
  esac
  printf '%s' "$info" | tr '[:upper:]' '[:lower:]' \
    | grep -qE 'cloudflare|akamai|fastly|cloudfront|edgecast|edgio|g.?core|bunny|stackpath|cdn77|incapsula|sucuri|netlify|vercel|fbcdn|limelight|lumen' \
    && return 0
  # A real answer that names some other org → genuinely not a CDN.
  printf '%s' "$info" | grep -qiE '"org"|"as"|"isp"' && return 1
  return 2
}

# Classify a panel-port response (pure, unit-testable). Args: httpcode server-header
# body-snippet(lowercased). Echoes: closed | cdn | panel | login | web.
#   panel = x-ui/3x-ui brand marker in the body (an exposed panel)
#   login = a login form on a panel port (panel-likely, no brand string)
#   cdn   = a CDN edge answered (not the origin)
_panel_classify() {
  local code="${1:-000}" srv="${2:-}" body="${3:-}"
  case "$code" in 000|""|connection*|couldnt*) echo closed; return ;; esac
  case "$(printf '%s' "$srv" | tr '[:upper:]' '[:lower:]')" in
    *cloudflare*|*akamai*|*fastly*|*cloudfront*|*varnish*|*"amazons3"*) echo cdn; return ;;
  esac
  case "$body" in
    *x-ui*|*xui*|*"xray panel"*) echo panel; return ;;
  esac
  case "$body" in *'type="password"'*|*'type=password'*|*"name=\"password\""*) echo login; return ;; esac
  echo web
}

# Host exposure (whole-host disguise) — does the server answer anything beyond
# :443? A real CDN edge (the cover it impersonates) answers ONLY 443. An open
# proxy PANEL (x-ui/3x-ui) is both a takeover risk and a loud tell to any scanner
# profiling the IP; open SSH/RDP is normal-for-admin but still un-CDN-like. Short
# per-port timeout so a properly firewalled host (all-filtered) can't stall it.
probe_host_exposure() {
  { [ -n "$XRAY_CONFIG" ] || [ -n "$XRAY_JSON_CONFIG" ]; } || { XRAY_HOSTEXP_STATUS="skipped"; return 0; }
  check_cmd nc || { XRAY_HOSTEXP_STATUS="skipped"; return 0; }
  local ip="${RESOLVED_IP:-$VPN_HOST}"
  { [ -n "$ip" ] && [ "$ip" != "www.example.com" ]; } || { XRAY_HOSTEXP_STATUS="skipped"; return 0; }
  hdr "Host exposure (does the server look like only a web host?)"
  local open="" panel=0 admin=0 spec p name hit
  for spec in "22:SSH" "3389:RDP" "8080:panel/alt-http" "8081:panel" "2053:panel" "9000:panel" "54321:x-ui-panel"; do
    p=${spec%%:*}; name=${spec#*:}
    if [[ "$OSTYPE" == darwin* ]]; then nc -z -G 2 "$ip" "$p" 2>/dev/null && hit=1 || hit=0
    else nc -z -w 2 "$ip" "$p" 2>/dev/null && hit=1 || hit=0; fi
    if [ "$hit" = "1" ]; then
      open="${open}${open:+, }${p}(${name})"
      case "$name" in SSH|RDP) admin=1 ;; *) panel=1 ;; esac
    fi
  done
  XRAY_HOSTEXP_OPEN="$open"
  XRAY_HOSTEXP_STATUS="ok"
  if [ -z "$open" ]; then
    ok "no giveaway ports open beyond 443 — to a scanner the host looks like a plain web server (good disguise)"
    return 0
  fi
  info "open beyond 443: ${open}"
  if [ "$panel" = "1" ]; then
    # A CDN edge shares one IP and serves many alt-ports BY DESIGN (Cloudflare:
    # 8080/2053/2087/8443…), so "panel port open" here is the CDN's, not the
    # origin's — the classic false positive on a CDN-fronted config. Downgrade it
    # and point at --panel-probe against the real backend IP.
    _cdnrc=0; _is_cdn_ip "$ip" || _cdnrc=$?
    if [ "$_cdnrc" = "2" ]; then
      # Unknown: do NOT claim an exposed panel. On a CDN-fronted host these ports are
      # the CDN's own and the finding would be false; say what we could not establish.
      XRAY_HOSTEXP_CDN=""
      warn "could not determine whether ${ip} is a CDN edge (address lookup unavailable) — so it is UNKNOWN whether these are the CDN's own alt-ports or an exposed panel on your origin. Re-run including the dns probe, or audit directly with --panel-probe <origin-ip>"
    elif [ "$_cdnrc" = "0" ]; then
      XRAY_HOSTEXP_CDN=1
      info "…but the resolved IP is a CDN edge — those are the CDN's own alt-ports (e.g. Cloudflare serves 8080/2053/2087/8443), NOT an exposed x-ui/3x-ui panel. Origin panel exposure can't be seen through the CDN; audit the backend directly with: --panel-probe <origin-ip>"
    else
      XRAY_HOSTEXP_CDN=0
      warn "server exposes a likely proxy-PANEL port to the internet — a takeover risk AND a strong tell (a host impersonating a CDN cover should answer only 443; a scanner profiling the IP sees a proxy panel instead)"
      add_verdict "Server exposes a proxy-panel port (e.g. x-ui/3x-ui) to the internet — a takeover risk and a detectability tell: a host that impersonates a CDN cover should expose only 443. Bind the panel to localhost (reach it over an SSH tunnel) or firewall it to an admin allowlist. Confirm which ports serve a real panel with: --panel-probe ${ip}"
    fi
  fi
  [ "$admin" = "1" ] && info "SSH/RDP reachable — normal for admin, but a real CDN edge doesn't answer it; restricting management to a jump host / firewall allowlist sharpens the host's web-only profile"
}

# --panel-probe [IP]: audit an ORIGIN IP for an exposed x-ui/3x-ui admin panel.
# Host-exposure only nc-scans the resolved IP (= the CDN edge on a fronted config);
# this actively fetches the known panel ports/paths on a backend you name and
# classifies each (x-ui/3x-ui login vs a CDN edge vs a plain web server vs closed),
# so it's a repeatable fleet audit. GETs only (share-safe: booleans/codes only).
probe_panel() {
  { [ -n "${PANEL_PROBE:-}" ] && [ "${PANEL_PROBE:-}" != "0" ]; } || { PANEL_STATUS="skipped"; return 0; }
  check_cmd curl || { warn "--panel-probe needs curl"; PANEL_STATUS="skipped"; return 0; }
  local tgt
  case "$PANEL_PROBE" in 1|default|"") tgt="${RESOLVED_IP:-$VPN_HOST}" ;; *) tgt="$PANEL_PROBE" ;; esac
  { [ -n "$tgt" ] && [ "$tgt" != "www.example.com" ]; } || { warn "--panel-probe: no target (pass --panel-probe <origin-ip>)"; PANEL_STATUS="skipped"; return 0; }

  hdr "Panel probe (x-ui / 3x-ui exposure) — target ${tgt}"
  if _is_cdn_ip "$tgt"; then
    warn "${tgt} is a CDN edge, not an origin — panel ports here are the CDN's own (e.g. Cloudflare 8080/2053/2087/8443). Point --panel-probe at the BACKEND/origin IP behind the CDN to audit the real panel"
  fi

  # port:scheme:path — the default x-ui/3x-ui/marzban surfaces + CF-style panel ports.
  local checks="54321:http:/ 2053:https:/ 2053:https:/panel/ 8080:http:/ 8080:http:/panel/ 8080:http:/dashboard/ 8081:http:/ 9000:http:/ 2083:https:/panel/ 2087:https:/panel/ 8443:https:/panel/"
  local any=0 found=0 spec port rest scheme path url code srv body verdict tmp
  tmp=$(mktemp 2>/dev/null) || tmp="/tmp/_panel.$$"
  for spec in $checks; do
    port=${spec%%:*}; rest=${spec#*:}; scheme=${rest%%:*}; path=${rest#*:}
    if [[ "$OSTYPE" == darwin* ]]; then nc -z -G 2 "$tgt" "$port" 2>/dev/null || continue
    else nc -z -w 2 "$tgt" "$port" 2>/dev/null || continue; fi
    any=1
    url="${scheme}://${tgt}:${port}${path}"
    code=$(curl -sS -k --max-time "$TIMEOUT" -o "$tmp" -w '%{http_code}|%header{server}' "$url" 2>/dev/null)
    srv=${code#*|}; code=${code%%|*}
    body=$(head -c 4000 "$tmp" 2>/dev/null | tr '[:upper:]' '[:lower:]' | tr -d '\000')
    verdict=$(_panel_classify "$code" "$srv" "$body")
    case "$verdict" in
      panel) fail  "  ${url} → x-ui/3x-ui PANEL (HTTP ${code}) — EXPOSED"; found=1 ;;
      login) warn  "  ${url} → login form (HTTP ${code}) — likely a panel"; found=1 ;;
      cdn)   info  "  ${url} → CDN edge (HTTP ${code}, server=$(_safe "$srv")) — not your origin" ;;
      web)   info  "  ${url} → responds (HTTP ${code}), no panel markers" ;;
      closed) info "  ${url} → open TCP but no HTTP response" ;;
    esac
  done
  rm -f "$tmp" 2>/dev/null
  PANEL_STATUS="ok"; PANEL_FOUND="$found"
  if [ "$any" = "0" ]; then
    ok "no panel ports open on ${tgt} — clean (nothing beyond the tested surface answers)"
  elif [ "$found" = "1" ]; then
    add_verdict "Panel probe: an x-ui/3x-ui admin panel is reachable on ${tgt} (see the panel/login rows) — a takeover risk (auth-bypass/RCE CVEs, default creds) AND a scanner tell. Bind it to 127.0.0.1 (reach it over an SSH tunnel), firewall the port to an admin allowlist, set a non-default webBasePath, and rotate off default credentials"
  else
    ok "no exposed x-ui/3x-ui panel found on ${tgt} at the default ports/paths — a hardened panel (custom webBasePath / localhost-bound) wouldn't show here, so confirm server-side too"
  fi
}

# Pure helper (unit-testable): classify a concurrency burst. succeeded/total +
# min/max handshake ms → one of: all-failed / capped / degraded / clean.
_classify_conn_limit() {
  local s="${1:-0}" t="${2:-0}" mn="${3:-0}" mx="${4:-0}"
  [ "$s" -eq 0 ] && { echo "all-failed"; return; }
  [ "$s" -lt "$t" ] && { echo "capped"; return; }
  # all completed: degraded if the slowest handshake ballooned vs the fastest
  if [ "$mx" -ge 800 ] && [ "$mn" -gt 0 ] && [ "$mx" -ge $(( mn * 3 )) ]; then echo "degraded"; return; fi
  echo "clean"
}

# --conn-test N: open N simultaneous TLS handshakes to the server and report how
# many complete + the handshake-time spread. Tells you whether the server CAPS /
# rate-limits / degrades under concurrent connections (robustness & real-world UX
# behind CGNAT / many devices — NOT a censorship signal). Direct (no tunnel), so it
# works standalone and inside a --sub-test N deep dive. Bounded per-connection by
# curl --max-time (openssl can't be bounded on macOS). Opt-in; never auto-runs.
probe_conn_limit() {
  [ -n "${CONN_TEST_N:-}" ] || { CONN_LIMIT_STATUS="disabled"; return 0; }
  [ "$CONN_TEST_N" -ge 1 ]   2>/dev/null || CONN_TEST_N=16
  [ "$CONN_TEST_N" -le 128 ] 2>/dev/null || CONN_TEST_N=128   # safety cap — not a flood tool
  local n="$CONN_TEST_N"
  hdr "Connection-limit probe (${n} concurrent TLS handshakes)"
  if ! check_cmd curl; then warn "skipping — curl not available"; CONN_LIMIT_STATUS="curl-missing"; return 0; fi
  if ! _nc_tcp_probe "$VPN_HOST" "$VPN_PORT_TCP"; then
    warn "skipping — ${VPN_HOST}:${VPN_PORT_TCP} not reachable (TCP)"; CONN_LIMIT_STATUS="unreachable"; return 0
  fi
  local sni; sni=$(_xray_cover_sni 2>/dev/null); [ -z "$sni" ] && sni="$VPN_HOST"
  local t=$(( TIMEOUT + 3 )) d i
  d=$(mktemp -d -t detect_blocking.conn.XXXXXX) || { CONN_LIMIT_STATUS="error"; return 0; }
  # Fire all N at once (same instant) so a concurrency cap actually triggers.
  local pids=""
  for i in $(seq 1 "$n"); do
    ( curl -k -sS --max-time "$t" --connect-to "${sni}:443:${VPN_HOST}:${VPN_PORT_TCP}" \
        "https://${sni}/" -o /dev/null -w '%{time_appconnect}' 2>/dev/null > "$d/$i" ) &
    pids="$pids $!"
  done
  # Wait ONLY for our curls — a bare `wait` would also block on a long-lived xray-core
  # background job (probe 12, when --conn-test runs without --no-tunnel) and hang.
  # shellcheck disable=SC2086
  [ -n "$pids" ] && wait $pids 2>/dev/null
  local succ=0 fail=0 minms="" maxms=0 ta ms
  for i in $(seq 1 "$n"); do
    ta=$(cat "$d/$i" 2>/dev/null)
    ms=$(awk -v s="${ta:-0}" 'BEGIN{printf "%d", (s+0)*1000}')
    if [ "${ms:-0}" -gt 0 ]; then
      succ=$((succ+1))
      { [ -z "$minms" ] || [ "$ms" -lt "$minms" ]; } && minms=$ms
      [ "$ms" -gt "$maxms" ] && maxms=$ms
    else
      fail=$((fail+1))
    fi
  done
  rm -rf "$d"
  [ -z "$minms" ] && minms=0
  CONN_LIMIT_STATUS="ok"; CONN_LIMIT_REQUESTED="$n"; CONN_LIMIT_SUCC="$succ"; CONN_LIMIT_FAIL="$fail"
  CONN_LIMIT_MINMS="$minms"; CONN_LIMIT_MAXMS="$maxms"
  CONN_LIMIT_VERDICT=$(_classify_conn_limit "$succ" "$n" "$minms" "$maxms")
  case "$CONN_LIMIT_VERDICT" in
    clean)
      ok "handled ${succ}/${n} concurrent TLS handshakes (${minms}-${maxms}ms) — no connection cap or throttle observed" ;;
    capped)
      warn "only ${succ}/${n} concurrent handshakes completed — the server CAPS or rate-limits concurrent connections; clients behind CGNAT or with many apps/devices will see failures"
      add_verdict "Server completes only ${succ}/${n} concurrent TLS handshakes — a low concurrent-connection cap / rate-limit. Raise the listener backlog + OS limits (ulimit -n / somaxconn) and check any fail2ban / iptables connection-rate rules [server-side]" ;;
    degraded)
      warn "${succ}/${n} completed but the handshake time ballooned ${minms}→${maxms}ms under load — soft throttle / resource contention under concurrency" ;;
    all-failed)
      warn "0/${n} concurrent handshakes completed although TCP is open — connections are dropped under concurrency (aggressive cap or SYN-rate protection)"
      add_verdict "0/${n} concurrent TLS handshakes completed despite an open TCP port — the server drops connections under concurrency. Investigate connection-rate limiting / SYN protections and OS limits [server-side]" ;;
  esac
}

# --yt-test N: open N concurrent connections THROUGH the tunnel to real YouTube-infra
# hosts (round-robin over XRAY_YT_HOSTS) and report how many complete + TTFB spread.
# This is the connection FAN-OUT real playback generates (parallel chunk/thumbnail/API
# origins), so it catches the "VPN connects but YouTube buffers/won't load" case that a
# single-stream throughput test misses — and empirically confirms what probe 16 infers
# (googlevideo throttles datacenter egress IPs). Reuses probe 12's tunnel INBOUND (xray
# + SOCKS port) but runs INDEPENDENTLY of probe 12's pass/fail verdict — so a Cloudflare
# block (probe 12's target) doesn't suppress the YouTube measurement, and a divergence
# between the two becomes its own signal. Reuses --conn-test's clean/capped/degraded/
# all-failed buckets. On by default for tunnel runs.
probe_yt_reach() {
  [ -n "${YT_TEST_N:-}" ] || { YT_REACH_STATUS="disabled"; return 0; }   # --no-yt-test → fully silent
  [ "$YT_TEST_N" -ge 1 ]   2>/dev/null || YT_TEST_N=16
  [ "$YT_TEST_N" -le 128 ] 2>/dev/null || YT_TEST_N=128
  local n="$YT_TEST_N" port="${XRAY_JSON_SOCKS_PORT:-}"
  # Print the header even when we skip, so it's visibly "ran but skipped (why)" rather
  # than silently absent — it's on by default, users expect to see it.
  hdr "YouTube reachability under fan-out (via the tunnel)"
  # On by default for tunnel runs, but auto-skip inside --watch / --from-file loops
  # so a monitoring cadence doesn't hammer YouTube every iteration. Force with --yt-test.
  if [ "${YT_TEST_FORCE:-0}" != "1" ] \
     && { [ "${_WATCH_CHILD:-0}" = "1" ] || [ "${_BATCH_CHILD:-0}" = "1" ]; }; then
    info "skipped in watch/batch loop to avoid repeated YouTube traffic — pass --yt-test to force"
    YT_REACH_STATUS="skipped-loop"; return 0
  fi
  # INDEPENDENT of probe 12's verdict: we only need its tunnel INBOUND (the xray
  # process + SOCKS port) to be up — NOT for its Cloudflare reachability to have
  # passed. probe 12 leaves xray running on failure (killed only at EXIT), so if
  # Cloudflare was blocked/reset but YouTube works (or vice versa), we still measure
  # it. Only skip if there's genuinely no tunnel inbound to send through.
  if ! { [ -n "${XRAY_JSON_XRAY_PID:-}" ] && kill -0 "$XRAY_JSON_XRAY_PID" 2>/dev/null && [ -n "$port" ]; }; then
    info "skipped — no tunnel inbound is up (xray-core didn't start; see probe 12)"
    YT_REACH_STATUS="skipped"; return 0
  fi
  [ "${XRAY_JSON_STATUS:-}" = "ok" ] || info "probe 12 (Cloudflare) failed, but the tunnel inbound is up — testing YouTube independently through it"
  check_cmd curl || { warn "skipping — curl not available"; YT_REACH_STATUS="curl-missing"; return 0; }
  local ha; read -ra ha <<< "$XRAY_YT_HOSTS"
  local nh=${#ha[@]}; [ "$nh" -ge 1 ] || { YT_REACH_STATUS="error"; return 0; }
  # Each SOCKS connection opens a fresh tunnel hop, so the budget clears the Reality
  # handshake RTT (≈ probe-12 RTT) on top of $TIMEOUT — but CAPPED: this is a quick
  # reachability test, it must not inherit probe 12's slow-handshake-retry RTT (which
  # can be ~20s) or a broken/silent tunnel would make every connection hang that long.
  local maxt; maxt=$(( ( ${XRAY_JSON_RTT_MS:-3000} + 999 ) / 1000 + TIMEOUT ))
  [ "$maxt" -gt 10 ] && maxt=10
  # If probe 12 already failed, the tunnel is suspect: confirm YouTube quickly (≤6s)
  # AND with a SINGLE probe — enough to disentangle "Cloudflare-specific block" from
  # "dead tunnel" without firing a doomed 6-way fan-out (which is what made this hang
  # on a broken config). The full fan-out only runs when the tunnel works, or when the
  # user explicitly forces it with --yt-test.
  if [ "${XRAY_JSON_STATUS:-}" != "ok" ] && [ "${YT_TEST_FORCE:-0}" != "1" ]; then
    [ "$maxt" -gt 6 ] && maxt=6
    n=1
  fi
  local d i host; d=$(mktemp -d -t detect_blocking.yt.XXXXXX) || { YT_REACH_STATUS="error"; return 0; }
  if [ "$n" = "1" ]; then
    info "tunnel suspect — quick 1-connection reachability check (up to ${maxt}s; --yt-test forces the full ${YT_TEST_N}-way fan-out)"
  else
    info "probing ${n} connection(s) across ${nh} YouTube host(s) via the tunnel (up to ${maxt}s)…"
  fi
  local pids=""
  for i in $(seq 1 "$n"); do
    host="${ha[$(( (i-1) % nh ))]}"
    ( curl -sS --max-time "$maxt" --socks5-hostname "127.0.0.1:$port" \
        -o /dev/null -w '%{time_starttransfer} %{http_code}' \
        "https://${host}/" 2>/dev/null > "$d/$i"; : > "$d/$i.done" ) &
    pids="$pids $!"
  done
  # Live progress (interactive terminal only — suppressed under --json, and when
  # stderr is redirected to a file/pipe/CI so the \r + \033[K cursor codes don't
  # leak in as literal bytes) so a slow/dead tunnel shows a ticking counter
  # instead of looking frozen.
  if [ "${LOG_QUIET:-0}" != "1" ] && [ -t 2 ]; then
    local _el=0 _dn=0
    while [ "$_dn" -lt "$n" ] && [ "$_el" -le "$maxt" ]; do
      _dn=$(find "$d" -name '*.done' 2>/dev/null | grep -c .)
      printf '\r          probing… %s/%s done (%ss)   ' "$_dn" "$n" "$_el" >&2
      [ "$_dn" -lt "$n" ] && { sleep 1; _el=$((_el+1)); }
    done
    printf '\r\033[K' >&2
  fi
  # Wait ONLY for our curls — a bare `wait` would also block on the long-lived
  # xray-core background job (probe 12) and hang forever.
  # shellcheck disable=SC2086
  [ -n "$pids" ] && wait $pids 2>/dev/null
  local succ=0 fail=0 minms="" maxms=0 line ttfb code ms
  for i in $(seq 1 "$n"); do
    line=$(cat "$d/$i" 2>/dev/null); ttfb=${line%% *}; code=${line##* }
    case "$code" in [1-5][0-9][0-9])
        succ=$((succ+1)); ms=$(awk -v s="${ttfb:-0}" 'BEGIN{printf "%d", (s+0)*1000}')
        { [ -z "$minms" ] || [ "$ms" -lt "$minms" ]; } && minms=$ms
        [ "$ms" -gt "$maxms" ] && maxms=$ms ;;
      *) fail=$((fail+1)) ;;
    esac
  done
  rm -rf "$d"; [ -z "$minms" ] && minms=0
  YT_REACH_STATUS="ok"; YT_REACH_REQUESTED="$n"; YT_REACH_SUCC="$succ"; YT_REACH_FAIL="$fail"
  YT_REACH_MINMS="$minms"; YT_REACH_MAXMS="$maxms"
  YT_REACH_VERDICT=$(_classify_conn_limit "$succ" "$n" "$minms" "$maxms")
  case "$YT_REACH_VERDICT" in
    clean)
      ok "YouTube handled ${succ}/${n} concurrent connections via the tunnel (${minms}-${maxms}ms TTFB) — loads fine under realistic fan-out" ;;
    capped)
      warn "only ${succ}/${n} concurrent YouTube connections completed through the tunnel — it can't sustain the connection fan-out real playback needs (partial loads / buffering likely)"
      add_verdict "YouTube: only ${succ}/${n} concurrent connections completed through the tunnel — the tunnel/server caps concurrency or the egress is partially blocked by Google. Check server connection limits (mux/ulimit) and the egress IP's reputation [server-side]" ;;
    degraded)
      warn "${succ}/${n} completed but TTFB ballooned ${minms}→${maxms}ms under load — Google is likely throttling the egress IP (datacenter egress); expect buffering"
      add_verdict "YouTube reachable but TTFB degrades badly under concurrency (${minms}→${maxms}ms) — googlevideo throttles datacenter/VPN egress IPs. Route YouTube via a residential/clean egress for usable playback [server-side]" ;;
    all-failed)
      # Blaming the EGRESS only makes sense if the tunnel demonstrably carries traffic.
      # When probe 12 also failed, "YouTube unreachable" is a restatement of "the tunnel
      # is dead" and says nothing about egress reputation — asserting it anyway sends the
      # operator to audit a healthy egress. (Seen on a real in-region run: the tool said
      # the tunnel carried nothing AND that Google had listed the egress, in one report.)
      if [ "${XRAY_JSON_STATUS:-}" = "ok" ]; then
        warn "0/${n} — YouTube is unreachable through a WORKING tunnel (probe 12 passed); the egress IP is likely blocked/listed by Google, or routing drops these destinations"
        add_verdict yt-egress-blocked "YouTube: 0/${n} connections completed through the tunnel, while probe 12 confirmed the tunnel itself carries traffic — so the egress IP is blocked/listed by Google or YouTube is force-routed to a dead path. Verify the egress reputation [server-side]"
      else
        warn "0/${n} — YouTube unreachable through the tunnel, but probe 12 did not confirm the tunnel carries traffic either, so this is NOT evidence about the egress (see the cross-reference below)"
      fi ;;
  esac
  # Cross-reference with probe 12: now that YT runs independently, a divergence is a
  # real signal — disentangles "dead tunnel" from "one destination blocked".
  if [ "${XRAY_JSON_STATUS:-}" != "ok" ]; then
    case "$YT_REACH_VERDICT" in
      clean|degraded|capped)
        info "→ YouTube works through the tunnel even though probe 12's Cloudflare check failed: the tunnel is ALIVE; Cloudflare specifically is blocked/reset at the egress (or was transient), not the whole tunnel"
        add_verdict tunnel-cf-only-block "Tunnel carries YouTube but not Cloudflare (probe 12) — a destination-specific egress block on Cloudflare, NOT a dead tunnel; re-check probe 12 against a different target before concluding the config is broken" ;;
      all-failed)
        info "→ both Cloudflare (probe 12) and YouTube fail through the tunnel: the tunnel itself isn't passing traffic — most likely the Reality outbound/auth failed (verify UUID / keys / flow / target SNI), not a per-site block" ;;
    esac
  fi
}

# Happ routing-profile recognition. A happ://routing/add/ link carries a
# routing + DNS ruleset, NOT a server — so there's nothing to tunnel-test. We
# decode it, summarise it, and lint the parts the tool already reasons about
# (the IPOnDemand DNS-leak vector, and a remote DoH resolver that's itself
# region-blocked) so the user gets something useful instead of a dead end.
probe_happ_routing() {
  [ -n "${HAPP_ROUTING:-}" ] || return 0
  hdr "Happ routing profile (no server — informational)"
  if ! command -v jq >/dev/null 2>&1 || ! printf '%s' "$HAPP_ROUTING_SRC" | jq empty >/dev/null 2>&1; then
    warn "could not decode the routing profile (not valid JSON)"
    return 0
  fi
  local name strat fakedns remote_dns route_order global
  name=$(printf '%s' "$HAPP_ROUTING_SRC" | jq -r '.Name // "(unnamed)"')
  strat=$(printf '%s' "$HAPP_ROUTING_SRC" | jq -r '.DomainStrategy // "?"')
  fakedns=$(printf '%s' "$HAPP_ROUTING_SRC" | jq -r 'if .FakeDns then "on" else "off" end')
  remote_dns=$(printf '%s' "$HAPP_ROUTING_SRC" | jq -r '.RemoteDNSDomain // .RemoteDNSIp // "?"')
  route_order=$(printf '%s' "$HAPP_ROUTING_SRC" | jq -r '.RouteOrder // "?"')
  global=$(printf '%s' "$HAPP_ROUTING_SRC" | jq -r 'if .GlobalProxy then "on" else "off" end')
  info "profile \"${name}\" — a routing/DNS ruleset, not a server (no address / id / cover here, so nothing to tunnel-test)"
  info "DomainStrategy=${strat}, RouteOrder=${route_order}, GlobalProxy=${global}, FakeDns=${fakedns}, remote DNS=${remote_dns}"
  case "$strat" in
    IPOnDemand|IPIfNonMatch)
      if [ "$fakedns" = "on" ]; then
        info "DomainStrategy=${strat} resolves destination domains to evaluate geoip rules (a DNS-leak vector) — FakeDns=on here mitigates it: the engine matches on synthetic IPs instead of doing real lookups"
      else
        warn "DomainStrategy=${strat} resolves destination domains via the configured DNS to evaluate geoip rules — a DNS-leak vector; enable FakeDns, or use domainStrategy=AsIs"
      fi ;;
  esac
  case "$remote_dns" in
    *cloudflare*|*dns.google*|*google*)
      info "remote DNS is ${remote_dns} — note this resolver's own domain is blocked in some regions (e.g. cloudflare-dns.com / dns.google in RU); a DoH resolver that's unreachable in-region silently breaks resolution there (resolver-agnostic: prefer one reachable from the target region)" ;;
  esac
  info "to test the tunnel itself, pass the VLESS/Reality config this profile is paired with"
}

# Happ encrypted deep link. happ://crypt… wraps the server/subscription with RSA
# (PKCS#1) — only the Happ app holding the private key can open it. We detect it
# and say so rather than failing on an undecodable blob.
probe_happ_crypt() {
  [ -n "${HAPP_CRYPT:-}" ] || return 0
  hdr "Happ encrypted deep link (crypt)"
  warn "this is an RSA-encrypted Happ link — the server/subscription is hidden and only the Happ app with the private key can open it; it cannot be decoded here"
  info "paste the decrypted vless:// (or the plain subscription URL) to test the server"
}

# Subscription inventory — prints the fleet decoded from --subscription (one line
# per config: remarks + the first proxy outbound's protocol/security/server/cover),
# marking the index being deep-tested. Values are run through _safe (a sub is
# untrusted input). The selected config is tested by the normal probes below.
probe_subscription_inventory() {
  { [ -n "${SUB_DIR:-}" ] && [ -d "$SUB_DIR" ]; } || return 0
  hdr "Subscription inventory (${SUB_COUNT:-?} configs)"
  local f i=0 line
  for f in "$SUB_DIR"/[0-9][0-9][0-9].json; do
    [ -f "$f" ] || continue
    line=$(jq -r '
      (.remarks // .name // "?") as $r
      | ([.outbounds[]? | select(.settings.vnext != null or .settings.servers != null)
          | "\(.protocol)/\(.streamSettings.security // "none") "
            + ((.settings.vnext // .settings.servers)[0].address) + ":" + ((.settings.vnext // .settings.servers)[0].port|tostring)
            + " cover=\(.streamSettings.realitySettings.serverName // "-")"]) as $o
      | "[\($r)] " + (if ($o|length) > 0 then $o[0] else "(no proxy outbound — e.g. Hysteria/sing-box)" end)
    ' "$f" 2>/dev/null)
    line=$(_safe "$line")
    if [ "$i" = "${SUB_TEST:-0}" ]; then info "→ #${i} ${line}  ◀ tested below"; else info "  #${i} ${line}"; fi
    i=$((i+1))
  done
  info "deep-test another server with: --sub-test N   (N = 0..$(( ${SUB_COUNT:-1} - 1 )))"
}

# Pad string $1 to $2 DISPLAY columns (trailing spaces), truncating with an
# ellipsis if longer. printf's '%-Ns' counts BYTES, which mangles the alignment of
# any column holding CJK / Cyrillic / emoji (each row's byte-vs-display delta
# differs, so everything after it shifts). perl -CS counts CHARACTERS and truncates
# on a char boundary — exact for Latin/Cyrillic/flag emoji, at most ~1 col off per
# wide pictograph, and never cuts mid-codepoint. Falls back to byte-pad if perl is
# absent (ragged, like before, but never corrupt).
# Collapse a sorted list of integers (one per line on stdin) into compact ranges:
# "0 1 2 3 5 7 8" → "0-3,5,7-8". Used to render the node lists in the fleet
# remediation plan without printing 25 individual indices.
_compress_ranges() {
  awk '
    NR==1 { start=$1; prev=$1; next }
    $1 == prev+1 { prev=$1; next }
    { out = out sep (start==prev ? start"" : start"-"prev); sep=","; start=$1; prev=$1 }
    END { if (NR>0) { out = out sep (start==prev ? start"" : start"-"prev); print out } }
  '
}

# Build a profile×signal MATRIX from "<base-signal> <node-idx>" lines on stdin —
# the systematic view of the fleet's tells. Groups nodes by identical signal-SET and
# emits TAB-tagged lines for the caller to render: HDR (2-char column codes), one ROW
# per group (count, x/. cells, comma-idx list), TOT (per-signal node totals), LEG
# (code→name legend). Columns = the canonical-ordered signals present in the fleet.
# Cells are ASCII (x/.) and every field is width-3 so columns align (no multibyte).
_signal_matrix() {
  awk '
    BEGIN{
      N=split("self-signed:SS cover-mismatch:CM chain-invalid:CI cn!=sni:CN no-relay:NR tls-parity:TP sni!=ip:SI sni-nxdomain:NX cover-obscure:CO non443:NP sni-kw:KW vision-off:VO utls-rare:UT mux:MX fet:FE id-nonuuid:ID clock:CK exposed:EX throttle?:TH", o, " ")
      for(i=1;i<=N;i++){ split(o[i],kv,":"); name[i]=kv[1]; code[i]=kv[2] }
    }
    NF>=2{ has[$2 SUBSEP $1]=1; node[$2]=1; present[$1]=1 }
    END{
      nc=0; for(i=1;i<=N;i++) if(present[name[i]]){ nc++; cn[nc]=name[i]; cc[nc]=code[i] }
      for(nd in node){ sig=""; for(c=1;c<=nc;c++) sig=sig (has[nd SUBSEP cn[c]]?"1":"0"); mem[sig]=mem[sig](mem[sig]==""?"":",")nd; gc[sig]++ }
      h=""; for(c=1;c<=nc;c++) h=h sprintf("%-3s",cc[c]); printf "HDR\t%s\n",h
      for(sig in mem){ cells=""; for(c=1;c<=nc;c++){ on=(substr(sig,c,1)=="1"); cells=cells sprintf("%-3s",(on?"x":".")); if(on) tot[c]+=gc[sig] } printf "ROW\t%d\t%s\t%s\n",gc[sig],cells,mem[sig] }
      tc=""; for(c=1;c<=nc;c++) tc=tc sprintf("%-3s",tot[c]); printf "TOT\t%s\n",tc
      leg=""; for(c=1;c<=nc;c++) leg=leg cc[c]"="cn[c]" "; printf "LEG\t%s\n",leg
    }
  '
}

# Fit a "host:port" endpoint into $2 columns WITHOUT losing the port: if it
# overflows, truncate the HOST (ASCII, '~' marker) and keep ":port" — so the column
# never overruns and shifts the rest of the table, yet the port (real data) is never
# cut. A value with no ':' (e.g. the "(no vless outbound)" label) is tail-truncated.
# Endpoints are ASCII (domains / IPv4 / bracketed IPv6), so byte length == columns.
_ep_fit() {
  local s="${1-}" w="$2" host port hb
  [ "${#s}" -le "$w" ] && { printf '%s' "$s"; return; }
  case "$s" in
    *:*) port="${s##*:}"; host="${s%:*}"
         hb=$(( w - ${#port} - 2 )); [ "$hb" -lt 1 ] && hb=1
         printf '%s~:%s' "${host:0:$hb}" "$port" ;;
    *)   printf '%s~' "${s:0:$((w-1))}" ;;
  esac
}

_wpad() {
  local s="${1-}" w="$2"
  if command -v perl >/dev/null 2>&1; then
    printf '%s' "$s" | perl -CS -e '
      my $w = shift; local $/; my $x = <STDIN>; $x //= ""; chomp $x;
      $x = substr($x, 0, $w - 1) . "\x{2026}" if length($x) > $w;
      my $pad = $w - length($x); $pad = 0 if $pad < 0;
      print $x, " " x $pad;
    ' "$w"
  else
    printf '%-*s' "$w" "$s"
  fi
}

# Pure helper (unit-testable): given a per-server run's JSON blob, emit a single
# TAB-separated line "score<TAB>band<TAB>fp<TAB>tells". `tells` is a compact,
# comma-joined list of the dominant detectability signals that drove the score —
# all sourced from DIRECT probes that run under --no-tunnel (15 cover-cert,
# 20 active-probe, 24 TLS-parity, host-exposure, 26 detectability) — so the fleet
# table can show WHY each node scores what it does. "clean" = no signal fired.
_fleet_row_fields() {
  printf '%s' "${1-}" | jq -r '
    .probes as $p
    | (($p // {}).xray_detectability // {}) as $d
    | ($p.xray_cover // {})        as $cv
    | ($p.xray_active_probe // {}) as $ap
    | ($p.xray_tls_parity // {})   as $tp
    | ($p.xray_lint // {})         as $ln
    | ($p.xray_clock // {})        as $ck
    | (($p.host_exposure // {}).open_ports // []) as $op
    # which TLS dimensions diverged from the cover (only set when parity mismatched)
    | ([ (if $tp.version_match == false then "ver"    else empty end),
         (if $tp.alpn_match    == false then "alpn"   else empty end),
         (if $tp.cipher_match  == false then "cipher" else empty end),
         (if $tp.ext_match     == false then "ext"    else empty end) ] | join("+")) as $pdims
    # the active prober got this from the server posing as the cover. curl "000"
    # (or empty) means NO HTTP response at all — show it as "noresp", not a code.
    | (($ap.relay_http_code // "") | tostring) as $relcode
    | (if ($relcode == "" or $relcode == "000") then "noresp" else $relcode end) as $reldisp
    | [ (($d.score // "?") | tostring),
        ($d.band // "?"),
        ((($d.deployment_fingerprint) // "-") | tostring | .[0:8]),
        # tells: each signal carries its value where it has one, so the table is
        # actionable (which port / which HTTP code / which TLS dim), not just labels.
        ([ (if   $cv.status == "fake"        then "self-signed"
            elif $cv.status == "mismatch"    then "cover-mismatch"
            elif $cv.status == "unreachable" then "cover-unreach" else empty end),
           (if $cv.chain_valid == false           then "chain-invalid" else empty end),
           (if $cv.cn_matches_servername == false then "cn!=sni"       else empty end),
           (if $ap.matches_cover == false then "no-relay:" + $reldisp else empty end),
           (if $tp.status == "mismatch"
              then "tls-parity" + (if $pdims != "" then ":" + $pdims else "" end)
              else empty end),
           (if $d.tls_in_tls_protected == false then "vision-off"    else empty end),
           (if $d.sni_ip_asn_match == false     then "sni!=ip"       else empty end),
           (if $d.sni_resolves == false         then "sni-nxdomain"  else empty end),
           (if $d.port_standard == false        then "non443"        else empty end),
           (if $d.sni_keyword == true           then "sni-kw"        else empty end),
           (if $d.cover_obscure == true         then "cover-obscure" else empty end),
           (if $ln.fet_exposed == true          then "fet"           else empty end),
           (if $d.mux_enabled == true           then "mux"           else empty end),
           (if $ln.id_uuid == false             then "id-nonuuid"    else empty end),
           (if $d.utls_fp_uncommon == true
              then "utls-rare" + (if (($d.utls_fp // "") | tostring) != "" then ":" + ($d.utls_fp | tostring) else "" end)
              else empty end),
           (if ($ck.skew_seconds != null and ($ck.skew_seconds | fabs) >= 5)
              then "clock:" + ($ck.skew_seconds | tostring) + "s" else empty end),
           (if ($op | length) > 0
              then "exposed:" + (($op | map(tostring | split("/")[0]))[0:2] | join("+"))
                   + (if ($op | length) > 2 then "+" + ((($op | length) - 2) | tostring) + "more" else "" end)
              else empty end),
           (if $d.volume_throttle_suspected == true then "throttle?" else empty end)
         ] | if length == 0 then "clean" else join(",") end) ]
    | @tsv' 2>/dev/null
}

# One fleet node: parse its endpoint, do a bounded TCP precheck, then (if up) a
# no-tunnel fingerprint self-invoke → write ONE tab-separated row file into SUB_DIR
# (idx, kind, remarks, server, cover, detect, fp, tells, band). Runs as a background
# job so a whole fleet probes concurrently; the parent renders the rows in order.
# All attacker-influenced values are _safe-sanitised before they reach the row.
_walk_one() {
  local f="$1" pad idx remarks host port cover server j score band fp tells detect kind yt
  pad=$(basename "$f" .json); idx=$((10#$pad))
  yt="-"   # YouTube fan-out result; stays "-" unless YT-mode walk runs a per-node tunnel
  remarks=$(_safe "$(jq -r '.remarks // .name // "?"' "$f" 2>/dev/null)")
  host=$(_safe "$(jq -r 'first(.outbounds[]? | select(.settings.vnext != null or .settings.servers != null) | (.settings.vnext // .settings.servers)[0].address) // empty' "$f" 2>/dev/null)")
  port=$(_safe "$(jq -r 'first(.outbounds[]? | select(.settings.vnext != null or .settings.servers != null) | (.settings.vnext // .settings.servers)[0].port) // empty' "$f" 2>/dev/null)")
  cover=$(_safe "$(jq -r 'first(.outbounds[]? | .streamSettings.realitySettings.serverName // empty) // "-"' "$f" 2>/dev/null)")
  if [ -z "$host" ]; then
    kind=skip; server="(no vless outbound)"; cover="-"; detect="skip (HY)"; fp="-"; tells="no Reality fingerprint"; band=""
  else
    server="${host}:${port}"
    # Bounded TCP precheck (nc -G/-w $TIMEOUT) — a dead server's openssl connect
    # would otherwise hang the OS connect timeout (~75s), not $TIMEOUT.
    if ! _nc_tcp_probe "$host" "$port"; then
      kind=dead; detect="unreachable"; fp="-"; tells="TCP refused/filtered"; band=""
    else
      if [ "${YT_TEST_FORCE:-0}" = "1" ]; then
        # YT-mode walk (--sub-test all --yt-test): spin a per-node tunnel so probe 12
        # comes up and the YouTube fan-out runs (default N=6). --xray-only skips
        # transport 0-10; --no-speedtest/--no-stability/--no-bufferbloat drop the slow
        # data-plane QoE probes (14/17/22) — they dominated wall time (one flaky node's
        # stability pulses alone took ~100s) and feed NOTHING in the fleet table (they
        # don't move the detectability score). Still slower than the fingerprint walk
        # (one xray per node) — hence opt-in. Detectability stays tunnel-aware via the
        # cover/active-probe/parity/egress probes, just without the QoE measurements.
        j=$(bash "$0" --xray-config-json "$f" --xray-only --no-speedtest --no-stability --no-bufferbloat --json 2>/dev/null)
        yt=$(printf '%s' "$j" | jq -r '
          (.probes.youtube_reach // {}) as $y
          | if $y.status == "ok"
            then (($y.succeeded|tostring) + "/" + ($y.requested|tostring) + " "
                  + (if   $y.verdict == "clean"      then "ok"
                     elif $y.verdict == "degraded"   then "slow"
                     elif $y.verdict == "capped"     then "capped"
                     elif $y.verdict == "all-failed" then "fail"
                     else ($y.verdict // "?") end))
            else "-" end' 2>/dev/null)
        yt="${yt:--}"
      else
        # --only xray,xrayjson skips transport probes (0-10); --no-tunnel skips the
        # xray-spawning/data probes → just the direct fingerprint.
        j=$(bash "$0" --xray-config-json "$f" --only xray,xrayjson --no-tunnel --json 2>/dev/null)
      fi
      IFS=$'\t' read -r score band fp tells <<EOF
$(_fleet_row_fields "$j")
EOF
      score="${score:-?}"; band="${band:-?}"; fp="${fp:--}"; tells="${tells:-?}"
      detect="${score}/${band}"; kind=scored
    fi
  fi
  # Self-heal the row dir: under heavy concurrency the dir has been observed briefly
  # unavailable on some systems, which made this redirect fail with ENOENT (a noisy
  # but non-fatal "012.row: No such file or directory"). mkdir -p is idempotent and
  # cheap, and guarantees the write target exists regardless of the transient.
  [ -d "$SUB_DIR" ] || mkdir -p "$SUB_DIR" 2>/dev/null
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$idx" "$kind" "$remarks" "$server" "$cover" "$detect" "$fp" "$tells" "$band" "$yt" > "$SUB_DIR/$pad.row" 2>/dev/null
}

# --sub-test all: score EVERY config in the sub with a fast no-tunnel fingerprint
# pass (one _walk_one self-invoke per config → reuses the whole probe pipeline),
# run CONCURRENTLY in batches of --sub-jobs (default 8), and print a fleet
# detectability table + root-cause synthesis. No xray spawn / no data pull, so a
# 28-server fleet is just TLS handshakes. Deep-test any row with --sub-test N.
probe_subscription_walk() {
  { [ -n "${SUB_DIR:-}" ] && [ -d "$SUB_DIR" ]; } || return 0
  # Compact, fixed-width table that never wraps: the per-node "tells" are NOT a
  # column here — they're a ~100-char string that repeats across same-template nodes
  # and overran the line. They're shown deduplicated under "node profiles" below.
  # remarks via _wpad (multibyte display-width), server:port via _ep_fit (port kept).
  # YT mode (--sub-test all --yt-test): per-node tunnel + YouTube fan-out, extra
  # "YouTube" column. Opt-in because it spawns one xray per node (much slower).
  local yt_mode=0; [ "${YT_TEST_FORCE:-0}" = "1" ] && yt_mode=1
  local rw=24 sw=38 fmt
  if [ "$yt_mode" = 1 ]; then
    fmt='          %-3s %s %-38s %-16.16s %-13s %-11s %s\n'
    hdr "Subscription fleet scan — ${SUB_COUNT} configs (tunnel + YouTube per node)"
    info "fp = deployment template; YouTube = succeeded/requested + verdict (ok / slow=throttled / capped / fail) via a per-node tunnel"
    # shellcheck disable=SC2059
    printf "$fmt" "#" "$(_wpad remarks "$rw")" "server:port" "cover" "detect" "YouTube" "fp"
  else
    fmt='          %-3s %s %-38s %-16.16s %-13s %s\n'
    hdr "Subscription fleet scan — ${SUB_COUNT} configs (fingerprint-only, no tunnel)"
    info "fp = deployment template (same fp = same server build); per-node signals are in the 'signal matrix' below"
    # shellcheck disable=SC2059
    printf "$fmt" "#" "$(_wpad remarks "$rw")" "server:port" "cover" "detect" "fp"
  fi

  # Probe the fleet CONCURRENTLY in batches of $jobs (each _walk_one writes its own
  # row file → no shared state, no interleaved output). A 28-node fleet goes from
  # minutes to seconds; --sub-jobs 1 forces serial. In YT mode each job spawns a
  # full tunnel, so default to a smaller batch (3) to avoid xray thrash.
  local _defjobs=8; [ "$yt_mode" = 1 ] && _defjobs=3
  local jobs="${SUB_JOBS:-$_defjobs}"
  case "$jobs" in ''|*[!0-9]*) jobs=$_defjobs ;; esac
  [ "$jobs" -ge 1 ] || jobs=$_defjobs
  local f running=0
  for f in "$SUB_DIR"/[0-9][0-9][0-9].json; do
    [ -f "$f" ] || continue
    _walk_one "$f" &
    running=$((running+1))
    if [ "$running" -ge "$jobs" ]; then wait; running=0; fi
  done
  wait

  # Render the row files in index order and tally as we go.
  local rf idx kind remarks server cover detect fp tells band yt
  local crit=0 high=0 mod=0 low=0 dead=0 plan_lines="" fp_counts=""
  for rf in "$SUB_DIR"/[0-9][0-9][0-9].row; do
    [ -f "$rf" ] || continue
    IFS=$'\t' read -r idx kind remarks server cover detect fp tells band yt < "$rf"
    # shellcheck disable=SC2059
    if [ "$yt_mode" = 1 ]; then
      printf "$fmt" "$idx" "$(_wpad "$remarks" "$rw")" "$(_ep_fit "$server" "$sw")" "$cover" "$detect" "${yt:--}" "$fp"
    else
      printf "$fmt" "$idx" "$(_wpad "$remarks" "$rw")" "$(_ep_fit "$server" "$sw")" "$cover" "$detect" "$fp"
    fi
    case "$kind" in
      dead) dead=$((dead+1)) ;;
      scored)
        case "$band" in critical) crit=$((crit+1)) ;; high) high=$((high+1)) ;; moderate) mod=$((mod+1)) ;; low) low=$((low+1)) ;; esac
        [ "$fp" != "-" ] && fp_counts="${fp_counts}${fp}"$'\n'
        # Accumulate "<base-signal> <node-idx>" pairs (value suffix after ':'
        # stripped, so no-relay:403 / no-relay:noresp group as "no-relay") — drives
        # the signal matrix and the per-fix node lists in the remediation plan.
        case "$tells" in
          clean|'?'|'') : ;;
          *) plan_lines="${plan_lines}$(printf '%s' "$tells" | tr ',' '\n' | sed 's/:.*$//' | awk -v ix="$idx" 'NF{print $1, ix}')"$'\n' ;;
        esac ;;
    esac
  done
  info "fleet detectability: ${crit} critical · ${high} high · ${mod} moderate · ${low} low · ${dead} unreachable (Hysteria entries skipped — no Reality fingerprint)"
  local scored=$(( crit + high + mod + low ))
  # Signal matrix: nodes grouped by identical signal-SET, signals as fixed columns,
  # x/. cells + a per-signal total row. A systematic grid (never wraps) where a
  # uniform fleet collapses to a few rows and any node that differs stands out.
  if [ -n "$plan_lines" ]; then
    info "signal matrix (x = signal fired; rows grouped by identical signal-set, most common first; 'total' = nodes per signal):"
    local _mw=30 _mrow _ma _mb _mc _mtot="" _mleg="" _mrng _mrows=""
    while IFS=$'\t' read -r _mrow _ma _mb _mc; do
      case "$_mrow" in
        HDR) info "$(printf '  %-*s%s' "$_mw" 'nodes' "$_ma")" ;;
        ROW) _mrng=$(printf '%s' "$_mc" | tr ',' '\n' | sort -n | _compress_ranges)
             _mrows="${_mrows}${_ma}"$'\t'"$(printf '  %-*s%s' "$_mw" "[${_mrng}] (${_ma})" "$_mb")"$'\n' ;;
        TOT) _mtot="$_ma" ;;
        LEG) _mleg="$_ma" ;;
      esac
    done < <(printf '%s' "$plan_lines" | _signal_matrix)
    printf '%s' "$_mrows" | sort -t"$(printf '\t')" -k1,1nr | cut -f2- | while IFS= read -r _l; do info "$_l"; done
    [ -n "$_mtot" ] && info "$(printf '  %-*s%s' "$_mw" 'total' "$_mtot")"
    [ -n "$_mleg" ] && info "  legend: ${_mleg}"
  fi
  if [ "$scored" -gt 0 ] && [ -n "$plan_lines" ]; then
    # Remediation plan: many of those signals are SYMPTOMS of one root fix (e.g.
    # self-signed / chain-invalid / cn!=sni / no-relay / tls-parity all clear when
    # the cover is relayed), so we collapse them into a handful of actionable fixes,
    # each annotated with how many nodes it clears and which (range-compressed), and
    # ranked by impact. A node can appear under several fixes — it needs each.
    info "remediation plan (fixes ranked by nodes affected; a node may need several):"
    # group = "<comma-signals>|<fix text>". The delimiter is '|' (NOT '='), because
    # signal tokens themselves contain '=' (cn!=sni, sni!=ip).
    local _g _sigs _fix _idxs _cnt _rng _pri=0 _planout=""
    for _g in \
      "self-signed,cover-mismatch,chain-invalid,cn!=sni,no-relay,tls-parity,sni!=ip|Reality cover not relayed / cover-cert invalid — point Reality dest + serverNames at the real cover host:443 (server-side; clears self-signed/chain/cn/no-relay/parity at once)" \
      "sni-nxdomain,cover-obscure|Cover SNI does not resolve or is a low-quality/self-owned domain — use a real, resolvable, popular HTTPS cover the server actually relays to" \
      "non443|Listener on a non-standard port — move it to 443" \
      "exposed|Management/SSH port(s) open on the VPN IP — firewall so only 443 is reachable from outside" \
      "sni-kw|Circumvention keyword in the SNI — change serverName to an innocuous popular domain" \
      "vision-off|TLS-in-TLS not protected — set flow=xtls-rprx-vision" ; do
      _sigs="${_g%%|*}"; _fix="${_g#*|}"; _pri=$((_pri+1))
      _idxs=$(printf '%s' "$plan_lines" | awk -v want=",${_sigs}," 'NF && index(want, ","$1",")>0 {print $2}' | sort -n | uniq)
      [ -n "$_idxs" ] || continue
      _cnt=$(printf '%s\n' "$_idxs" | grep -c .)
      _rng=$(printf '%s\n' "$_idxs" | _compress_ranges)
      _planout="${_planout}${_cnt}	${_pri}	[${_cnt} node(s): ${_rng}] ${_fix}"$'\n'
    done
    # rank by node count desc, ties broken by how fundamental the fix is (def order)
    printf '%s' "$_planout" | sort -t"$(printf '\t')" -k1,1nr -k2,2n | awk -F"$(printf '\t')" 'NF>=3{n++; printf "%d. %s\n", n, $3}' | while IFS= read -r _l; do
      info "  $_l"
    done
  fi
  # Bottom line: a short, COMPUTED synthesis (all grounded in the measured signals) —
  # how uniform the fleet is, how cheaply a censor identifies it, and what exposure
  # remains after the #1 fix (so the plan's payoff and its limits are explicit).
  if [ "$scored" -gt 0 ] && [ -n "$plan_lines" ]; then
    info "bottom line:"
    local _distinct _dom _domc _domfp _ccbad _res
    _distinct=$(printf '%s' "$fp_counts" | grep -v '^$' | sort -u | grep -c .)
    _dom=$(printf '%s' "$fp_counts" | grep -v '^$' | sort | uniq -c | sort -rn | head -1)
    _domc=$(printf '%s' "$_dom" | awk '{print $1}'); _domfp=$(printf '%s' "$_dom" | awk '{print $2}')
    [ -n "$_domfp" ] && info "  · uniformity: ${_distinct} deployment template(s); ${_domfp} covers ${_domc}/${scored} scored nodes — a server-side template fix touches most of the fleet at once"
    # cover-cert-bad = an active prober is served a cert that isn't the cover's
    _ccbad=$(printf '%s' "$plan_lines" | awk '$1=="self-signed"||$1=="cover-mismatch"{print $2}' | sort -u | grep -c .)
    [ "${_ccbad:-0}" -gt 0 ] && info "  · single-probe identifiable: ${_ccbad}/${scored} present a self-signed/mismatched cover cert — one unauthenticated TLS connection to the listener is enough to flag the IP"
    # residual exposure after the #1 (cover-relay) fix: signals it does NOT clear
    # (utls-rare / mux are tradeoffs, not scored — excluded from the residual).
    _res=$(printf '%s' "$plan_lines" | awk '
      BEGIN{split("self-signed cover-mismatch chain-invalid cn!=sni no-relay tls-parity sni!=ip utls-rare mux",x," "); for(i in x) cl[x[i]]=1}
      !cl[$1]{n[$1]++} END{for(s in n) print n[s], s}' | sort -rn | awk '{printf "%s(%s) ", $2, $1}')
    [ -n "$_res" ] && info "  · residual after fix #1 (relay the cover): ${_res}— cleared by fixes #2+"
  fi
  info "deep-test any server (tunnel + throughput + stability) with: --sub-test N"
}

# Hysteria2 static config analysis. Hysteria2 is QUIC over UDP/443 — a different
# stack from Xray/Reality (no cover relay, no TLS-in-TLS), so the Xray probes
# don't apply and a TCP/TLS probe against it would falsely read "unreachable".
# Instead we apply the tool's detection PRINCIPLES to what a client config
# exposes: the cleartext SNI carried in the QUIC Initial (the #1 tell), whether
# obfs/cert hardening is set, and the UDP/443-single-point + QUIC-SNI risks. What
# actually dominates detectability — the server's masquerade / cert / enforced
# obfs — lives in the SERVER config a client file can't see; we say so plainly.
probe_hysteria() {
  [ -n "${HYSTERIA_DETECTED:-}" ] || { HYSTERIA_STATUS="skipped"; return 0; }
  local src="$HYSTERIA_SRC" host="" sni="" eff_sni="" from_uri=0 q=""
  case "$src" in hysteria2://*|hy2://*|hysteria://*) from_uri=1 ;; esac
  if [ "$from_uri" = "1" ]; then
    case "$src" in *\?*) q=${src#*\?}; q=${q%%#*} ;; esac
    host=${src#*://}; host=${host#*@}; host=${host%%[/?]*}; host=${host%%:*}
    sni=$(_qp "$q" sni); [ -z "$sni" ] && sni=$(_qp "$q" peer)
    case "$(_qp "$q" obfs)" in ?*) HYSTERIA_OBFS=1 ;; *) HYSTERIA_OBFS=0 ;; esac
    case "$(_qp "$q" insecure)" in 1|true) HYSTERIA_INSECURE=1 ;; *) HYSTERIA_INSECURE=0 ;; esac
  else
    host=$(grep -iE '^[[:space:]]*server:' "$src" 2>/dev/null | head -1 \
           | sed -E 's/.*server:[[:space:]]*//; s/^["'\'']//; s/["'\'']$//; s/[[:space:]]*#.*$//')
    host=${host#*://}; host=${host%%:*}
    sni=$(grep -iE '^[[:space:]]*sni:' "$src" 2>/dev/null | head -1 \
          | sed -E 's/.*sni:[[:space:]]*//; s/["'\'']//g; s/[[:space:]]*#.*$//; s/[[:space:]]*$//')
    if grep -qiE '^[[:space:]]*obfs:|salamander' "$src" 2>/dev/null; then HYSTERIA_OBFS=1; else HYSTERIA_OBFS=0; fi
    if grep -qiE '^[[:space:]]*insecure:[[:space:]]*true' "$src" 2>/dev/null; then HYSTERIA_INSECURE=1; else HYSTERIA_INSECURE=0; fi
  fi
  [ -z "$host" ] && host="$VPN_HOST"
  if [ -n "$sni" ]; then HYSTERIA_SNI_EXPLICIT=1; eff_sni="$sni"; else HYSTERIA_SNI_EXPLICIT=0; eff_sni="$host"; fi
  HYSTERIA_STATUS="ok"

  hdr "Hysteria2 config analysis (QUIC/UDP — static)"
  info "Hysteria2 detected — QUIC over UDP/443. The Xray/Reality probes (TCP, TLS-in-TLS, cover relay) don't apply; this is a static read of what the client config exposes."

  # 1. The headline tell: a protocol/circumvention keyword in the cleartext SNI.
  #    Hysteria2's QUIC Initial carries the SNI, which the GFW decrypts and reads
  #    (since 2024) — a keyword there is one-glance identification.
  local sni_lc kw=0
  sni_lc=$(printf '%s' "$eff_sni" | tr '[:upper:]' '[:lower:]')
  case "$sni_lc" in
    *hysteria*|*hy2*|*vpn*|*proxy*|*xray*|*v2ray*|*reality*|*shadowsock*|*trojan*|*wireguard*|*outline*|*tuic*|*vless*|*vmess*|*censor*|*unblock*|*bypass*|*-rkn*|*rkn-*)
      kw=1 ;;
  esac
  HYSTERIA_SNI_KEYWORD="$kw"
  if [ "$kw" = "1" ]; then
    warn "the TLS SNI carries a protocol/circumvention keyword — sent in cleartext in the QUIC Initial, which the GFW decrypts and reads (since 2024); a censor identifies and blocklists it at a glance"
    reveal "  effective SNI: $eff_sni"
    add_verdict "Hysteria2 TLS SNI carries a protocol/circumvention keyword (e.g. 'hysteria' / 'vpn'). QUIC sends the SNI in the Initial packet, which the GFW decrypts and reads — one-glance identification. Set tls.sni to an innocuous, popular domain, independent of the connect host [client-side]"
  else
    ok "no protocol/circumvention keyword in the SNI"
  fi

  # 2. SNI defaults to the server hostname when tls.sni is unset → the dedicated
  #    host itself is what rides in the QUIC Initial.
  if [ "$HYSTERIA_SNI_EXPLICIT" = "0" ]; then
    info "no explicit tls.sni — the QUIC Initial SNI defaults to the server hostname, so the dedicated host is what a censor sees; set tls.sni to an innocuous, popular domain (independent of the connect address)"
  fi

  # 3. obfs (salamander) — without it the QUIC/Hysteria handshake is
  #    fingerprintable. (Must be enabled on BOTH ends; absent here = none.)
  if [ "$HYSTERIA_OBFS" = "0" ]; then
    warn "no obfs (salamander) in the client config — the QUIC handshake is fingerprintable; enable 'obfs: salamander' on BOTH the client and server to randomize the wire shape"
    add_verdict "Hysteria2 has no obfs (salamander) configured — the QUIC handshake is fingerprintable by a DPI profiling QUIC. Enable 'obfs: salamander' (shared password) on both client and server [client-side]"
  else
    ok "obfs (salamander) present — the QUIC handshake is obfuscated"
  fi

  # 4. Cert verification disabled.
  if [ "$HYSTERIA_INSECURE" = "1" ]; then
    warn "tls.insecure=true — the client does not verify the server cert (MITM risk, and it can't confirm the masquerade cert is genuine)"
    add_verdict "Hysteria2 client has tls.insecure=true — disables cert verification (MITM exposure; also defeats masquerade-cert validation). Set insecure:false and pin the cert (pinSHA256) instead [client-side]"
  fi

  # 5. UDP/443 single point + the QUIC-SNI advisory.
  info "Hysteria2 lives on UDP/443 with no TCP fallback — a censor that blocks or throttles UDP/443 wholesale (common in RU/CN) takes it down; consider port-hopping (a UDP port range) and/or a TCP-based fallback transport"
  _quic_sni_note

  # 6. What a client config can't show.
  info "detectability is dominated by SERVER-side settings absent from a client config — the masquerade target (what an HTTP prober sees on 443), the TLS cert, and whether obfs is enforced; verify those on the server"
}

# Probe 16 — egress integrity (geo / reputation / DNS leak). Runs through the
# probe-12 tunnel. Tells you if the egress is already on the datacenter/proxy
# lists that streaming & banking services block, and whether DNS resolves in a
# different region than the egress (possible leak). Output: country code +
# flags only — never the raw egress IP. Sends the egress IP to a 3rd-party
# IP-info service; disable with --no-egress-check.
probe_xray_egress() {
  if [ "$XRAY_EGRESS_CHECK" != "1" ]; then
    XRAY_EGRESS_STATUS="disabled"
    return 0
  fi
  if [ "$XRAY_JSON_STATUS" != "ok" ]; then
    XRAY_EGRESS_STATUS="skipped"
    return 0
  fi

  hdr "16. Egress integrity (geo / reputation / DNS)"

  if ! check_cmd curl; then
    warn "skipping — curl not available"
    XRAY_EGRESS_STATUS="curl-missing"
    return 0
  fi

  # Each lookup opens a FRESH tunnel connection, so the budget must clear the
  # Reality handshake (≈ probe-12 RTT) first — a flat $TIMEOUT (default 5s) is
  # shorter than a high-RTT handshake and times the lookup out mid-handshake.
  local port="$XRAY_JSON_SOCKS_PORT" info_json dns_json maxt have_flags=0
  maxt=$(( ( ${XRAY_JSON_RTT_MS:-3000} + 999 ) / 1000 + TIMEOUT ))

  # Source 1 — ip-api (HTTP): country + hosting/proxy/mobile flags.
  info_json=$(curl -sS --max-time "$maxt" --socks5-hostname "127.0.0.1:$port" \
              "$XRAY_EGRESS_INFO_URL" 2>/dev/null)

  # --- parse source 1 (ip-api flags) ---
  if printf '%s' "$info_json" | grep -q '"countryCode"'; then
    have_flags=1
    if command -v jq >/dev/null 2>&1; then
      XRAY_EGRESS_COUNTRY=$(printf '%s' "$info_json" | jq -r '.countryCode // empty' 2>/dev/null)
      XRAY_EGRESS_HOSTING=$(printf '%s' "$info_json" | jq -r 'if .hosting then 1 else 0 end' 2>/dev/null)
      XRAY_EGRESS_PROXY=$(printf '%s'   "$info_json" | jq -r 'if .proxy   then 1 else 0 end' 2>/dev/null)
      XRAY_EGRESS_MOBILE=$(printf '%s'  "$info_json" | jq -r 'if .mobile  then 1 else 0 end' 2>/dev/null)
    else
      XRAY_EGRESS_COUNTRY=$(printf '%s' "$info_json" | sed -nE 's/.*"countryCode":"([^"]*)".*/\1/p')
      printf '%s' "$info_json" | grep -q '"hosting":true' && XRAY_EGRESS_HOSTING=1 || XRAY_EGRESS_HOSTING=0
      printf '%s' "$info_json" | grep -q '"proxy":true'   && XRAY_EGRESS_PROXY=1   || XRAY_EGRESS_PROXY=0
      printf '%s' "$info_json" | grep -q '"mobile":true'  && XRAY_EGRESS_MOBILE=1  || XRAY_EGRESS_MOBILE=0
    fi
  fi

  # --- source 2+ : a pool of HTTPS ASN sources (first responder wins) ---
  local asn_out org cc2=""
  asn_out=$(_egress_asn "$port" "$maxt")
  org=""
  case "$asn_out" in *"$(printf '\t')"*)
    cc2=${asn_out%%"$(printf '\t')"*}
    org=${asn_out#*"$(printf '\t')"} ;;
  esac
  if [ -n "$org" ]; then
    # Known hosting/cloud providers + datacenter keywords. A match is a strong
    # "this is a server network" signal that ip-api's flag sometimes misses.
    if printf '%s' "$org" | grep -qiE 'hosting|datacenter|data.?cent|colo|cloud|vps|dedicated|amazon|aws|azure|microsoft|google|cloudflare|digitalocean|digital ocean|linode|akamai|fastly|vultr|choopa|m247|leaseweb|contabo|scaleway|g.?core|oracle|alibaba|tencent|datacamp|colocrossing|psychz|quadranet|limestone|frantech|buyvm|clouvider|hetzner|ovh|servers|host\b'; then
      XRAY_EGRESS_ASN_HOSTING=1
    else
      XRAY_EGRESS_ASN_HOSTING=0
    fi
  fi
  [ -z "$XRAY_EGRESS_COUNTRY" ] && XRAY_EGRESS_COUNTRY="$cc2"

  # Source 3 (fallback) — when ip-api's flag endpoint was rate-limited (no
  # countryCode above → have_flags=0), get an explicit datacenter/proxy/ASN-type
  # flag from ipapi.is so reputation is still determined, not "n/a". The keyword
  # heuristic (source 2) misses providers not on its list; this is authoritative.
  if [ "$have_flags" = "0" ] && command -v jq >/dev/null 2>&1; then
    local dc_json
    dc_json=$(curl -sS --max-time "$maxt" --socks5-hostname "127.0.0.1:$port" "$XRAY_EGRESS_DC_URL" 2>/dev/null)
    if printf '%s' "$dc_json" | grep -q '"is_datacenter"'; then
      XRAY_EGRESS_DC=$(printf '%s' "$dc_json" | jq -r 'if (.is_datacenter == true) or (((.asn.type // .company.type) // "") | ascii_downcase | test("hosting")) then 1 else 0 end' 2>/dev/null)
      [ -z "$XRAY_EGRESS_PROXY" ] && XRAY_EGRESS_PROXY=$(printf '%s' "$dc_json" | jq -r 'if (.is_proxy==true) or (.is_vpn==true) or (.is_tor==true) then 1 else 0 end' 2>/dev/null)
      [ -z "$XRAY_EGRESS_COUNTRY" ] && XRAY_EGRESS_COUNTRY=$(printf '%s' "$dc_json" | jq -r '(.location.country_code // .country_code) // empty' 2>/dev/null)
    fi
  fi

  # If neither source gave a country, last-resort HTTPS country (Cloudflare).
  if [ -z "$XRAY_EGRESS_COUNTRY" ]; then
    XRAY_EGRESS_COUNTRY=$(curl -sS --max-time "$maxt" --socks5-hostname "127.0.0.1:$port" \
      https://cloudflare.com/cdn-cgi/trace 2>/dev/null | sed -nE 's/^loc=([A-Za-z]{2}).*/\1/p' | head -1)
  fi
  if [ -z "$XRAY_EGRESS_COUNTRY" ]; then
    fail "egress IP-info lookup returned no data through the tunnel (all sources failed)"
    XRAY_EGRESS_STATUS="no-data"
    return 0
  fi

  # DNS resolver (edns, HTTP) — only when port-80 lookups work (ip-api did).
  if [ "$have_flags" = "1" ]; then
    dns_json=$(curl -sS --max-time "$maxt" --socks5-hostname "127.0.0.1:$port" \
               "$XRAY_EGRESS_DNS_URL" 2>/dev/null)
    if printf '%s' "$dns_json" | grep -q '"dns"' && command -v jq >/dev/null 2>&1; then
      XRAY_EGRESS_DNS_COUNTRY=$(printf '%s' "$dns_json" | jq -r '.dns.geo // empty' 2>/dev/null | sed -nE 's/^([A-Za-z ]+) -.*/\1/p')
      [ -z "$XRAY_EGRESS_DNS_COUNTRY" ] && XRAY_EGRESS_DNS_COUNTRY=$(printf '%s' "$dns_json" | jq -r '.dns.geo // empty' 2>/dev/null)
      [ -n "$XRAY_EGRESS_DNS_COUNTRY" ] && info "DNS resolver (via tunnel): ${XRAY_EGRESS_DNS_COUNTRY} — proxied lookups exit through the tunnel (resolved at the egress), not your local resolver; a client-side DNS leak would instead show up as the routing 'domainStrategy' finding, not here"
    fi
  fi

  # Report what each source said (booleans/class only — never the IP or org).
  info "ip-api:  country=${XRAY_EGRESS_COUNTRY:-?}, hosting=${XRAY_EGRESS_HOSTING:-n/a}, proxy=${XRAY_EGRESS_PROXY:-n/a}, mobile=${XRAY_EGRESS_MOBILE:-n/a}"
  info "2nd src: ASN/org looks like a hosting provider = ${XRAY_EGRESS_ASN_HOSTING:-n/a}"
  [ -n "$XRAY_EGRESS_DC" ] && info "3rd src: datacenter/hosting-type ASN = ${XRAY_EGRESS_DC} (fallback — used because ip-api gave no flags)"
  case "$XRAY_EGRESS_INFO_URL" in
    http://*) info "note: ip-api geo/flags come over plain HTTP — an on-path adversary (the censor being profiled) can spoof them; cross-check against the HTTPS 2nd/3rd sources, treat as indicative on a hostile network, or set XRAY_EGRESS_INFO_URL to an HTTPS endpoint" ;;
  esac

  # Entry↔egress co-location — a deployment-topology tell. Most providers egress
  # on a DIFFERENT network than the entry; a deployment that exits from the SAME
  # /24 (or same ASN) as its Reality entry runs ingress+egress on one block — a
  # distinctive, per-provider signature (e.g. an entry .6 exiting via .2 in the
  # same /24). Operator-visible only (a censor doesn't see the egress), so it's
  # reported as identification, not scored. Booleans only — IPs only via --reveal.
  local eg_ip="" entry_ip
  eg_ip=$(printf '%s' "$info_json" | sed -nE 's/.*"query":"([^"]*)".*/\1/p' | head -1)
  [ -z "$eg_ip" ] && eg_ip=$(printf '%s' "${dc_json:-}" | jq -r '.ip // empty' 2>/dev/null)
  # Entry IP: RESOLVED_IP when probe 1 ran, else the (often IP-literal) VPN_HOST.
  entry_ip="${RESOLVED_IP:-$VPN_HOST}"
  if [ -n "$eg_ip" ] && [ -n "$entry_ip" ]; then
    case "$entry_ip$eg_ip" in
      *[!0-9.]*) : ;;  # skip if either isn't a bare IPv4 (v6 / hostname)
      *)
        if [ "${entry_ip%.*}" = "${eg_ip%.*}" ]; then
          XRAY_EGRESS_COLOCATED="same-/24"
        else
          local e_asn g_asn; e_asn=$(_asn_of "$entry_ip"); g_asn=$(_asn_of "$eg_ip")
          if [ -n "$e_asn" ] && [ "$e_asn" = "$g_asn" ]; then XRAY_EGRESS_COLOCATED="same-ASN"
          else XRAY_EGRESS_COLOCATED="different"; fi
        fi ;;
    esac
  fi
  case "$XRAY_EGRESS_COLOCATED" in
    same-/24) info "topology: egress is in the SAME /24 as the Reality entry → single-block deployment (distinctive per-provider tell)" ;;
    same-ASN) info "topology: egress shares the entry's ASN (same provider/network) → co-located deployment" ;;
  esac
  # --reveal: the operator-only specifics the share-safe lines deliberately omit.
  reveal "egress IP = ${eg_ip:-?} | entry IP = ${entry_ip:-?} | org = ${org:-?} | country = ${XRAY_EGRESS_COUNTRY:-?} | colocated = ${XRAY_EGRESS_COLOCATED:-?}"

  XRAY_EGRESS_STATUS="ok"
  local flagged=0
  [ "${XRAY_EGRESS_PROXY:-0}" = "1" ] && flagged=1
  [ "${XRAY_EGRESS_HOSTING:-0}" = "1" ] && flagged=1
  [ "${XRAY_EGRESS_ASN_HOSTING:-0}" = "1" ] && flagged=1
  [ "${XRAY_EGRESS_DC:-0}" = "1" ] && flagged=1

  if [ "$flagged" = "1" ]; then
    if [ "${XRAY_EGRESS_HOSTING:-0}" != "1" ] && [ "${XRAY_EGRESS_PROXY:-0}" != "1" ] && [ "${XRAY_EGRESS_ASN_HOSTING:-0}" = "1" ]; then
      # ip-api missed it, the ASN heuristic caught it — the v0.5.7 Microsoft case.
      warn "ip-api didn't flag the egress, but its ASN/org is a known hosting provider → treat as datacenter"
      add_verdict "Egress ASN/org is a known hosting provider even though ip-api's hosting flag is clean — its datacenter classification is incomplete. Treat the egress as a datacenter IP: streaming / payment / banking may still challenge it"
    else
      warn "egress flagged as datacenter/proxy — streaming & banking services likely to block it"
      add_verdict "Egress is on datacenter/proxy reputation lists — fine for censorship circumvention, but streaming / payment / banking sites will challenge or block it. For those use cases a residential or clean egress is needed"
    fi
  elif [ "$have_flags" = "1" ] && [ -n "$XRAY_EGRESS_ASN_HOSTING" ]; then
    ok "egress not flagged by ip-api or by the ASN/org heuristic — looks clean (2 sources; still a heuristic, not proof of residential)"
  elif [ "$XRAY_EGRESS_DC" = "0" ]; then
    ok "egress not flagged — ip-api was rate-limited, but the fallback source reports a non-datacenter ASN (cross-checked)"
  else
    XRAY_EGRESS_STATUS="partial"
    warn "egress geo=${XRAY_EGRESS_COUNTRY} — reputation only partially checked (every reputation source was unreachable; flags may be incomplete)"
  fi
}

# Pure classifier for the held-session pulse ladder (probe 17), split out from
# the probe so the transient-vs-volumetric decision is unit-testable without a
# live tunnel. Given the post-retry tallies it echoes one class token:
#   none        no pulses ran
#   ok          every pulse passed
#   slow        some timed out, none reset
#   volumetric  a pulse was reset and NOTHING larger survived → a monotonic byte
#               threshold = volumetric kill-shaping
#   transient   a pulse was reset but a LARGER pulse then succeeded → non-monotonic,
#               so not a byte threshold (a path/size anomaly, not a clean block)
#   reset       a reset fitting neither shape (the tiniest pulse, or none passed)
# Args: total okc killc kill_bytes max_ok_bytes  (the *_bytes args may be empty).
_classify_stability_ladder() {
  local total="${1:-0}" okc="${2:-0}" killc="${3:-0}" kb="${4:-}" maxok="${5:-}"
  [ "$total" -eq 0 ] && { printf 'none\n'; return; }
  if [ "$killc" -gt 0 ]; then
    if [ "$okc" -gt 0 ] && [ -n "$kb" ] && [ "$kb" != "0" ]; then
      if [ -n "$maxok" ] && [ "$maxok" -gt "$kb" ]; then printf 'transient\n'; return; fi
      printf 'volumetric\n'; return
    fi
    printf 'reset\n'; return
  fi
  [ "$okc" -eq "$total" ] && { printf 'ok\n'; return; }
  printf 'slow\n'
}

# Probe 17 — held-session stability (delayed-RST / kill-shaping). Opt-in.
# Holds the probe-12 tunnel and pulses small requests for a while, catching the
# censor tactic of allowing the handshake then RST-ing the proven tunnel
# seconds later — invisible to the short bursts in probes 13/14. Each kill is
# retried once inline (see the loop) so a single RST isn't mistaken for shaping.
probe_xray_stability() {
  if [ "$XRAY_STABILITY" != "1" ]; then
    XRAY_STABILITY_STATUS="disabled"
    return 0
  fi
  if [ "$XRAY_JSON_STATUS" != "ok" ]; then
    XRAY_STABILITY_STATUS="skipped"
    return 0
  fi

  hdr "17. Held-session stability (delayed-RST detection)"

  if ! check_cmd curl; then
    warn "skipping — curl not available"
    XRAY_STABILITY_STATUS="curl-missing"
    return 0
  fi

  # Auto-skip inside --watch / --from-file loops: a ~20s hold every iteration
  # would dominate a monitoring cadence. Force with --stability.
  if [ "${XRAY_STABILITY_FORCE:-0}" != "1" ] \
     && { [ "${_WATCH_CHILD:-0}" = "1" ] || [ "${_BATCH_CHILD:-0}" = "1" ]; }; then
    info "skipped in watch/batch loop (~${XRAY_STABILITY_SECONDS}s hold) — pass --stability to force"
    XRAY_STABILITY_STATUS="skipped-loop"
    return 0
  fi

  local port="$XRAY_JSON_SOCKS_PORT"
  local cap="$XRAY_STABILITY_SECONDS" iv="$XRAY_STABILITY_INTERVAL"
  local total=0 okc=0 killc=0 slowc=0 first_fail="" kill_bytes="" max_ok_bytes="" retried_ok=0
  local rtt rmin="" rmax="" t0 t1 start now size url mt rc state hsz retried_this note sclass
  # Each pulse is a fresh connection → its budget must clear the handshake
  # (≈ probe-12 RTT) plus a download window that grows with the pulse size.
  local hs
  hs=$(( ( ${XRAY_JSON_RTT_MS:-3000} + 999 ) / 1000 ))

  info "pulse ladder: ${XRAY_STABILITY_SIZES} bytes (0 = tiny), ≤${cap}s total"

  start=$(_now_ms)
  for size in $XRAY_STABILITY_SIZES; do
    case "$size" in ''|*[!0-9]*) continue ;; esac
    now=$(_now_ms)
    [ "$(( now - start ))" -ge "$(( cap * 1000 ))" ] && { info "  (time cap reached, stopping ladder)"; break; }
    total=$(( total + 1 ))
    if [ "$size" = "0" ]; then
      url="https://cloudflare.com/cdn-cgi/trace"; mt=$(( hs + 8 ))
    else
      url="https://speed.cloudflare.com/__down?bytes=${size}"; mt=$(( hs + 8 + size / 131072 ))
    fi
    t0=$(_now_ms)
    curl -sS --max-time "$mt" --socks5-hostname "127.0.0.1:$port" -o /dev/null "$url" 2>/dev/null
    rc=$?
    # A single RST is common (a transient blip / server hiccup). Before counting
    # a kill, retry the SAME pulse once — only a reset that REPRODUCES is a real
    # kill. (28 = timeout = slowness, not a reset → not retried.) This auto-
    # confirms in one run what would otherwise need a manual re-run.
    retried_this=0
    if [ "$rc" != "0" ] && [ "$rc" != "28" ]; then
      sleep 1
      t0=$(_now_ms)
      curl -sS --max-time "$mt" --socks5-hostname "127.0.0.1:$port" -o /dev/null "$url" 2>/dev/null
      rc=$?; retried_this=1
      [ "$rc" = "0" ] && retried_ok=$(( retried_ok + 1 ))
    fi
    t1=$(_now_ms); rtt=$(( t1 - t0 ))
    # curl exit codes: 0 ok; 28 timeout (slow, not killed); anything else
    # (18/52/56/35/55/…) = the connection was reset / closed mid-stream = killed.
    case "$rc" in
      0)  state="ok"; okc=$(( okc + 1 ))
          { [ -z "$max_ok_bytes" ] || [ "$size" -gt "$max_ok_bytes" ]; } && max_ok_bytes="$size"
          [ -z "$rmin" ] && rmin="$rtt"; [ "$rtt" -lt "$rmin" ] && rmin="$rtt"
          [ -z "$rmax" ] && rmax="$rtt"; [ "$rtt" -gt "$rmax" ] && rmax="$rtt" ;;
      28) state="slow"; slowc=$(( slowc + 1 )) ;;
      *)  state="killed"; killc=$(( killc + 1 )); [ -z "$kill_bytes" ] && kill_bytes="$size" ;;
    esac
    if [ "$state" != "ok" ] && [ -z "$first_fail" ]; then
      now=$(_now_ms); first_fail=$(( ( now - start ) / 1000 ))
    fi
    if [ "$size" = "0" ]; then hsz="tiny"; elif [ "$size" -ge 1048576 ]; then hsz="$(( size / 1048576 ))MB"; else hsz="$(( size / 1024 ))KB"; fi
    note=""
    if [ "$retried_this" = "1" ]; then
      [ "$state" = "ok" ] && note=" (reset once, recovered on retry)" || note=" (reset reproduced on retry)"
    fi
    info "  $(printf '%-5s' "$hsz") pulse: ${state}$([ "$state" = ok ] && echo " (${rtt} ms)")${note}"
    XRAY_STABILITY_RESULTS="${XRAY_STABILITY_RESULTS}${XRAY_STABILITY_RESULTS:+ }${size}|${state}|$([ "$state" = ok ] && echo "$rtt")"
    sleep "$iv"
  done

  XRAY_STABILITY_TOTAL="$total"
  XRAY_STABILITY_OK="$okc"
  XRAY_STABILITY_KILLED="$killc"
  XRAY_STABILITY_SLOW="$slowc"
  XRAY_STABILITY_KILL_BYTES="$kill_bytes"
  XRAY_STABILITY_FIRST_FAIL_S="$first_fail"
  XRAY_STABILITY_RTT_MIN="$rmin"
  XRAY_STABILITY_RTT_MAX="$rmax"

  local kb_h="" maxok_h=""
  if [ -n "$kill_bytes" ]; then
    if [ "$kill_bytes" = "0" ]; then kb_h="tiny"; elif [ "$kill_bytes" -ge 1048576 ]; then kb_h="$(( kill_bytes / 1048576 ))MB"; else kb_h="$(( kill_bytes / 1024 ))KB"; fi
  fi
  if [ -n "$max_ok_bytes" ]; then
    if [ "$max_ok_bytes" = "0" ]; then maxok_h="tiny"; elif [ "$max_ok_bytes" -ge 1048576 ]; then maxok_h="$(( max_ok_bytes / 1048576 ))MB"; else maxok_h="$(( max_ok_bytes / 1024 ))KB"; fi
  fi

  XRAY_STABILITY_RETRIED="$retried_ok"
  [ "$retried_ok" -gt 0 ] && info "  ${retried_ok} pulse(s) reset once but passed on retry — transient blips, not counted as kills"

  # Pure classification (kills here are already retry-confirmed: a pulse counts
  # as killed only if its inline retry also failed).
  sclass=$(_classify_stability_ladder "$total" "$okc" "$killc" "$kill_bytes" "$max_ok_bytes")
  case "$sclass" in
    none)
      warn "no pulses ran"
      XRAY_STABILITY_STATUS="unstable" ;;
    volumetric)
      fail "tunnel reset at the ${kb_h} pulse (smaller pulses passed, none larger survived; reset reproduced on retry) — volumetric kill-shaping"
      XRAY_STABILITY_STATUS="killed"
      add_verdict "Tunnel survives small flows but is reset once a transfer reaches ~${kb_h} (the reset reproduced on an immediate retry, so it is not a one-off) — volumetric kill-shaping. The censor allows the handshake and trivial traffic, then drops the connection past a byte threshold; trace-only probes never see it. Mitigation: rotate endpoint / cover SNI, add padding, or switch transport" ;;
    transient)
      warn "tunnel reset at the ${kb_h} pulse (reproduced on retry) but a larger ${maxok_h} pulse then succeeded — non-monotonic, inconsistent with a byte threshold; a size/path anomaly rather than active shaping"
      XRAY_STABILITY_STATUS="transient"
      add_verdict "Tunnel reset at ~${kb_h} (reproduced on an immediate retry) yet a larger ${maxok_h} pulse afterwards succeeded — non-monotonic, so this is not a volumetric byte-threshold block. It points to a size/path anomaly or intermittent loss, not active shaping; monitor (probes 13/14 for capacity) before treating it as a block" ;;
    reset)
      fail "tunnel reset mid-session (${killc}/${total} pulses killed, first at ${kb_h:-tiny}; reproduced on retry)"
      XRAY_STABILITY_STATUS="killed"
      add_verdict "Tunnel connection was reset mid-session (not a timeout, and reproduced on an immediate retry) — post-detection kill-shaping / RST injection. Short connection tests miss this; rotate endpoint/cover or change transport" ;;
    ok)
      ok "tunnel stable across all ${total} pulses up to the largest size (RTT ${rmin:-?}-${rmax:-?} ms)"
      XRAY_STABILITY_STATUS="ok" ;;
    *)
      warn "tunnel slow: ${slowc}/${total} pulses timed out (no resets — degraded, not killed)"
      XRAY_STABILITY_STATUS="slow"
      add_verdict "Tunnel is slow — ${slowc}/${total} size-ladder pulses timed out but none were reset, so this is degraded throughput / congestion, not active kill-shaping. See probes 13/14 for capacity" ;;
  esac
}

# Read a single config field by key. For a --xray-config URL, $1 is a query
# key; for --xray-config-json, $1 is the jq path under the first reality
# outbound's settings. Echoes the value (empty if absent). Internal use only —
# values are never printed by the lint probe, only their shape is reported.
_xray_cfg_field() {
  local urlkey="$1" jqpath="$2"
  if [ -n "$XRAY_CONFIG" ]; then
    local q=""
    case "$XRAY_CONFIG" in *\?*) q=${XRAY_CONFIG#*\?}; q=${q%%#*} ;; esac
    _qp "$q" "$urlkey"
    return 0
  fi
  if [ -n "$XRAY_JSON_CONFIG" ] && [ -r "$XRAY_JSON_CONFIG" ] && command -v jq >/dev/null 2>&1; then
    jq -r "$jqpath // empty" "$XRAY_JSON_CONFIG" 2>/dev/null | head -1
  fi
}

# Probe 18 — config pre-flight lint (static, no network). Surfaces common
# Reality/VLESS misconfigs that otherwise masquerade as DPI. Advisory: each
# finding names the protocol knob, never the secret value.
# Classify a VLESS `encryption` field, pure so it's unit-testable. Classic VLESS
# uses encryption=none; Xray (2025+) added a native post-quantum VLESS Encryption
# layer, encryption="mlkem768x25519plus.<method>.<session>[+padding][+delay]" where
# <method> = native (raw/structured) | xorpub (obfuscated pubkey) | random (full
# random, VMess/SS-like). Echoes: none | native | xorpub | random | invalid.
_vless_enc_method() {            # encryption-string
  local e="$1" m
  case "$e" in
    ""|none) echo none ;;
    mlkem768x25519plus*|mlkem768x25519*)
      m="${e#*.}"; m="${m%%.*}"; m="${m%%+*}"
      case "$m" in native|xorpub|random) echo "$m" ;; *) echo native ;; esac ;;
    *) echo invalid ;;
  esac
}

# Resolve a sockopt.dialerProxy chain (JSON-only — a share-link can't express it).
# An outbound whose sockopt.dialerProxy names another outbound is dialed THROUGH
# it; when that target is a LOCAL socks/http proxy it's a client-side desync layer
# (ByeDPI / ciadpi / zapret / GoodbyeDPI) that fragments/disorders the ClientHello.
# Echoes "tag|proto host:port" (host:port of the dialer target), or "" if none;
# "tag|missing" if the referenced tag doesn't exist. Share-safe: only ever a
# loopback endpoint or a tag name.
_dialer_proxy_target() {
  [ -n "$XRAY_JSON_CONFIG" ] && [ -r "$XRAY_JSON_CONFIG" ] && command -v jq >/dev/null 2>&1 || return 0
  jq -r '
    (.outbounds // []) as $o
    | ([ $o[] | select(.streamSettings.sockopt.dialerProxy != null)
         | .streamSettings.sockopt.dialerProxy ] | first) as $t
    | if $t == null then empty
      else ($o | map(select(.tag == $t)) | first) as $d
        | $t + "|" + (if $d == null then "missing"
            else ($d.protocol // "?") + " "
               + (($d.settings.servers[0].address // $d.settings.vnext[0].address // "?"))
               + ":" + (($d.settings.servers[0].port // $d.settings.vnext[0].port // 0)|tostring)
            end)
      end' "$XRAY_JSON_CONFIG" 2>/dev/null | head -1
}

# Is the dialerProxy a LOCAL desync proxy (loopback socks/http)? echoes 1/0.
_dialer_is_local_desync() {
  case "$(_dialer_proxy_target)" in
    *'|'*127.0.0.1*|*'|'*localhost*|*'|'*::1*) echo 1 ;;
    *) echo 0 ;;
  esac
}

# Minimal SOCKS5 CONNECT relay, loopback-only, pure perl (a soft-dep the QUIC/IKE
# probes already use — no install needed). Blocking; run backgrounded. $1 = port.
# Handles ATYP 1 (IPv4) + 3 (domain); rejects IPv6-upstream (ATYP 4) and non-CONNECT.
# It applies NO desync — it is plumbing to complete a dialerProxy chain locally.
_socks5_stub_serve() {
  perl - "$1" <<'PERL' 2>/dev/null
use strict; use warnings; use IO::Socket::INET; use IO::Select;
$SIG{CHLD}='IGNORE'; $SIG{PIPE}='IGNORE';
my $port = $ARGV[0] or exit 1;
my $srv = IO::Socket::INET->new(LocalAddr=>'127.0.0.1', LocalPort=>$port,
          Proto=>'tcp', Listen=>32, ReuseAddr=>1) or exit 1;
sub rd { my ($fh,$n)=@_; my $b=''; while (length($b)<$n){ my $r=sysread($fh,my $c,$n-length($b)); return undef if !defined $r||$r==0; $b.=$c } $b }
sub wr { my ($fh,$d)=@_; my $o=0; while ($o<length($d)){ my $w=syswrite($fh,$d,length($d)-$o,$o); return 0 if !defined $w; $o+=$w } 1 }
my $lsel = IO::Select->new($srv);
while (1) {
  exit 0 if getppid() <= 1;              # script gone (even on SIGKILL) → self-terminate
  next unless $lsel->can_read(5);
  my $c = $srv->accept or next;
  my $pid = fork; next if $pid; close $srv; binmode $c;
  my $g = rd($c,2); exit unless defined $g; my ($v,$nm)=unpack('CC',$g); exit if $v!=5;
  exit unless defined rd($c,$nm); wr($c, pack('CC',5,0));
  my $h = rd($c,4); exit unless defined $h; my ($v2,$cmd,$rsv,$at)=unpack('CCCC',$h); exit if $v2!=5;
  my $host;
  if ($at==1){ my $a=rd($c,4); exit unless defined $a; $host=join('.',unpack('C4',$a)); }
  elsif ($at==3){ my $l=rd($c,1); exit unless defined $l; $host=rd($c,unpack('C',$l)); exit unless defined $host; }
  else { wr($c,pack('CCCCNn',5,8,0,1,0,0)); exit; }
  my $pb=rd($c,2); exit unless defined $pb; my $dp=unpack('n',$pb);
  if ($cmd!=1){ wr($c,pack('CCCCNn',5,7,0,1,0,0)); exit; }
  my $up=IO::Socket::INET->new(PeerAddr=>$host,PeerPort=>$dp,Proto=>'tcp');
  if (!$up){ wr($c,pack('CCCCNn',5,5,0,1,0,0)); exit; }
  binmode $up; wr($c,pack('CCCCNn',5,0,0,1,0,0));
  my $sel=IO::Select->new($c,$up);
  LOOP: while (1) {
    my @r=$sel->can_read(120); last unless @r;
    for my $fh (@r){ my $n=sysread($fh,my $buf,65536); last LOOP if !defined $n||$n==0;
      my $o=($fh==$c)?$up:$c; last LOOP unless wr($o,$buf); }
  }
  close $c; close $up; exit;
}
PERL
}

# --stub-dialer orchestrator: when the config dials through a LOCAL desync
# dialerProxy that isn't running, spawn a throwaway plain socks on its port so the
# tunnel probes can run. Idempotent (uses an existing listener), loopback-only.
# HONEST: plain socks = NO desync → validates carriage + egress/QoE, not efficacy.
_start_stub_dialer() {
  # AUTO mode: without --stub-dialer, still stub a LOCAL desync dialerProxy that has no
  # listener — otherwise every tunnel probe fails and the run reads as "dead endpoint"
  # when the real cause is just that ByeDPI/zapret isn't running here. Every bail-out
  # below is silent in auto mode (a normal config must not gain noise); the loud
  # "THROWAWAY PLAIN socks / NOT desync efficacy" warning still prints when we do stub.
  local _auto=0
  [ "${STUB_DIALER:-}" = "0" ] && return 0   # --no-stub-dialer: never stub, not even in auto
  if [ "${STUB_DIALER:-}" != "1" ]; then
    [ -n "${NO_TUNNEL:-}" ] && return 0
    _auto=1
  fi
  if [ -n "${NO_TUNNEL:-}" ]; then
    info "--stub-dialer ignored with --no-tunnel (there are no tunnel probes to serve)"; return 0
  fi
  local tgt; tgt=$(_dialer_proxy_target)
  if [ -z "$tgt" ]; then
    [ "$_auto" = 1 ] || info "--stub-dialer: this config has no dialerProxy chain — nothing to stub"; return 0
  fi
  if [ "$(_dialer_is_local_desync)" != "1" ]; then
    [ "$_auto" = 1 ] || info "--stub-dialer: the dialerProxy is not a local proxy — not stubbing (a remote hop must be reachable on its own)"; return 0
  fi
  local port; port=$(printf '%s' "$tgt" | sed -E 's/.*:([0-9]+)$/\1/')
  case "$port" in ''|*[!0-9]*) [ "$_auto" = 1 ] || info "--stub-dialer: could not read the dialerProxy port — skipping"; return 0 ;; esac
  if nc -z 127.0.0.1 "$port" 2>/dev/null; then
    [ "$_auto" = 1 ] || info "--stub-dialer: 127.0.0.1:$port already has a listener (real desync proxy or a prior stub) — using it, not stubbing"; return 0
  fi
  if ! check_cmd perl; then
    [ "$_auto" = 1 ] || warn "--stub-dialer needs perl (absent) — start a socks on 127.0.0.1:$port yourself (e.g. microsocks -p $port)"; return 0
  fi
  [ "$_auto" = 1 ] && info "auto-stubbing the dialerProxy chain: a local desync proxy is configured on 127.0.0.1:$port but nothing is listening — without this every tunnel probe would fail and look like a dead endpoint (suppress with --no-stub-dialer)"
  _socks5_stub_serve "$port" & _STUB_PID=$!
  local i=0 up=0
  while [ "$i" -lt 20 ]; do
    nc -z 127.0.0.1 "$port" 2>/dev/null && { up=1; break; }
    sleep 0.1; i=$(( i + 1 ))
  done
  if [ "$up" != "1" ]; then
    warn "--stub-dialer: stub socks failed to bind 127.0.0.1:$port — tunnel probes will fail on the chain"
    kill "$_STUB_PID" 2>/dev/null; _STUB_PID=""; return 0
  fi
  warn "--stub-dialer: serving the dialerProxy chain with a THROWAWAY PLAIN socks on 127.0.0.1:$port (NO desync). This validates the config's CARRIAGE + egress/QoE, NOT desync efficacy — desync only bites a live DPI, so test that from an in-region vantage"
}

# Config-validity detectors ($1 = json file). Cheap structural bugs that stop xray
# from LOADING at all — otherwise they surface only as a cryptic probe-12 failure.
# _dup_outbound_tags echoes duplicated outbound tags (xray requires unique tags —
# routing resolves only the first, the rest never run). _string_ports_present echoes
# "1" if any outbound endpoint port is a JSON string (xray needs a uint16 integer).
_dup_outbound_tags() {
  jq -r '[.outbounds[]?.tag // empty] | group_by(.) | map(select(length>1) | .[0]) | .[]' "$1" 2>/dev/null
}
_string_ports_present() {
  jq -r '[ .outbounds[]? | .settings? | (.vnext[]?, .servers[]?) | .port? ]
         | map(select(type=="string")) | if length>0 then "1" else empty end' "$1" 2>/dev/null
}

# GFW fully-encrypted-traffic (FET) exposure decision — pure/unit-testable. Echoes
# 1 (random from byte 0, no TLS/HTTP framing → GFW entropy block, USENIX'23), 0
# (has a recognizable shape), or "" (protocol not evaluated). Args: proto sec net
# vless_enc (from _vless_enc_method). See the caller for the full rationale.
_fet_exposed() {
  local proto="$1" sec="$2" net="$3" venc="${4:-}"
  case "$proto" in
    ss|shadowsocks) echo 1 ;;                          # fully-encrypted, no framing
    vmess|vless|trojan)
      case "$sec" in
        ""|none)
          case "$net" in
            tcp|raw)
              case "$venc" in                          # VLESS Encryption method matters
                random)        echo 1 ;;               # full-random (VMess/SS-like) → exposed
                native|xorpub) echo 0 ;;               # reshapes the wire → don't assert a block
                *)             echo 1 ;;               # classic security=none, no VLESS Enc
              esac ;;
            *) echo 0 ;;                               # ws/httpupgrade/grpc/xhttp carry HTTP framing
          esac ;;
        *) echo 0 ;;                                   # tls/reality → TLS exemption
      esac ;;
    *) echo ;;                                         # other protocol → not evaluated ("")
  esac
}

probe_xray_lint() {
  if [ -z "$XRAY_CONFIG" ] && [ -z "$XRAY_JSON_CONFIG" ]; then
    XRAY_LINT_STATUS="skipped"
    return 0
  fi

  hdr "18. Config pre-flight (lint)"

  local sec net flow pbk sid sni enc fp insec findings=""
  if [ -n "$XRAY_CONFIG" ]; then
    local q=""
    case "$XRAY_CONFIG" in *\?*) q=${XRAY_CONFIG#*\?}; q=${q%%#*} ;; esac
    sec=$(_qp "$q" security); net=$(_qp "$q" type); flow=$(_qp "$q" flow)
    pbk=$(_qp "$q" pbk); sid=$(_qp "$q" sid); sni=$(_qp "$q" sni)
    enc=$(_qp "$q" encryption); fp=$(_qp "$q" fp)
    insec=$(_qp "$q" allowInsecure); [ -z "$insec" ] && insec=$(_qp "$q" insecure)
    [ -z "$net" ] && net=tcp
  else
    sec=$(_xray_cfg_field security '.outbounds[0].streamSettings.security')
    net=$(_xray_cfg_field type     '.outbounds[0].streamSettings.network')
    flow=$(_xray_cfg_field flow    '.outbounds[0].settings.vnext[0].users[0].flow')
    pbk=$(_xray_cfg_field pbk      '.outbounds[0].streamSettings.realitySettings.publicKey')
    sid=$(_xray_cfg_field sid      '.outbounds[0].streamSettings.realitySettings.shortId')
    sni=$(_xray_cfg_field sni      '.outbounds[0].streamSettings.realitySettings.serverName')
    enc=$(_xray_cfg_field encryption '.outbounds[0].settings.vnext[0].users[0].encryption')
    fp=$(_xray_cfg_field fp        '.outbounds[0].streamSettings.realitySettings.fingerprint')
    insec=$(_xray_cfg_field allowInsecure '.outbounds[0].streamSettings.tlsSettings.allowInsecure')
    [ -z "$net" ] && net=tcp
  fi
  case "$insec" in 1|true|TRUE|True) insec=1 ;; *) insec="" ;; esac

  # Join findings with a real newline (JSON emit splits on "\n").
  _lint_add() {
    warn "$1"
    if [ -n "$findings" ]; then
      findings="$findings
$1"
    else
      findings="$1"
    fi
  }

  # --- config validity: structural bugs that stop xray from LOADING ---
  # Cheap static checks for the common errors that otherwise surface only as a
  # cryptic probe-12 tunnel failure: duplicate outbound tags + string ports. This is
  # the high-confidence, zero-false-positive subset (a full validator is `xray -test`,
  # which also rejects placeholder keys — not run here to keep the check FP-free).
  # config_valid: 0 = a structural bug found; "" (null) = none of these (NOT a full
  # validity guarantee). JSON-only.
  if [ -n "$XRAY_JSON_CONFIG" ] && [ -r "$XRAY_JSON_CONFIG" ] && command -v jq >/dev/null 2>&1; then
    local _dup _strport
    _dup=$(_dup_outbound_tags "$XRAY_JSON_CONFIG")
    _strport=$(_string_ports_present "$XRAY_JSON_CONFIG")
    if [ -n "$_dup" ]; then
      XRAY_CONFIG_VALID=0
      _lint_add "duplicate outbound tag(s): $(printf '%s' "$_dup" | tr '\n' ' ') — xray requires unique outbound tags; routing resolves only the first, the rest never run"
    fi
    if [ "$_strport" = "1" ]; then
      XRAY_CONFIG_VALID=0
      _lint_add "an outbound 'port' is a JSON string — xray needs an integer (e.g. 443, not \"443\"); the config will not load"
    fi
    if [ "$XRAY_CONFIG_VALID" = "0" ]; then
      add_verdict "Config will NOT load in xray-core as written — fix the structural error(s) above before any network diagnosis (otherwise it surfaces only as a cryptic tunnel failure). Full validation: xray -test -config <file>"
    fi
  fi

  # VLESS Encryption (Xray 2025+): a NATIVE post-quantum crypto layer (ML-KEM-768 +
  # X25519), encryption="mlkem768x25519plus.<native|xorpub|random>.<session>[+pad]".
  # Recognize it (classic VLESS is encryption=none), record method + padding — both
  # feed the FET check and probe 26's vision logic — and DON'T false-error on it.
  local _isv=0
  case "$XRAY_CONFIG" in vless://*) _isv=1 ;; esac
  [ "$_isv" = 0 ] && [ -n "$XRAY_JSON_CONFIG" ] && [ "$(_xray_cfg_field protocol '.outbounds[0].protocol')" = "vless" ] && _isv=1
  if [ "$_isv" = 1 ]; then
    XRAY_VLESS_ENC=$(_vless_enc_method "$enc")
    case "$enc" in *+*) XRAY_VLESS_ENC_PADDING=1 ;; *) XRAY_VLESS_ENC_PADDING=0 ;; esac
    case "$XRAY_VLESS_ENC" in
      none) : ;;
      invalid) _lint_add "vless encryption='$enc' is neither 'none' nor a recognized VLESS Encryption string (mlkem768x25519plus.<native|xorpub|random>…) — likely a typo" ;;
      *)
        info "VLESS Encryption enabled — post-quantum ML-KEM-768 + X25519, method=${XRAY_VLESS_ENC}$( [ "$XRAY_VLESS_ENC_PADDING" = 1 ] && printf ' + traffic padding' || printf ', no padding blocks' ) (a native crypto layer, independent of TLS/Reality)"
        [ "$XRAY_VLESS_ENC_PADDING" = 0 ] && info "VLESS Encryption has no padding/delay blocks — padding blunts packet-length/timing (flow-shape) analysis; worth adding for the RU/CN frontier"
        ;;
    esac
  fi

  # flow=vision requires raw TCP transport ("raw" = current name for "tcp") — UNLESS
  # VLESS Encryption is configured, which lifts the transport restriction (vision
  # then runs on any transport: the VLESSENC + XHTTP + vision frontier config).
  if [ -n "$flow" ] && { [ "$net" != "tcp" ] && [ "$net" != "raw" ]; } \
     && { [ -z "$XRAY_VLESS_ENC" ] || [ "$XRAY_VLESS_ENC" = "none" ] || [ "$XRAY_VLESS_ENC" = "invalid" ]; }; then
    _lint_add "flow=$flow requires raw TCP transport (network=tcp/raw), but network=$net and no VLESS Encryption — the handshake will fail (VLESS Encryption would lift this restriction)"
  fi

  # httpupgrade transport (HTTP/1.1 Upgrade → a WebSocket-shaped tunnel without the
  # full ws handshake). It's the CDN-frontable transport of choice behind a public
  # balancer (the ByeDPI/Cloudflare pattern), so name it explicitly instead of letting
  # it fall through the generic branches: check the settings a CDN actually needs, and
  # say plainly that vision can't apply here (it needs raw TCP).
  if [ "$net" = "httpupgrade" ]; then
    local _hu_path _hu_host
    _hu_path=$(_xray_cfg_field type '.outbounds[0].streamSettings.httpupgradeSettings.path')
    _hu_host=$(_xray_cfg_field type '.outbounds[0].streamSettings.httpupgradeSettings.host')
    [ -z "$_hu_path" ] && _lint_add "network=httpupgrade but httpupgradeSettings.path is empty — the server routes the Upgrade by path; an empty/wrong path answers 404 and the tunnel never establishes"
    [ -z "$_hu_host" ] && info "httpupgrade: no httpupgradeSettings.host — the Host header falls back to the TLS serverName; set it explicitly when the CDN routes by Host"
    info "transport httpupgrade — CDN-frontable (HTTP/1.1 Upgrade behind a public balancer); carries HTTP framing, so the FET entropy classifier does not apply. XTLS vision cannot be used on this transport (it requires raw TCP) — cover-SNI quality and ECH are the levers here"
  fi

  # ALPN vs transport / cover. The declared alpn is parsed from the URL (or tls/reality
  # settings) but was never checked against what it has to be compatible with:
  #   - ws / httpupgrade ride an HTTP/1.1 `Upgrade`; over HTTP/2 that needs Extended
  #     CONNECT (RFC 8441), which many stacks and CDNs do not do → pinning h2 breaks it.
  #   - on REALITY the handshake is relayed to the cover, so an alpn the cover would
  #     never choose manufactures the probe-24 parity divergence yourself.
  local _alpn
  _alpn=$(_xray_cfg_field alpn '(.outbounds[0].streamSettings.tlsSettings.alpn // .outbounds[0].streamSettings.realitySettings.alpn | if type=="array" then join(",") else . end)')
  if [ -n "$_alpn" ]; then
    case "$_alpn" in
      *h2*)
        case "$net" in
          ws|httpupgrade)
            _lint_add "alpn declares h2 but network=$net rides an HTTP/1.1 Upgrade — over HTTP/2 that requires Extended CONNECT (RFC 8441), which many servers/CDNs do not implement; the tunnel may fail to establish. Drop h2 from alpn (or use http/1.1) for this transport" ;;
        esac ;;
    esac
    [ "$sec" = "reality" ] && info "alpn is pinned to '${_alpn}' on a REALITY config — the handshake is relayed to the cover, so this must be an ALPN that cover actually negotiates, or probe 24 will read as a parity mismatch. Leaving alpn unset lets the relay decide (what a real client of that cover does)"
  fi

  # VLESS without a flow is deprecated upstream (Xray-core is migrating to
  # VLESS-with-flow; XTLS/Xray-core discussion #5568). A forward-looking warning,
  # not a misconfig — so it's a plain warn (visible), not a _lint_add (which frames
  # findings as likely typos). The probe-26 vision +15 already drives the actionable
  # fix on a REALITY+raw config; this catches the CDN/non-raw configs too.
  if [ "$_isv" = 1 ] && [ -z "$flow" ]; then
    XRAY_VLESS_FLOW_DEPRECATED=1
    warn "VLESS without flow= is deprecated upstream (Xray is migrating to VLESS-with-flow; #5568) — plan flow=xtls-rprx-vision (raw TCP) or VLESS Encryption + flow (CDN transport)"
  elif [ "$_isv" = 1 ]; then
    XRAY_VLESS_FLOW_DEPRECATED=0
  fi

  # dialerProxy chain (client-side desync layer: ByeDPI / ciadpi / zapret /
  # GoodbyeDPI). The proxy outbound dials THROUGH another outbound, so the whole
  # tunnel TCP+TLS goes through it and it can fragment/disorder the ClientHello to
  # defeat SNI/TLS DPI. This changes how two things read — a tunnel failure (the
  # dialer must be running) and the cleartext SNI (the dialer may already hide it)
  # — so probe 12 and probe 27 consume XRAY_DESYNC_CHAIN. JSON-only feature.
  local _dp _dp_tag _dp_dst
  _dp=$(_dialer_proxy_target)
  if [ -n "$_dp" ]; then
    _dp_tag=${_dp%%|*}; _dp_dst=${_dp#*|}
    XRAY_DIALER_PROXY="$_dp_tag"
    if [ "$_dp_dst" = "missing" ]; then
      XRAY_DESYNC_CHAIN=0
      _lint_add "sockopt.dialerProxy='$_dp_tag' references no outbound with that tag — the chain is broken (add the '$_dp_tag' outbound or fix the tag)"
    elif [ "$(_dialer_is_local_desync)" = "1" ]; then
      XRAY_DESYNC_CHAIN=1
      info "dialerProxy chain: the tunnel dials through '$_dp_tag' → a LOCAL proxy ($_dp_dst) — a client-side desync layer (ByeDPI / ciadpi / zapret / GoodbyeDPI). The whole tunnel TCP+TLS is dialed through it, so it can fragment/disorder the ClientHello to defeat SNI/TLS DPI. Two consequences: (1) that proxy must be RUNNING locally or the tunnel fails — a 'dead endpoint' reading can actually be the chain; (2) its desync strength (split/disorder/fake/ttl) lives in that process, not this config — verify it there"
    else
      XRAY_DESYNC_CHAIN=1
      info "dialerProxy chain: the tunnel dials through '$_dp_tag' → $_dp_dst (a chained outbound — the connection is proxied through it before reaching the endpoint)"
    fi
    # tcpKeepAliveInterval (benign; the user asked) — a keepalive on the dialed socket.
    local _ka
    _ka=$(jq -r '[.outbounds[]?.streamSettings.sockopt.tcpKeepAliveInterval // empty] | first // empty' "$XRAY_JSON_CONFIG" 2>/dev/null)
    [ -n "$_ka" ] && info "sockopt tcpKeepAliveInterval=${_ka}s — TCP keepalive on the dialed socket (keeps the fronted connection warm; benign, a minor traffic-timing signal at most)"
  fi
  if [ "$sec" = "reality" ]; then
    [ -z "$pbk" ] && _lint_add "security=reality but publicKey (pbk) is missing"
    if [ -n "$sid" ]; then
      case "$sid" in
        *[!0-9a-fA-F]*) _lint_add "shortId (sid) is not valid hex" ;;
        *) [ "${#sid}" -gt 16 ] && _lint_add "shortId (sid) is longer than 16 hex chars (max 8 bytes)" ;;
      esac
    fi
    if [ -z "$sni" ]; then
      _lint_add "security=reality but serverName (sni) is empty"
    else
      case "$sni" in
        *[!0-9.]*) : ;;  # has non-numeric/non-dot → a hostname, good
        *) _lint_add "serverName (sni) looks like a bare IP — Reality cover must be a domain" ;;
      esac
    fi
    [ -z "$fp" ] && _lint_add "no uTLS fingerprint (fp) set — a real-browser fp is recommended for Reality"
  fi
  # (VLESS encryption handled above — classic 'none' vs the new VLESS Encryption
  # layer; a modern encryption=mlkem768x25519plus.* is valid, not an error.)
  # allowInsecure / insecure=true — a static red flag that needs no network, so
  # it fires even against an unreachable node: the client accepts ANY server
  # cert, which (a) masks a cover cert that won't validate for the SNI — itself
  # a strong active-probe fingerprint — and (b) is MITM-able. Reality needs no
  # client-side cert at all; if you must use plain TLS, use a real domain whose
  # cert is genuinely valid so allowInsecure can be dropped.
  if [ "$insec" = "1" ]; then
    _lint_add "allowInsecure=true — client skips cert validation; it's masking an invalid/self-signed cert (a strong active-probe tell) and is MITM-able. Use a real valid-cert domain, or Reality (no client cert needed)"
  fi

  # --- GFW fully-encrypted-traffic (FET) exposure (gfw.report, USENIX'23) ---
  # Since 2021 the GFW EXEMPTS traffic that looks like a known protocol — a TLS
  # record header ([\x16-\x17]\x03[\x00-\x09]), an HTTP verb, or mostly-printable
  # bytes — and BLOCKS the rest by an entropy test (set bits/byte ~3.4-4.6 = looks
  # random/encrypted). A proxy with NO TLS/HTTP framing (Shadowsocks, or
  # VMess/VLESS over RAW TCP with security=none) is random from byte 0, matches no
  # exemption, and is blocked. TLS/Reality match the TLS exemption; ws/grpc/xhttp
  # carry plaintext HTTP framing; UDP transports (mKCP/QUIC) aren't covered by
  # this TCP classifier. Purely static — read protocol + security + transport.
  local proto fet=""
  if [ -n "$XRAY_CONFIG" ]; then proto=${XRAY_CONFIG%%://*}
  else proto=$(_xray_cfg_field protocol '.outbounds[0].protocol'); fi
  proto=$(printf '%s' "$proto" | tr '[:upper:]' '[:lower:]')
  # Classic security=none + raw TCP is random from byte 0 → exposed. VLESS Encryption
  # changes it by method: 'random' is STILL full-random (exposed); 'native'/'xorpub'
  # reshape the wire so their FET-resistance is method-dependent — report, don't
  # over-claim. Decision extracted to the pure _fet_exposed (unit-tested).
  fet=$(_fet_exposed "$proto" "$sec" "$net" "$XRAY_VLESS_ENC")
  XRAY_FET_EXPOSED="$fet"
  if [ "$fet" = "1" ]; then
    case "$proto" in
      ss|shadowsocks) warn "GFW fully-encrypted-traffic exposure: Shadowsocks has no TLS/HTTP framing → random from byte 0, so the GFW entropy classifier (USENIX'23) blocks it unless a plugin/SS-2022 prefix breaks the popcount band" ;;
      vless)
        if [ "$XRAY_VLESS_ENC" = "random" ]; then
          warn "GFW fully-encrypted-traffic exposure: VLESS Encryption method='random' emits full-random bytes (VMess/SS-like) with no TLS/HTTP framing on raw TCP → the GFW entropy classifier (USENIX'23) blocks it. Use method 'native'/'xorpub', or wrap in TLS/REALITY"
        else
          warn "GFW fully-encrypted-traffic exposure: vless+raw-TCP with security=none has no TLS/HTTP framing → the GFW entropy classifier (USENIX'23) blocks fully-random traffic"
        fi ;;
      *)              warn "GFW fully-encrypted-traffic exposure: ${proto}+raw-TCP with security=none has no TLS/HTTP framing → the GFW entropy classifier (USENIX'23) blocks fully-random traffic" ;;
    esac
    add_verdict "GFW fully-encrypted-traffic (FET) exposure: this transport sends fully-encrypted bytes with no TLS record header or HTTP framing, so it is random from the first byte. Since 2021 the GFW exempts traffic that looks like a known protocol (TLS / HTTP / mostly-printable) and BLOCKS the rest via an entropy test (set bits per byte ~3.4-4.6). Give it a recognizable shape: wrap in TLS or switch to REALITY (matches the TLS exemption), use a transport with plaintext HTTP framing (ws / xhttp), or for Shadowsocks add an obfs/TLS plugin or a printable prefix + padding. UDP transports (mKCP/QUIC) are not covered by this TCP classifier"
  fi

  # QUIC-SNI exposure (advisory): a QUIC-based transport/protocol. Xray-form here
  # (URL scheme hysteria2/tuic, or network=quic); sing-box configs are covered in
  # the non-Xray branch since lint skips them.
  case "$proto" in
    hysteria2|hy2|tuic) _quic_sni_note ;;
    *) [ "$net" = "quic" ] && _quic_sni_note ;;
  esac

  # --- client id format (share-safe: format + length only, NEVER the value) ---
  # VLESS/VMess hash a non-UUID id to a derived UUID, so a hand-assigned string
  # works — but it's unusual, can indicate a typo/truncated UUID (which still
  # passes `xray -test` yet fails auth against a UUID server), and a short/shared
  # id is a fleet-credential signal. We only report whether it's a canonical UUID
  # and its length — never the id itself (it's a secret).
  local cfg_id=""
  if [ -n "$XRAY_JSON_CONFIG" ] && command -v jq >/dev/null 2>&1; then
    cfg_id=$(jq -r '(.outbounds[0].settings.vnext[0].users[0].id) // empty' "$XRAY_JSON_CONFIG" 2>/dev/null | head -1)
  elif [ -n "$XRAY_CONFIG" ]; then
    case "$XRAY_CONFIG" in vless://*) cfg_id=${XRAY_CONFIG#vless://}; cfg_id=${cfg_id%%@*} ;; esac
  fi
  if [ -n "$cfg_id" ]; then
    if printf '%s' "$cfg_id" | grep -qiE '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'; then
      XRAY_ID_UUID=1
    else
      XRAY_ID_UUID=0
      info "client id is not a canonical UUID (${#cfg_id}-char string) — VLESS/VMess hash it to a derived UUID so it still works, but it's unusual (a typo/truncated UUID also passes 'xray -test' yet fails auth, and a short/shared id is a fleet-credential tell); confirm it matches the server's user id exactly"
    fi
  fi

  # Server-side VLESS fallbacks (active-probe defense): an inbound that relays
  # unauthenticated clients to a real site. Informational — a good sign when
  # present; only meaningful on a server/inbound config (client configs lack it).
  if [ -n "$XRAY_JSON_CONFIG" ] && command -v jq >/dev/null 2>&1; then
    if jq -e '[.inbounds[]? | select((.settings.fallbacks // []) | length > 0)] | length > 0' "$XRAY_JSON_CONFIG" >/dev/null 2>&1; then
      info "server-side VLESS fallbacks present — unauthenticated clients are relayed to a real site (active-probe defense)"
    fi
  fi

  XRAY_LINT_FINDINGS="$findings"
  if [ -z "$findings" ]; then
    ok "config shape sane — no obvious Reality/VLESS misconfig"
    XRAY_LINT_STATUS="ok"
  else
    XRAY_LINT_STATUS="warn"
    add_verdict "Config pre-flight found a likely misconfiguration (see probe 18) — fix it before blaming the network; these typos commonly masquerade as DPI/handshake failures"
  fi
}

# Convert an HTTP Date header value to epoch seconds (GNU and BSD date).
_epoch_from_httpdate() {
  local s="$1"
  # The HTTP Date header is always RFC-7231 English ("Wed, 10 Jun 2026 …"), so
  # force LC_ALL=C — otherwise %a/%b are matched against the machine's LC_TIME
  # month/day names and a non-English locale (e.g. ru_RU on the operator's mac)
  # fails to parse it, leaving the clock-skew probe blind ("could not parse").
  if date -d "now" >/dev/null 2>&1; then
    LC_ALL=C date -d "$s" +%s 2>/dev/null
  else
    LC_ALL=C TZ=UTC date -j -f "%a, %d %b %Y %H:%M:%S GMT" "$s" +%s 2>/dev/null
  fi
}

# Probe 19 — clock skew. Reality authentication is time-windowed, so a client
# clock off by minutes fails the handshake exactly like a fingerprint block.
probe_clock_skew() {
  if [ -z "$XRAY_CONFIG" ] && [ -z "$XRAY_JSON_CONFIG" ]; then
    XRAY_CLOCK_STATUS="skipped"
    return 0
  fi

  hdr "19. Clock skew (Reality auth is time-windowed)"

  if ! check_cmd curl; then
    warn "skipping — curl not available"
    XRAY_CLOCK_STATUS="unknown"
    return 0
  fi

  local hdrs server_date server_epoch local_epoch skew host
  for host in "$BASELINE_DOMAIN" cloudflare.com www.google.com; do
    hdrs=$(curl -sSI --max-time "$TIMEOUT" "https://$host/" 2>/dev/null)
    server_date=$(printf '%s' "$hdrs" | grep -i '^date:' | head -1 | sed -E 's/^[Dd]ate:[[:space:]]*//' | tr -d '\r')
    [ -n "$server_date" ] && break
  done

  if [ -z "$server_date" ]; then
    warn "could not fetch a reference time (no HTTPS Date header reachable)"
    XRAY_CLOCK_STATUS="unknown"
    return 0
  fi

  server_epoch=$(_epoch_from_httpdate "$server_date")
  local_epoch=$(date +%s)
  case "$server_epoch" in
    ''|*[!0-9]*) warn "could not parse reference time"; XRAY_CLOCK_STATUS="unknown"; return 0 ;;
  esac

  skew=$(( local_epoch - server_epoch ))
  XRAY_CLOCK_SKEW_S="$skew"
  local abs="$skew"; [ "$abs" -lt 0 ] && abs=$(( -abs ))

  if [ "$abs" -le 60 ]; then
    ok "clock within ${abs}s of network time — fine for Reality"
    XRAY_CLOCK_STATUS="ok"
  else
    fail "local clock is ${skew}s off network time"
    XRAY_CLOCK_STATUS="skew"
    add_verdict "Local clock is ${skew}s off real time — Reality auth is time-windowed and will reject handshakes at this skew, which looks identical to a fingerprint block. Sync the clock (NTP) before diagnosing further"
  fi
}

# Probe 20 — active-probe resistance. Probe 15 checks the cover cert; this
# checks the cover BEHAVIOUR the way a censor does: make a real HTTPS request
# to the server using the cover SNI and compare the response to the genuine
# cover site. A real Reality server relays unauth clients to dest → matching
# response; a fake one errors / mismatches. Output: match boolean + codes.
probe_xray_active_probe() {
  local sni
  sni=$(_xray_cover_sni)
  if [ -z "$sni" ]; then
    XRAY_ACTIVE_STATUS="skipped"
    return 0
  fi

  hdr "20. Active-probe resistance (cover behaviour)"
  info "unauthenticated HTTP probe (what an active prober sends)"

  if ! check_cmd curl; then
    warn "skipping — curl not available"
    XRAY_ACTIVE_STATUS="curl-missing"
    return 0
  fi

  # Genuine cover response, out-of-band (the real site).
  XRAY_ACTIVE_REAL_CODE=$(curl -sS --max-time "$TIMEOUT" -o /dev/null \
    -w '%{http_code}' "https://$sni/" 2>/dev/null)
  case "$XRAY_ACTIVE_REAL_CODE" in
    ''|000) warn "genuine cover site unreachable from here — cannot baseline"; XRAY_ACTIVE_STATUS="no-baseline"; return 0 ;;
  esac

  # Same request, but forced to the VPN server IP:PORT with the cover SNI/Host.
  # MUST use the server's actual Reality port (VPN_PORT_TCP), not 443 — a server
  # on a non-standard port (e.g. 56443) isn't listening on 443, so probing 443
  # would falsely read "no coherent HTTP" and over-score the active-probe tell.
  # (Probes 15/24 already connect on VPN_PORT_TCP; this aligns probe 20 with them.)
  # The genuine-cover baseline above stays on the cover's real :443.
  # -k because a (broken) server may present a self-signed cert; we care about
  # whether a coherent HTTP response comes back, not cert validity here.
  XRAY_ACTIVE_RELAY_CODE=$(curl -sS -k --max-time "$TIMEOUT" -o /dev/null \
    --resolve "$sni:${VPN_PORT_TCP:-443}:$VPN_HOST" \
    -w '%{http_code}' "https://$sni:${VPN_PORT_TCP:-443}/" 2>/dev/null)
  [ -z "$XRAY_ACTIVE_RELAY_CODE" ] && XRAY_ACTIVE_RELAY_CODE=000

  info "cover behaviour: relay-code=${XRAY_ACTIVE_RELAY_CODE}, genuine-code=${XRAY_ACTIVE_REAL_CODE}"

  if [ "$XRAY_ACTIVE_RELAY_CODE" = "$XRAY_ACTIVE_REAL_CODE" ]; then
    XRAY_ACTIVE_MATCH=1
    ok "server relays unauth probes to the genuine cover (responses match) → active-probe resistant"
    XRAY_ACTIVE_STATUS="ok"
  elif [ "$XRAY_ACTIVE_RELAY_CODE" = "000" ]; then
    XRAY_ACTIVE_MATCH=0
    fail "server returns no coherent HTTP to an unauth prober → not relaying to the cover"
    XRAY_ACTIVE_STATUS="exposed"
    add_verdict "Server fails active probing — an unauthenticated HTTPS request does not get relayed to the genuine cover site (no coherent response), so it does not behave like the site it impersonates. Combined with the cover-cert check (probe 15) this is a strong VPN fingerprint. Fix the Reality 'dest'/'serverNames' so unauth clients are proxied to the real cover"
  else
    XRAY_ACTIVE_MATCH=0
    warn "server's unauth response differs from the genuine cover (relay=${XRAY_ACTIVE_RELAY_CODE} vs ${XRAY_ACTIVE_REAL_CODE})"
    XRAY_ACTIVE_STATUS="mismatch"
    add_verdict "Server's response to an unauthenticated prober differs from the genuine cover site — partial mimicry that a determined active prober can distinguish. Verify Reality 'dest' points at the exact cover host the client's serverName expects"
  fi
}

# Tunnel-test one synthesized single-outbound config: launch xray, probe
# cloudflare trace through its socks inbound, echo "ok|<rtt_ms>" or "fail".
# Self-contained lifecycle (own pid + tempfiles) so the fleet loop can repeat.
_fleet_test_one() {
  local cfg_src="$1" tag="$2" socks_port pid log base patched rc trace rtt t0 t1 ready i
  socks_port=$(_find_free_port) || { printf 'fail'; return 0; }
  # xray-core picks its parser by extension, so the patched config needs .json.
  base=$(mktemp -t detect_blocking.fleet.XXXXXX) || { printf 'fail'; return 0; }
  patched="${base}.json"
  if ! mv "$base" "$patched" 2>/dev/null; then rm -f "$base"; printf 'fail'; return 0; fi
  if ! jq --arg t "$tag" --argjson p "$socks_port" '
        .inbounds = [{ tag:"socks", listen:"127.0.0.1", port:$p, protocol:"socks", settings:{auth:"noauth", udp:true} }]
        | .outbounds as $all
        | (reduce range(0;6) as $_ ([$t]; . as $have
             | ($have + [ $all[] | select(.tag as $x | ($have | index($x)))
                          | (.streamSettings.sockopt.dialerProxy // empty), (.proxySettings.tag // empty) ] | unique))) as $keep
        | .outbounds = ([ $all[] | select(.tag == $t) ]
            + [ $all[] | select((.tag != $t) and (.tag as $x | ($keep | index($x)))) ]
            + [ {protocol:"freedom", tag:"direct"} ])
        | del(.routing) | del(.observatory)
      ' "$cfg_src" > "$patched" 2>/dev/null; then
    rm -f "$patched"; printf 'fail'; return 0
  fi
  log=$(mktemp -t detect_blocking.fleetlog.XXXXXX)
  xray run -c "$patched" >"$log" 2>&1 &
  pid=$!
  ready=0
  for i in $(seq 1 $(( TIMEOUT * 5 + 10 ))); do
    nc -z 127.0.0.1 "$socks_port" 2>/dev/null && { ready=1; break; }
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.2
  done
  if [ "$ready" -eq 1 ]; then
    t0=$(_now_ms)
    trace=$(curl -sS --max-time "$(( ( ${XRAY_JSON_RTT_MS:-3000} + 999 ) / 1000 + TIMEOUT ))" \
            --socks5-hostname "127.0.0.1:$socks_port" \
            https://cloudflare.com/cdn-cgi/trace 2>/dev/null)
    t1=$(_now_ms); rtt=$(( t1 - t0 ))
    if printf '%s' "$trace" | grep -q '^h=cloudflare\.com'; then
      rc="ok|$rtt"
    else
      rc="fail"
    fi
  else
    rc="fail"
  fi
  kill "$pid" 2>/dev/null; for i in 1 2 3; do kill -0 "$pid" 2>/dev/null || break; sleep 0.2; done; kill -9 "$pid" 2>/dev/null
  rm -f "$patched" "$log" 2>/dev/null
  printf '%s' "$rc"
}

# Probe 21 — per-outbound fleet health matrix (opt-in --fleet). For a
# multi-outbound JSON config, tunnel-test each proxy outbound and print a
# health table keyed by the operator-defined tag (never address/port).
# Endpoint tags for the fleet matrix: proxy outbounds (vnext/servers) EXCLUDING
# dialerProxy / proxySettings HELPERS (e.g. a local ByeDPI socks) — those are chain
# plumbing, not fleet endpoints. Counting them inflates the fleet AND mislabels the
# real endpoint as "down" (isolating it drops the dangling dialer). $1 = json path.
_fleet_tags() {
  jq -r '
    (.outbounds // []) as $o
    | [ $o[] | (.streamSettings.sockopt.dialerProxy // empty), (.proxySettings.tag // empty) ] as $helpers
    | $o
    | map(select((.settings.vnext != null or .settings.servers != null)
                 and ((.tag // "") as $t | ($helpers | index($t)) | not)))
    | .[].tag // empty' "$1" 2>/dev/null
}

probe_xray_fleet() {
  if [ "$XRAY_FLEET" = "0" ]; then
    XRAY_FLEET_STATUS="disabled"
    return 0
  fi
  # Auto-detect: only multi-outbound JSON configs are worth fanning out. URL
  # form / single-outbound / no-jq → stay silent (no header, no work).
  if [ -z "$XRAY_JSON_CONFIG" ] || [ ! -r "$XRAY_JSON_CONFIG" ]; then
    XRAY_FLEET_STATUS="skipped"
    return 0
  fi
  if ! command -v jq >/dev/null 2>&1; then
    XRAY_FLEET_STATUS="jq-missing"
    return 0
  fi

  local tags count
  tags=$(_fleet_tags "$XRAY_JSON_CONFIG")
  count=$(printf '%s\n' "$tags" | grep -c .)
  if [ -z "$tags" ] || [ "$count" -le 1 ]; then
    # Single-outbound (or none) — not a fleet; nothing to do, stay quiet.
    XRAY_FLEET_STATUS="single"
    return 0
  fi

  hdr "21. Per-outbound fleet health matrix"
  info "auto-detected ${count} outbounds — testing each (one xray spawn each; this can take a while)"

  if ! check_cmd xray; then warn "skipping — xray not in PATH"; XRAY_FLEET_STATUS="xray-missing"; return 0; fi

  # Heavy (N spawns): auto-skip inside --watch / --from-file loops unless forced.
  if [ "${XRAY_FLEET_FORCE:-0}" != "1" ] \
     && { [ "${_WATCH_CHILD:-0}" = "1" ] || [ "${_BATCH_CHILD:-0}" = "1" ]; }; then
    info "skipped in watch/batch loop (${count} xray spawns) — pass --fleet to force"
    XRAY_FLEET_STATUS="skipped-loop"
    return 0
  fi

  local tag n=0 okc=0 res rtt state
  while IFS= read -r tag; do
    [ -z "$tag" ] && continue
    n=$(( n + 1 ))
    res=$(_fleet_test_one "$XRAY_JSON_CONFIG" "$tag")
    if [ "${res%%|*}" = "ok" ]; then
      rtt="${res#*|}"; state="ok"; okc=$(( okc + 1 ))
      info "  $(printf '%-12s' "$tag") [OK]   RTT ${rtt} ms"
    else
      rtt=""; state="fail"
      info "  $(printf '%-12s' "$tag") [FAIL] tunnel unreachable"
    fi
    XRAY_FLEET_RESULTS="${XRAY_FLEET_RESULTS}${XRAY_FLEET_RESULTS:+ }${tag}|${state}|${rtt}"
  done <<EOF
$tags
EOF

  XRAY_FLEET_TOTAL="$count"
  XRAY_FLEET_OK="$okc"
  XRAY_FLEET_STATUS="ok"
  if [ "$okc" = "$count" ]; then
    ok "all ${count} outbounds healthy"
  elif [ "$okc" = "0" ]; then
    fail "0/${count} outbounds reachable — fleet-wide failure (check the shared config knobs: cover/serverName, keys, flow)"
    if [ "$(_dialer_is_local_desync)" = "1" ]; then
      add_verdict "Every outbound fails the tunnel test — but this config dials through a LOCAL dialerProxy (client-side desync, ByeDPI/zapret). A fleet-wide failure is the expected symptom when that proxy isn't running (they all share it). Start the desync proxy and re-test BEFORE assuming a shared-config fault (serverName/cover/keys/flow)"
    else
      add_verdict "Every outbound in the fleet fails the tunnel test — the problem is in the shared configuration (serverName/cover, keys, flow), not a single dead endpoint"
    fi
  else
    warn "${okc}/${count} outbounds healthy — partial fleet degradation"
    add_verdict "${okc} of ${count} fleet outbounds pass — the rest are down; rotate or repair the failing endpoints (see the matrix above by tag)"
  fi
}

# Routing-coverage probe (split-tunnel). A "selected sites via the proxy, rest
# direct" config expresses its intent in routing.rules — which the other probes
# strip (probe 12/21 del .routing). Tier 1 maps the rules per outbound and lints
# the footguns (undefined outboundTag, default-route direction). Tier 2, when the
# tunnel is up, fetches a sample of proxy-routed sites through the LIVE config
# (routing intact) so you can see the split actually carries them.
probe_xray_routing() {
  if [ -z "$XRAY_JSON_CONFIG" ] || [ ! -r "$XRAY_JSON_CONFIG" ]; then
    XRAY_ROUTING_STATUS="skipped"; return 0
  fi
  if ! command -v jq >/dev/null 2>&1; then
    XRAY_ROUTING_STATUS="jq-missing"; return 0
  fi
  local nrules
  nrules=$(jq -r '(.routing.rules // []) | length' "$XRAY_JSON_CONFIG" 2>/dev/null)
  if [ "${nrules:-0}" -le 0 ]; then
    XRAY_ROUTING_STATUS="none"; return 0
  fi

  hdr "Routing coverage (split-tunnel)"

  # ---- Tier 1: static map + lint ----
  local defined_tags referenced_tags proxy_tags default_tag undef="" t tag
  defined_tags=$(jq -r '[.outbounds[]?.tag // empty] | join(" ")' "$XRAY_JSON_CONFIG" 2>/dev/null)
  referenced_tags=$(jq -r '[.routing.rules[]?.outboundTag // empty] | unique | join(" ")' "$XRAY_JSON_CONFIG" 2>/dev/null)
  proxy_tags=$(jq -r '[.outbounds[]? | select(.settings.vnext != null or .settings.servers != null) | .tag // empty] | join(" ")' "$XRAY_JSON_CONFIG" 2>/dev/null)
  XRAY_ROUTING_PROXY_TAGS="$proxy_tags"

  # Default route: a TRUE catch-all matches everything — a rule with no domain,
  # ip, port, OR protocol narrowing (network-only or empty). A protocol:/port:-
  # only rule (e.g. protocol:bittorrent → direct) is selective, NOT the default,
  # so it must be excluded — else a full-tunnel-with-bypass config gets read
  # backwards as "selective routing". Falls back to Xray's implicit default
  # (the first outbound) when no catch-all rule exists.
  default_tag=$(jq -r '
    [ .routing.rules[]? | select((.domain == null) and (.ip == null)
        and (.port == null) and (.protocol == null)) ]
    | last | .outboundTag // empty' "$XRAY_JSON_CONFIG" 2>/dev/null)
  [ -z "$default_tag" ] && default_tag=$(jq -r '.outbounds[0].tag // empty' "$XRAY_JSON_CONFIG" 2>/dev/null)
  XRAY_ROUTING_DEFAULT="$default_tag"

  for t in $referenced_tags; do
    case " $defined_tags " in *" $t "*) ;; *) undef="${undef:+$undef }$t" ;; esac
  done
  XRAY_ROUTING_UNDEF="$undef"

  for tag in $referenced_tags; do
    [ -z "$tag" ] && continue
    local nd ng ngi nip kind="direct/other"
    nd=$(jq -r --arg t "$tag"  '[.routing.rules[]? | select(.outboundTag==$t) | (.domain // [])[] | select(startswith("geosite:") | not)] | length' "$XRAY_JSON_CONFIG" 2>/dev/null)
    ng=$(jq -r --arg t "$tag"  '[.routing.rules[]? | select(.outboundTag==$t) | (.domain // [])[] | select(startswith("geosite:"))]     | length' "$XRAY_JSON_CONFIG" 2>/dev/null)
    ngi=$(jq -r --arg t "$tag" '[.routing.rules[]? | select(.outboundTag==$t) | (.ip // [])[]     | select(startswith("geoip:"))]       | length' "$XRAY_JSON_CONFIG" 2>/dev/null)
    nip=$(jq -r --arg t "$tag" '[.routing.rules[]? | select(.outboundTag==$t) | (.ip // [])[]     | select(startswith("geoip:") | not)] | length' "$XRAY_JSON_CONFIG" 2>/dev/null)
    case " $proxy_tags " in *" $tag "*) kind="proxy" ;; esac
    info "$(printf '%-14s (%-12s): %s domains · %s geosite · %s geoip · %s ip' "$(_safe "$tag")" "$kind" "$nd" "$ng" "$ngi" "$nip")"
  done
  info "default route → $(_safe "${default_tag:-<first outbound>}")"

  if [ -n "$undef" ]; then
    fail "routing references undefined outboundTag(s): $(_safe "$undef") → matched traffic is dropped/misrouted"
    add_verdict "Routing references outboundTag(s) not defined in outbounds ($(_safe "$undef")) — traffic matching those rules is silently dropped or misrouted; fix the tag names"
  fi
  case " $proxy_tags " in
    *" $default_tag "*) info "default route is a PROXY outbound → ALL traffic tunnels (not just the listed sites)" ;;
    *) [ -n "$proxy_tags" ] && info "default route is direct → only the listed sites/categories use the proxy (selective routing)" ;;
  esac

  # --- domainStrategy / DNS-resolution leak (precise per strategy) ---
  # IPOnDemand resolves a domain ONLY when matching reaches an ip/geoip rule —
  # so with no ip rules it never resolves (behaves like AsIs). IPIfNonMatch
  # resolves EVERY destination that no domain rule matched (it re-runs the rules
  # against the resolved IP), regardless of ip rules. Either resolution, with no
  # `dns` block, hits the system/ISP resolver — a DNS leak (the resolver sees the
  # proxied & direct domains even though traffic is tunneled) plus latency. With
  # sniffing on, domain rules match on the SNI WITHOUT resolution, so "AsIs"
  # avoids it and the ip/geoip rules degrade to matching IP-literal connections
  # only (usually all they were catching anyway).
  local dstrat has_dns has_iprule has_sniff has_dns_split=""
  dstrat=$(jq -r '.routing.domainStrategy // "AsIs"' "$XRAY_JSON_CONFIG" 2>/dev/null)
  has_dns=$(jq -e 'has("dns") and ((.dns.servers // []) | length > 0)' "$XRAY_JSON_CONFIG" >/dev/null 2>&1 && echo 1 || echo 0)
  has_iprule=$(jq -r '[.routing.rules[]? | select(.ip != null)] | length' "$XRAY_JSON_CONFIG" 2>/dev/null)
  has_sniff=$(jq -e 'any((.inbounds // [])[]?; .sniffing.enabled == true)' "$XRAY_JSON_CONFIG" >/dev/null 2>&1 && echo 1 || echo 0)
  # Split-horizon dns = at least one server is an object with a per-domain
  # `domains` map → foreign/blocked names can resolve over a tunneled resolver
  # while domestic names stay on the local one (the leak-free way to keep geoip).
  if [ "$has_dns" = "1" ]; then
    has_dns_split=$(jq -e '[.dns.servers[]? | select(type=="object" and has("domains"))] | length > 0' "$XRAY_JSON_CONFIG" >/dev/null 2>&1 && echo 1 || echo 0)
  fi
  XRAY_ROUTING_DOMAINSTRATEGY="$dstrat"
  XRAY_ROUTING_SNIFF="$has_sniff"
  XRAY_ROUTING_DNS_SPLIT="$has_dns_split"
  info "domainStrategy: ${dstrat} · dns block: $( [ "$has_dns" = 1 ] && echo present || echo none ) · sniffing: $( [ "$has_sniff" = 1 ] && echo on || echo off ) · ip/geoip rules: ${has_iprule:-0}"
  XRAY_ROUTING_DNS_RISK=0
  # The sharp distinction a censor-aware operator needs: local resolution here is
  # leak-only, NOT blending. `direct` traffic ALREADY resolves locally at the
  # freedom outbound (so "AsIs" keeps the real-user DNS-then-connect look the
  # operator wants), while a PROXIED domain connects from the EXIT IP — the local
  # censor never sees that connection, so resolving it locally adds zero blending
  # and only leaks intent; in a censored network the local resolver is poisoned,
  # mis-driving the very geoip rule it was meant to feed.
  local realism_note="local resolution here is leak-only, not blending: 'direct' traffic already resolves locally at the freedom outbound (so \"AsIs\" keeps the real-user DNS-then-connect pattern), while a PROXIED domain connects from the EXIT IP — the local censor never sees that connection, so resolving it locally adds no blending, only leaked intent; worse, a censored network's resolver poisons those answers and mis-drives the geoip rule"
  local split_fix="to keep geoip routing without leaking blocked-domain lookups, use a SPLIT-HORIZON 'dns' block: a tunneled DoH server for foreign/blocked domains (route the resolver's IP to a proxy outbound) + the local resolver for domestic/direct"
  case "$dstrat" in
    IPOnDemand)
      if [ "${has_iprule:-0}" -le 0 ]; then
        info "domainStrategy=IPOnDemand but there are no ip/geoip rules → it never actually resolves (IPOnDemand only resolves to evaluate an ip rule). No leak, but it's a no-op — set \"AsIs\" for clarity"
      elif [ "$has_dns" = "1" ]; then
        if [ "$has_dns_split" = "1" ]; then
          info "domainStrategy=IPOnDemand with a SPLIT-HORIZON dns block (per-domain servers) → good shape: foreign lookups can be tunneled while domestic stay local. Confirm the foreign/DoH server egresses THROUGH the proxy (route its IP to a proxy outbound), else those lookups still leak"
        else
          info "domainStrategy=IPOnDemand with a single-server dns block — confirm that server egresses through the proxy (route its IP to a proxy outbound); a split-horizon dns block (tunneled DoH for foreign, local resolver for domestic) blends better and leaks less"
        fi
      else
        XRAY_ROUTING_DNS_RISK=1
        warn "domainStrategy=IPOnDemand + ${has_iprule} ip/geoip rule(s) and no dns block → those rules resolve domain targets via the system resolver (DNS leak + latency)"
        info "$realism_note"
        info "$split_fix"
        if [ "$has_sniff" = "1" ]; then
          add_verdict "Routing domainStrategy=IPOnDemand resolves domain targets to IP to evaluate the ${has_iprule} ip/geoip rule(s), with no 'dns' block — those lookups hit the system/ISP resolver (a DNS leak + latency). This is leak-only, not blending: direct traffic already resolves locally at the freedom outbound, and a proxied domain connects from the exit IP (the local censor never sees it). Sniffing matches your domain rules without resolution, so set domainStrategy=\"AsIs\"; if you genuinely need geoip on domain targets, use a split-horizon 'dns' block (tunneled DoH for foreign, local resolver for domestic) so blocked-domain lookups don't leak"
        else
          add_verdict "Routing domainStrategy=IPOnDemand resolves domain targets via the system resolver to evaluate the ip/geoip rules, and the inbound has no sniffing — so even domain rules can force a local lookup (DNS leak + latency). Enable sniffing (enabled:true, routeOnly:true) so domain rules match on the SNI, then set domainStrategy=\"AsIs\"; if you need geoip on domain targets use a split-horizon 'dns' block (tunneled DoH for foreign, local resolver for domestic)"
        fi
      fi ;;
    IPIfNonMatch)
      if [ "$has_dns" = "1" ]; then
        if [ "$has_dns_split" = "1" ]; then
          info "domainStrategy=IPIfNonMatch with a SPLIT-HORIZON dns block (per-domain servers) → good shape, but confirm the foreign/DoH server egresses THROUGH the proxy (route its IP to a proxy outbound), else unmatched-domain lookups still leak"
        else
          info "domainStrategy=IPIfNonMatch with a single-server dns block — confirm that server egresses through the proxy; a split-horizon dns block (tunneled DoH for foreign, local resolver for domestic) blends better and leaks less"
        fi
      else
        XRAY_ROUTING_DNS_RISK=1
        warn "domainStrategy=IPIfNonMatch with no dns block → every destination that no domain rule matched is resolved via the system resolver, even with no ip rules (DNS leak + latency)"
        info "$realism_note"
        info "$split_fix"
        add_verdict "Routing domainStrategy=IPIfNonMatch resolves EVERY destination that no domain rule matched (it re-runs the rules against the resolved IP) with no 'dns' block — so those lookups hit the system/ISP resolver: a DNS leak across all unmatched traffic, plus latency. It's leak-only, not blending (direct traffic already resolves locally; proxied domains connect from the exit IP). Set domainStrategy=\"AsIs\"$( [ "$has_sniff" = 1 ] || printf '%s' ' (and enable sniffing on the inbound)' ); for geoip on domain targets use a split-horizon 'dns' block (tunneled DoH for foreign, local resolver for domestic)"
      fi ;;
    *) : ;;   # AsIs / unset → no local resolution for routing
  esac

  # --- egress reputation vs routing intent (cross-probe) ---
  # probe 16 (egress) ran before this probe, so its reputation flags are set. A
  # config that deliberately routes streaming / payment domains THROUGH a proxy
  # whose egress is on datacenter/proxy reputation lists is at war with itself:
  # those exact services geo-block datacenter IPs, so they'll error through this
  # node. We connect the routing intent to the egress verdict the tool already
  # has — more actionable than the generic "datacenter egress" note.
  local proxy_domains sens=""
  proxy_domains=$(jq -r --arg ptags "$proxy_tags" '
      ($ptags | split(" ") | map(select(length > 0))) as $pt
      | [ .routing.rules[]? | select(.outboundTag as $t | ($pt | index($t)))
          | (.domain // [])[] ] | join(" ")' "$XRAY_JSON_CONFIG" 2>/dev/null)
  if printf '%s' "$proxy_domains" | grep -qiE 'netflix|nflx|hulu|disney|bamgrid|hbomax|primevideo|amazonvideo|spotify|scdn|peacock|paramount|max\.com|geosite:(netflix|disney|hbo|spotify)'; then
    sens="streaming"
  fi
  if printf '%s' "$proxy_domains" | grep -qiE 'paypal|stripe|mastercard|sberbank|tinkoff|revolut|coinbase|binance'; then
    sens="${sens:+$sens,}payment"
  fi
  XRAY_ROUTING_PROXY_SENSITIVE="$sens"
  if [ -n "$sens" ]; then
    case "$XRAY_EGRESS_STATUS" in
      ok|partial)
        local eg_flagged=0
        [ "${XRAY_EGRESS_PROXY:-0}" = "1" ]       && eg_flagged=1
        [ "${XRAY_EGRESS_HOSTING:-0}" = "1" ]     && eg_flagged=1
        [ "${XRAY_EGRESS_ASN_HOSTING:-0}" = "1" ] && eg_flagged=1
        [ "${XRAY_EGRESS_DC:-0}" = "1" ]          && eg_flagged=1
        if [ "$eg_flagged" = "1" ]; then
          warn "proxy-routed set includes ${sens} services, but the egress is on datacenter/proxy reputation lists → those services will geo/proxy-block through this node"
          add_verdict "Routing sends ${sens} services through the proxy while the egress is on datacenter/proxy reputation lists — those exact services geo-block datacenter IPs, so they'll challenge or error through this node. Route ${sens} via a residential / clean-IP egress, or drop them from the proxy set"
        else
          info "proxy-routed set includes ${sens} services — egress reputation is clean at this vantage, but a datacenter egress would geo-block them (re-check from the deploy egress)"
        fi ;;
      *) info "proxy-routed set includes ${sens} services — egress reputation not checked (tunnel down / check disabled); on a datacenter egress these services geo-block" ;;
    esac
  fi
  XRAY_ROUTING_STATUS="ok"

  # ---- Tier 2: live split-tunnel test (needs a working tunnel) ----
  if [ "${XRAY_JSON_STATUS:-}" != "ok" ]; then
    info "live split-tunnel test skipped — tunnel not established (see probe 12); the map above is static"
    XRAY_ROUTING_LIVE="skipped"; return 0
  fi
  if ! check_cmd xray || ! check_cmd curl; then
    XRAY_ROUTING_LIVE="skipped"; return 0
  fi

  # Sample up to 4 explicit domains routed to a proxy outbound (geosite/geoip
  # need the .dat files to expand to hosts, so we sample the literal domains).
  local samples
  samples=$(jq -r --arg ptags "$proxy_tags" '
    ($ptags | split(" ") | map(select(length > 0))) as $pt
    | [ .routing.rules[]? | select(.outboundTag as $t | ($pt | index($t)))
        | (.domain // [])[] | select(startswith("geosite:") | not)
        | sub("^(domain:|full:)"; "") ]
    | unique | .[0:4][]' "$XRAY_JSON_CONFIG" 2>/dev/null)
  if [ -z "$samples" ]; then
    info "live test: no explicit proxy-routed domains to sample (only geosite/geoip categories)"
    XRAY_ROUTING_LIVE="ok"; return 0
  fi

  local socks_port base patched log pid i ready
  socks_port=$(_find_free_port) || { XRAY_ROUTING_LIVE="skipped"; return 0; }
  base=$(mktemp -t detect_blocking.routing.XXXXXX) || { XRAY_ROUTING_LIVE="skipped"; return 0; }
  patched="${base}.json"
  if ! mv "$base" "$patched" 2>/dev/null; then rm -f "$base"; XRAY_ROUTING_LIVE="skipped"; return 0; fi
  # Keep routing + outbounds intact; only relocate the socks inbound to our port.
  if ! jq --argjson p "$socks_port" '
        .inbounds = [{ tag:"socks", listen:"127.0.0.1", port:$p, protocol:"socks", settings:{auth:"noauth", udp:true} }]
        | del(.observatory)
      ' "$XRAY_JSON_CONFIG" > "$patched" 2>/dev/null; then
    rm -f "$patched"; XRAY_ROUTING_LIVE="skipped"; return 0
  fi
  log=$(mktemp -t detect_blocking.routinglog.XXXXXX)
  xray run -c "$patched" >"$log" 2>&1 &
  pid=$!; XRAY_ROUTING_PID="$pid"
  ready=0
  for i in $(seq 1 $(( TIMEOUT * 5 + 10 ))); do
    nc -z 127.0.0.1 "$socks_port" 2>/dev/null && { ready=1; break; }
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.2
  done
  if [ "$ready" -ne 1 ]; then
    warn "live test: xray did not start with the full routing config"
    XRAY_ROUTING_LIVE="failed"
    kill "$pid" 2>/dev/null; XRAY_ROUTING_PID=""
    rm -f "$patched" "$log" 2>/dev/null
    return 0
  fi

  # Per domain: carried (proxy reached it) / proxy-failed (reachable DIRECT but
  # not via the proxy — the only real routing fault) / n-a (unreachable both ways
  # — a non-fetchable apex or suffix-match entry like cdninstagram.com, NOT a
  # proxy problem). Comparing against a direct baseline is what keeps a CDN apex
  # from masquerading as a split-tunnel failure.
  local d okc=0 failc=0 nac=0 mt state
  mt=$(( ( ${XRAY_JSON_RTT_MS:-3000} + 999 ) / 1000 + TIMEOUT ))
  for d in $samples; do
    [ -z "$d" ] && continue
    if _url_reachable "https://$d/" "$mt" "127.0.0.1:$socks_port"; then
      state="carried"; okc=$(( okc + 1 ))
      info "  routed $(printf '%-18s' "$d") → carried by the config"
    elif _url_reachable "https://$d/" "$mt"; then
      state="proxy-failed"; failc=$(( failc + 1 ))
      info "  routed $(printf '%-18s' "$d") → reachable DIRECT but NOT through the config (routing/proxy fault)"
    else
      state="n-a"; nac=$(( nac + 1 ))
      info "  routed $(printf '%-18s' "$d") → n/a (not fetchable directly either — suffix-match/CDN apex)"
    fi
    XRAY_ROUTING_LIVE_RESULTS="${XRAY_ROUTING_LIVE_RESULTS}${XRAY_ROUTING_LIVE_RESULTS:+ }${d}|${state}"
  done

  kill "$pid" 2>/dev/null; for i in 1 2 3; do kill -0 "$pid" 2>/dev/null || break; sleep 0.2; done; kill -9 "$pid" 2>/dev/null
  XRAY_ROUTING_PID=""
  rm -f "$patched" "$log" 2>/dev/null

  local fetchable=$(( okc + failc ))
  if [ "$fetchable" -eq 0 ]; then
    info "live test inconclusive — all $nac sampled domains are non-fetchable apexes (suffix-match/CDN); nothing to carry"
    XRAY_ROUTING_LIVE="inconclusive"
  elif [ "$failc" -eq 0 ]; then
    ok "split-tunnel works — all $okc fetchable proxy-routed sites carried$( [ "$nac" -gt 0 ] && printf ' (%s n/a: non-fetchable apex, not a proxy fault)' "$nac" )"
    XRAY_ROUTING_LIVE="ok"
  elif [ "$okc" -eq 0 ]; then
    fail "0/$fetchable fetchable proxy-routed sites carried — the proxy path isn't carrying them"
    add_verdict "Split-tunnel: every fetchable proxy-routed site loads directly but NOT through the config — the proxy outbound isn't carrying traffic, so the sites this config should unblock won't work"
    XRAY_ROUTING_LIVE="failed"
  else
    warn "$okc/$fetchable fetchable proxy-routed sites carried — $failc reachable direct but not through the config (partial)"
    add_verdict "Split-tunnel partial: $failc proxy-routed site(s) load directly but not through the config — the routing/proxy isn't carrying them (the other $okc are fine; non-fetchable apexes are ignored)"
    XRAY_ROUTING_LIVE="partial"
  fi
}

# Warm round-trip (ms) through the tunnel: one keep-alive curl fetches the tiny
# trace endpoint N times — the first pays the handshake, the rest are warm, so
# their min is the true per-request RTT with handshake cost excluded. Echoes
# "min max" in ms, or empty on failure. $1 = socks port, $2 = max-time.
_tunnel_warm_rtt() {
  local port="$1" mt="$2" out line first=1 v min="" max=""
  # speed.cloudflare.com/__down?bytes=0 → a clean 200 with an empty body and no
  # redirect, same host as the load download so keep-alive reuse is consistent.
  local u="https://speed.cloudflare.com/__down?bytes=0"
  out=$(curl -sS --max-time "$mt" --socks5-hostname "127.0.0.1:$port" \
        -o /dev/null -w '%{time_total}\n' \
        "$u" "$u" "$u" "$u" "$u" 2>/dev/null) || return 1
  while IFS= read -r line; do
    if [ "$first" = "1" ]; then first=0; continue; fi   # drop handshake sample
    # seconds.float → integer ms
    v=$(printf '%s' "$line" | awk '{printf "%d", ($1*1000)+0.5}')
    case "$v" in ''|*[!0-9]*) continue ;; esac
    [ -z "$min" ] && min="$v"; [ "$v" -lt "$min" ] && min="$v"
    [ -z "$max" ] && max="$v"; [ "$v" -gt "$max" ] && max="$v"
  done <<EOF
$out
EOF
  [ -n "$min" ] || return 1
  printf '%s %s' "$min" "$max"
}

# Probe 22 — bufferbloat / latency-under-load. Warm RTT idle vs under a
# saturating download through the same tunnel. The inflation (load − idle) is
# the queueing delay the tunnel adds when busy — what makes a fast link feel
# laggy on realtime traffic. Output: ms only, never an endpoint.
probe_xray_bufferbloat() {
  if [ "$XRAY_BUFFERBLOAT" != "1" ]; then
    XRAY_BUFFERBLOAT_STATUS="disabled"
    return 0
  fi
  if [ "$XRAY_JSON_STATUS" != "ok" ]; then
    XRAY_BUFFERBLOAT_STATUS="skipped"
    return 0
  fi

  hdr "22. Bufferbloat (latency under load)"

  if ! check_cmd curl; then
    warn "skipping — curl not available"
    XRAY_BUFFERBLOAT_STATUS="curl-missing"
    return 0
  fi

  local port="$XRAY_JSON_SOCKS_PORT" mt idle load loadpid
  mt=$(( ( ${XRAY_JSON_RTT_MS:-3000} + 999 ) / 1000 + 10 ))

  idle=$(_tunnel_warm_rtt "$port" "$mt")
  if [ -z "$idle" ]; then
    warn "could not measure idle RTT through the tunnel"
    XRAY_BUFFERBLOAT_STATUS="no-data"
    return 0
  fi
  XRAY_BUFFERBLOAT_IDLE_MS="${idle%% *}"

  # Saturate the tunnel in the background (bounded), then sample warm RTT.
  curl -sS --max-time 8 --socks5-hostname "127.0.0.1:$port" -o /dev/null \
    "https://speed.cloudflare.com/__down?bytes=$((12*1024*1024))" >/dev/null 2>&1 &
  loadpid=$!
  sleep 1
  load=$(_tunnel_warm_rtt "$port" "$mt")
  kill "$loadpid" 2>/dev/null; wait "$loadpid" 2>/dev/null

  if [ -z "$load" ]; then
    warn "could not measure loaded RTT (tunnel dropped under load?)"
    XRAY_BUFFERBLOAT_STATUS="no-data"
    return 0
  fi
  XRAY_BUFFERBLOAT_LOAD_MS="${load%% *}"
  XRAY_BUFFERBLOAT_JITTER_MS=$(( ${load#* } - ${load%% *} ))
  local inflate=$(( XRAY_BUFFERBLOAT_LOAD_MS - XRAY_BUFFERBLOAT_IDLE_MS ))
  [ "$inflate" -lt 0 ] && inflate=0
  XRAY_BUFFERBLOAT_INFLATE_MS="$inflate"

  info "warm RTT idle ${XRAY_BUFFERBLOAT_IDLE_MS} ms → under load ${XRAY_BUFFERBLOAT_LOAD_MS} ms (jitter ${XRAY_BUFFERBLOAT_JITTER_MS} ms)"

  if [ "$inflate" -lt 100 ]; then
    ok "low bufferbloat: +${inflate} ms under load — fine for calls / gaming"
    XRAY_BUFFERBLOAT_STATUS="ok"
  elif [ "$inflate" -lt 400 ]; then
    warn "moderate bufferbloat: +${inflate} ms under load"
    XRAY_BUFFERBLOAT_STATUS="moderate"
    add_verdict "Tunnel adds ${inflate} ms of latency under load (moderate bufferbloat) — throughput is fine but realtime traffic (calls, gaming) will feel it when the link is busy"
  else
    fail "heavy bufferbloat: +${inflate} ms under load"
    XRAY_BUFFERBLOAT_STATUS="heavy"
    add_verdict "Tunnel adds ${inflate} ms of latency under load (heavy bufferbloat) — the link buffers badly when saturated; realtime traffic stalls during any download. Often the server/egress queue; consider a CAKE/fq_codel qdisc on the server or a less-congested egress"
  fi
}

# Probe 23 — path MTU to the server. A clamped MTU fragments the Reality
# ClientHello and causes intermittent handshake failures that mimic DPI. DF-bit
# ping sweep finds the largest unfragmented payload. Output: an MTU number.
probe_xray_mtu() {
  if [ -z "$XRAY_CONFIG" ] && [ -z "$XRAY_JSON_CONFIG" ]; then
    XRAY_MTU_STATUS="skipped"
    return 0
  fi

  hdr "23. Path MTU to server"

  if ! check_cmd ping; then
    warn "skipping — ping not available"
    XRAY_MTU_STATUS="no-ping"
    return 0
  fi

  # DF-bit + reply-timeout flags differ between ping flavours. Detect support
  # against loopback (always answers) so detection doesn't depend on whether
  # the TARGET answers — and ALWAYS carry a timeout so a non-answering / ICMP-
  # filtered host can't hang the sweep (no timeout = ~10s/ping × ladder).
  local pf sz ok_payload="" found=0
  if ping -M "do" -c 1 -W 1 127.0.0.1 >/dev/null 2>&1; then
    pf="-M do -W 2"          # GNU/iputils: -M do = DF, -W = reply timeout (s)
  elif ping -D -c 1 -t 1 127.0.0.1 >/dev/null 2>&1; then
    pf="-D -t 2"             # BSD/macOS: -D = DF, -t = total timeout (s)
  else
    info "ping flavour unrecognized — MTU undetermined"
    XRAY_MTU_STATUS="no-ping"
    return 0
  fi

  # Descending payload ladder; path MTU = largest passing payload + 28 (IP+ICMP).
  for sz in 1472 1452 1400 1372 1272 1172 972; do
    # shellcheck disable=SC2086
    if ping $pf -c 1 -s "$sz" "$VPN_HOST" >/dev/null 2>&1; then
      ok_payload="$sz"; found=1; break
    fi
  done

  if [ "$found" != "1" ]; then
    # Either ICMP is filtered, or even small DF packets fail. Confirm with a
    # plain (no-DF) ping: if that works too, ICMP echo is simply blocked.
    local base="-W 2"; case "$pf" in *-t\ *) base="-t 2" ;; esac
    # shellcheck disable=SC2086
    if ping $base -c 1 "$VPN_HOST" >/dev/null 2>&1; then
      info "host answers ping but no DF size passed — unusual; treating MTU as undetermined"
    else
      info "host does not answer ICMP echo — MTU undetermined (ICMP filtered)"
    fi
    XRAY_MTU_STATUS="filtered"
    return 0
  fi

  XRAY_MTU_PATH=$(( ok_payload + 28 ))
  if [ "$XRAY_MTU_PATH" -ge 1500 ]; then
    ok "path MTU ${XRAY_MTU_PATH} — full, no clamping"
    XRAY_MTU_STATUS="ok"
  else
    warn "path MTU clamped to ${XRAY_MTU_PATH} (< 1500)"
    XRAY_MTU_STATUS="clamped"
    add_verdict "Path MTU to the server is ${XRAY_MTU_PATH} (clamped below 1500) — large TLS ClientHellos may fragment and cause intermittent handshake failures that look like DPI. Usually benign, but if handshakes are flaky, clamp the client/server MSS to match"
  fi
}

# Pure: does the cleartext cover SNI carry a circumvention / antagonistic keyword?
# Echoes 1 on hit, 0 otherwise. A passive SNI blocklist matches these DIRECTLY — the
# cheapest possible detection, no DNS lookup and no active probe — so this is the
# severe tell, distinct from the softer "does not resolve" one.
#
# Censor-name terms (rkn / tspu) are matched on LABEL BOUNDARIES only (start, end, `.`
# or `-`), never as a bare substring: plenty of innocent domains contain those letters
# (`workname.com` contains "rkn"). Anchoring is why `blocked.rkn` used to slip through —
# the old patterns required a hyphen, so a dot-delimited label never matched.
_sni_keyword_hit() {
  local sni_lc
  sni_lc=$(printf '%s' "${1-}" | tr '[:upper:]' '[:lower:]')
  case "$sni_lc" in
    # protocol / circumvention vocabulary — distinctive enough to match anywhere
    *vpn*|*proxy*|*xray*|*v2ray*|*reality*|*shadowsock*|*trojan*|*wireguard*|*outline*\
    |*censor*|*roskomnadzor*|*zapret*|*unblock*|*bypass*) printf '1'; return 0 ;;
    # censor names, label-anchored (start | end | dot | hyphen delimited)
    rkn|rkn.*|*.rkn|*.rkn.*|*-rkn|*-rkn.*|*rkn-*) printf '1'; return 0 ;;
    tspu|tspu.*|*.tspu|*.tspu.*|*-tspu|*-tspu.*|*tspu-*) printf '1'; return 0 ;;
  esac
  printf '0'
}

# Pure: compare one negotiated TLS field between server and cover.
#   1  both sides read and EQUAL          → measured match
#   0  both sides read and DIFFERENT      → measured mismatch (the only scorable case)
#   "" either side unreadable             → NOT measured; must not be scored or claimed
# ALPN legitimately reads as empty ("no ALPN negotiated"), so an empty-vs-empty pair
# counts as a measured match only when BOTH are empty AND the handshake produced output;
# callers pass ALPN through the same gate and treat "" as unknown, which is the safe read.
_tls_field_match() {
  local a="$1" b="$2"
  { [ -n "$a" ] && [ -n "$b" ]; } || { printf '%s' ""; return 0; }
  [ "$a" = "$b" ] && printf '1' || printf '0'
}

# Probe 24 — TLS-negotiation parity. Compares the TLS the server negotiates
# (version / ALPN / cipher) against the genuine cover site. A relaying Reality
# server matches; a fake / wrong-dest one diverges. Booleans + generic values
# only — never the cover domain.
probe_xray_tls_parity() {
  local sni
  sni=$(_xray_cover_sni)
  if [ -z "$sni" ]; then
    XRAY_TLSPAR_STATUS="skipped"
    return 0
  fi

  hdr "24. TLS-negotiation parity (vs genuine cover)"

  if ! check_cmd openssl; then
    warn "skipping — openssl not available"
    XRAY_TLSPAR_STATUS="openssl-missing"
    return 0
  fi

  # Negotiate against the server (the IP) and the genuine cover, same SNI/ALPN.
  # -tlsextdebug dumps the ServerHello EXTENSION list — the discriminating part
  # of a JA3S fingerprint that version/ALPN/cipher alone miss. A correctly
  # relaying Reality server splices us to the real dest, so its ServerHello
  # (incl. extensions) should be byte-identical to the cover's; a broken/own-TLS
  # server diverges at the extension level even when version/cipher happen to align.
  # Bound both connects: openssl s_client blocks on the OS TCP connect timeout
  # (~75s) for a dead server or an NXDOMAIN/unroutable cover — `echo Q` only quits
  # after the handshake. Precheck both sides with a $TIMEOUT-bounded nc first.
  if ! _nc_tcp_probe "$VPN_HOST" "$VPN_PORT_TCP" || ! _nc_tcp_probe "$sni" 443; then
    warn "could not complete both TLS negotiations (server or cover unreachable)"
    XRAY_TLSPAR_STATUS="unreachable"
    return 0
  fi
  local s_out c_out s_ver c_ver s_alpn c_alpn s_ciph c_ciph s_ext c_ext
  s_out=$(echo Q | openssl s_client -connect "$VPN_HOST:$VPN_PORT_TCP" \
          -servername "$sni" -alpn h2,http/1.1 -tlsextdebug 2>/dev/null)
  c_out=$(echo Q | openssl s_client -connect "$sni:443" \
          -servername "$sni" -alpn h2,http/1.1 -tlsextdebug 2>/dev/null)

  if [ -z "$s_out" ] || [ -z "$c_out" ]; then
    warn "could not complete both TLS negotiations (server or cover unreachable)"
    XRAY_TLSPAR_STATUS="unreachable"
    return 0
  fi

  # Extract negotiated TLS version, ALPN, and cipher from each.
  s_ver=$(printf '%s' "$s_out"  | sed -nE 's/^[[:space:]]*Protocol[[:space:]]*:[[:space:]]*(.*)/\1/p' | head -1)
  c_ver=$(printf '%s' "$c_out"  | sed -nE 's/^[[:space:]]*Protocol[[:space:]]*:[[:space:]]*(.*)/\1/p' | head -1)
  s_alpn=$(printf '%s' "$s_out" | sed -nE 's/^ALPN protocol:[[:space:]]*(.*)/\1/p' | head -1)
  c_alpn=$(printf '%s' "$c_out" | sed -nE 's/^ALPN protocol:[[:space:]]*(.*)/\1/p' | head -1)
  # Cipher line format differs by openssl build and BOTH must be handled, else the
  # field silently reads as "unmeasured" and (pre-1.10.1) scored as a MISMATCH:
  #   OpenSSL 1.x / LibreSSL : "    Cipher    : TLS_AES_256_GCM_SHA384"
  #   OpenSSL 3.x            : "New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384"
  s_ciph=$(printf '%s' "$s_out" | sed -nE 's/^[[:space:]]*Cipher[[:space:]]*:[[:space:]]*(.*)/\1/p' | head -1)
  [ -z "$s_ciph" ] && s_ciph=$(printf '%s' "$s_out" | sed -nE 's/^New,[^,]*,[[:space:]]*Cipher is[[:space:]]*(.*)/\1/p' | head -1)
  c_ciph=$(printf '%s' "$c_out" | sed -nE 's/^[[:space:]]*Cipher[[:space:]]*:[[:space:]]*(.*)/\1/p' | head -1)
  [ -z "$c_ciph" ] && c_ciph=$(printf '%s' "$c_out" | sed -nE 's/^New,[^,]*,[[:space:]]*Cipher is[[:space:]]*(.*)/\1/p' | head -1)

  # ServerHello extension list (ordered ids), the JA3S-discriminating part.
  s_ext=$(printf '%s' "$s_out" | sed -nE 's/.*server extension.*\(id=([0-9]+)\).*/\1/p' | tr '\n' '-' | sed 's/-$//')
  c_ext=$(printf '%s' "$c_out" | sed -nE 's/.*server extension.*\(id=([0-9]+)\).*/\1/p' | tr '\n' '-' | sed 's/-$//')

  # Tri-state per field: 1 measured-match · 0 measured-MISMATCH · "" not measurable.
  # Never score a field we could not read (an unreadable cipher line used to look
  # exactly like a mismatch and added a permanent, unearned +15 in probe 26).
  XRAY_TLSPAR_SERVER_ALPN="$s_alpn"; XRAY_TLSPAR_COVER_ALPN="$c_alpn"
  XRAY_TLSPAR_VER_MATCH=$(_tls_field_match "$s_ver" "$c_ver")
  XRAY_TLSPAR_ALPN_MATCH=$(_tls_field_match "$s_alpn" "$c_alpn")
  XRAY_TLSPAR_CIPHER_MATCH=$(_tls_field_match "$s_ciph" "$c_ciph")
  XRAY_TLSPAR_EXT_MATCH=$(_tls_field_match "$s_ext" "$c_ext")

  # JA3S-grade fingerprint: hash(version|cipher|extension-ids) for each side. Same
  # inputs as JA3S (openssl's names rather than the canonical numeric encoding, but
  # apples-to-apples since both sides use the same tool). Share-safe (a shape hash).
  if check_cmd openssl; then
    XRAY_TLSPAR_SERVER_FP=$(printf '%s|%s|%s' "$s_ver" "$s_ciph" "$s_ext" | openssl dgst -sha256 2>/dev/null | sed -nE 's/.*([0-9a-f]{64}).*/\1/p' | cut -c1-12)
    XRAY_TLSPAR_COVER_FP=$(printf '%s|%s|%s' "$c_ver" "$c_ciph" "$c_ext" | openssl dgst -sha256 2>/dev/null | sed -nE 's/.*([0-9a-f]{64}).*/\1/p' | cut -c1-12)
  fi

  info "negotiation: version-match=${XRAY_TLSPAR_VER_MATCH:-n/a}, ALPN-match=${XRAY_TLSPAR_ALPN_MATCH:-n/a}, cipher-match=${XRAY_TLSPAR_CIPHER_MATCH:-n/a}, ext-match=${XRAY_TLSPAR_EXT_MATCH:-n/a} (server ${s_ver:-?}/${s_alpn:-none}, cover ${c_ver:-?}/${c_alpn:-none}; n/a = this openssl did not report the field, not a mismatch)"
  # HTTP/3 parity (advisory, NOT scored). A cover on a big CDN answers QUIC on UDP/443;
  # a TCP-only Reality server does not. One UDP packet then separates the impersonator
  # from the impersonated. Deliberately unscored: it correlates with the SNI<->IP
  # mismatch probe 26 already charges +10 for, and plenty of honest hosts skip h3 —
  # scoring both would charge twice for the same underlying fact.
  # No resolvability guard needed: this probe returns early unless the cover answered
  # TCP/443, so reaching here already proves the cover domain resolves and is up.
  if check_cmd perl; then
    XRAY_TLSPAR_COVER_H3=$(_quic_vn_probe "$sni" 443 "$TIMEOUT")
    # Order matters: "ok" may only be claimed when BOTH sides were measured. A Reality/TCP
    # config never gets its target QUIC-probed (probe 6 only baselines), and recording that
    # as "ok" asserted a parity nobody measured.
    if [ "$XRAY_TLSPAR_COVER_H3" != "vn" ] || [ -z "${UDP_QUIC_TARGET:-}" ]; then
      XRAY_TLSPAR_H3_PARITY="n/a"
    elif [ "${UDP_QUIC_TARGET}" = "vn" ]; then
      XRAY_TLSPAR_H3_PARITY="ok"
    elif [ "$XRAY_TLSPAR_COVER_H3" = "vn" ] && [ -n "${UDP_QUIC_TARGET:-}" ] && [ "${UDP_QUIC_TARGET}" != "vn" ]; then
      XRAY_TLSPAR_H3_PARITY="cover-only"
      warn "HTTP/3 parity: the cover domain answers QUIC on UDP/443 but this server does not — a prober can tell them apart with a single UDP packet (advisory, not scored; the SNI<->IP mismatch already covers the same underlying fact). Serving QUIC is not expected of a Reality endpoint; it matters only because you impersonate a host that does"
    else
      XRAY_TLSPAR_H3_PARITY="n/a"
    fi
  else
    XRAY_TLSPAR_H3_PARITY="n/a"
  fi

  info "HTTP versions: server ALPN=${s_alpn:-none} · cover ALPN=${c_alpn:-none} · cover HTTP/3=$( [ "$XRAY_TLSPAR_COVER_H3" = "vn" ] && printf 'yes' || printf 'no/unknown' )"
  info "ServerHello fingerprint (JA3S-grade): server ${XRAY_TLSPAR_SERVER_FP:-?} vs cover ${XRAY_TLSPAR_COVER_FP:-?}$( [ -n "$XRAY_TLSPAR_SERVER_FP" ] && [ "$XRAY_TLSPAR_SERVER_FP" = "$XRAY_TLSPAR_COVER_FP" ] && echo ' (match)' || echo ' (DIFFER)' )"

  # Decision on version+ALPN+cipher, but ONLY on fields we actually measured: any
  # measured "0" is a real mismatch; all-unmeasured is `unverified` (scored like
  # `unreachable`: +5 for an unobservable dimension, never the full mismatch penalty).
  local _mismatched=0 _measured=0 _f
  for _f in "$XRAY_TLSPAR_VER_MATCH" "$XRAY_TLSPAR_ALPN_MATCH" "$XRAY_TLSPAR_CIPHER_MATCH"; do
    case "$_f" in 0) _mismatched=1; _measured=$((_measured+1)) ;; 1) _measured=$((_measured+1)) ;; esac
  done
  if [ "$_measured" = "0" ]; then
    XRAY_TLSPAR_STATUS="unverified"
    warn "could not read version/ALPN/cipher from either handshake (this openssl build reports none of them) — TLS parity UNVERIFIED, not scored as a mismatch"
  elif [ "$_mismatched" = "0" ]; then
    XRAY_TLSPAR_STATUS="ok"   # every MEASURED field matches (unmeasured ones are ignored)
    if [ "$XRAY_TLSPAR_EXT_MATCH" = "0" ]; then
      # Version/ALPN/cipher align but the ServerHello extension SET diverges — a
      # finer (JA3S-grade) tell. Not scored (can be benign relay/openssl variance),
      # but a JA3S/JA4S fingerprinter could still distinguish server from cover.
      warn "version/ALPN/cipher match the cover, but the ServerHello EXTENSION set differs (JA3S-grade fingerprint ${XRAY_TLSPAR_SERVER_FP:-?} ≠ ${XRAY_TLSPAR_COVER_FP:-?}) — a JA3S/JA4S fingerprinter could still tell the server from the cover it impersonates (often benign relay/openssl variance; matters against a censor that does ServerHello fingerprinting)"
    else
      ok "TLS negotiation matches the genuine cover on every field this openssl reported (${_measured}/3 of version/ALPN/cipher, plus ServerHello extensions) → relays cleanly"
    fi
  else
    warn "TLS negotiation differs from the genuine cover"
    XRAY_TLSPAR_STATUS="mismatch"
    # Name the HTTP version divergence explicitly — "negotiation differs" alone gives
    # the operator nothing to change. This is the single most common cause: the client
    # pins an ALPN the cover would never pick, so the relayed handshake cannot match.
    if [ "$XRAY_TLSPAR_ALPN_MATCH" = "0" ]; then
      warn "HTTP version mismatch: this server negotiates '${s_alpn:-none}' while the genuine cover negotiates '${c_alpn:-none}' — an active prober comparing the two separates them on one handshake. Fix: make the client's alpn match the cover (or drop the alpn parameter entirely and let the relay decide, which is what a real client of that cover would do)"
    fi
    add_verdict "Server's TLS negotiation does not match the genuine cover site (version/ALPN/cipher$( [ "$XRAY_TLSPAR_EXT_MATCH" = "0" ] && echo '/ServerHello extensions' )$( if [ -n "$XRAY_TLSPAR_SERVER_FP" ] && [ "$XRAY_TLSPAR_SERVER_FP" != "$XRAY_TLSPAR_COVER_FP" ]; then printf '; JA3S-grade fingerprint %s vs cover %s' "$XRAY_TLSPAR_SERVER_FP" "$XRAY_TLSPAR_COVER_FP"; else printf '; the JA3S-grade ServerHello fingerprint itself MATCHES the cover, so the divergence is in the negotiated parameters only'; fi )) — it doesn't fully impersonate the host its serverName claims, a fingerprint an active prober or a JA3S/JA4S fingerprinter can use. Point Reality 'dest' at the exact cover the client's serverName expects (and confirm probes 15/20)"
  fi
}

# Probe 25 — cover-SNI region-throttle. A DIRECT bulk fetch from the genuine
# cover site vs a neutral baseline, from this vantage. If the cover is shaped
# in-region the tunnel (which uses that SNI) silently inherits the throttle.
# Best-effort: needs the cover to serve a measurable payload at its root.
# Output: KB/s + ratio, never the cover domain.
probe_xray_coverthrottle() {
  local sni
  sni=$(_xray_cover_sni)
  if [ -z "$sni" ]; then
    XRAY_COVERTHR_STATUS="skipped"
    return 0
  fi

  hdr "25. Cover-SNI region-throttle"

  if ! check_cmd curl; then
    warn "skipping — curl not available"
    XRAY_COVERTHR_STATUS="curl-missing"
    return 0
  fi

  # PRIMARY signal: the tunnel already presents the cover SNI in bulk, so
  # probe 13/14's throughput IS a reliable cover-SNI throughput measurement.
  # A direct fetch of the cover root is only trustworthy if the cover happens
  # to serve megabytes — for a small payload curl's speed_download reflects
  # connection-setup LATENCY, not bandwidth (that's the misleading "70 KB/s").
  # So: prefer the tunnel; fall back to a direct fetch only when there's no
  # tunnel AND the cover serves enough to measure real throughput.
  local tun_bps="${XRAY_SPEEDTEST_BEST_BPS:-}"
  [ -z "$tun_bps" ] && tun_bps="${XRAY_THROUGHPUT_BPS:-}"
  case "$tun_bps" in ''|*[!0-9]*) tun_bps="" ;; esac

  if [ -n "$tun_bps" ] && [ "$tun_bps" -gt 0 ]; then
    XRAY_COVERTHR_COVER_BPS="$tun_bps"
    if [ "$tun_bps" -ge 256000 ]; then
      ok "cover SNI not throttled at this vantage — the tunnel carries it at $(( tun_bps * 8 / 1000000 )) Mbps (a volumetric throttle would cap it to tens of KB/s)"
      XRAY_COVERTHR_STATUS="ok"
    elif [ "$tun_bps" -lt 51200 ] && [ "${TCP_OK:-1}" = "1" ] && [ "${TLS_PROPER_SNI_OK:-1}" = "1" ]; then
      fail "cover SNI may be shaped here — the tunnel carrying it manages only $(( tun_bps / 1024 )) KB/s while transport is clean"
      XRAY_COVERTHR_STATUS="throttled"
      add_verdict "The cover SNI may be throttled at this vantage — the tunnel that presents it manages only $(( tun_bps / 1024 )) KB/s while the transport layer (probes 2-5) is clean. If this is the affected region, the tunnel is inheriting a shape on the cover SNI: switch to a cover that isn't throttled here"
    else
      warn "tunnel throughput modest ($(( tun_bps / 1024 )) KB/s) — can't cleanly separate cover-SNI shaping from normal tunnel overhead; inconclusive"
      XRAY_COVERTHR_STATUS="inconclusive"
    fi
    info "note: a region-throttle only shows where it's enforced — run from the affected region (e.g. RU), not a clean vantage"
    return 0
  fi

  # No tunnel — fall back to a DIRECT bulk fetch from the cover. Only trust it
  # at >= 1 MB, below which speed_download is latency-dominated and unreliable.
  local cover_stats base_stats cbytes cbps bbps
  cover_stats=$(curl -sS -L --max-time "$(( TIMEOUT + 8 ))" -o /dev/null \
    -w '%{size_download} %{speed_download}' "https://${sni}/" 2>/dev/null)
  base_stats=$(curl -sS --max-time "$(( TIMEOUT + 8 ))" -o /dev/null \
    -w '%{size_download} %{speed_download}' \
    "https://speed.cloudflare.com/__down?bytes=$((4*1024*1024))" 2>/dev/null)
  cbytes=$(printf '%s' "$cover_stats" | awk '{print $1+0}')
  cbps=$(printf '%s'   "$cover_stats" | awk '{print int($2)}')
  bbps=$(printf '%s'   "$base_stats"  | awk '{print int($2)}')

  if [ "${cbytes:-0}" -lt 1048576 ] || [ "${bbps:-0}" -le 0 ]; then
    info "cover root served ${cbytes:-0} bytes — too little to measure bandwidth (a small fetch's speed is latency, not throughput), and no tunnel to cross-check"
    warn "inconclusive"
    XRAY_COVERTHR_STATUS="inconclusive"
    info "note: a region-throttle only shows where it's enforced — run from the affected region, not a clean vantage"
    return 0
  fi

  XRAY_COVERTHR_COVER_BPS="$cbps"
  XRAY_COVERTHR_BASE_BPS="$bbps"
  info "direct bulk fetch: cover $(( cbps / 1024 )) KB/s vs baseline $(( bbps / 1024 )) KB/s"
  if [ "$cbps" -lt 51200 ] && [ "$(( cbps * 5 ))" -lt "$bbps" ]; then
    fail "cover throughput $(( cbps / 1024 )) KB/s is a fraction of baseline → cover SNI appears throttled here"
    XRAY_COVERTHR_STATUS="throttled"
    add_verdict "The configured cover domain is itself throttled from this vantage (cover $(( cbps / 1024 )) KB/s vs baseline $(( bbps / 1024 )) KB/s) — the Reality tunnel, which presents that SNI, will silently inherit the shaping ('fast handshake, slow data'): pick a cover that is NOT shaped in the target region"
  else
    ok "cover not throttled here ($(( cbps / 1024 )) KB/s vs baseline $(( bbps / 1024 )) KB/s)"
    XRAY_COVERTHR_STATUS="ok"
  fi
}

# Probe 27 — SNI privacy / ECH posture (advisory; unnumbered header so probe 26
# stays the last SCORED probe, exactly like the volume-throttle advisory). Probe
# 26 scores the QUALITY of the cleartext cover SNI but treats its visibility as
# fixed. This adds the orthogonal axis the KB names as the step after DoH: CAN the
# SNI be hidden (Encrypted ClientHello), and does the transport allow it? Reality
# relies on a cleartext cover BY DESIGN (ECH N/A); a TLS-over-CDN transport (the
# ByeDPI/Cloudflare pattern) CAN use ECH, and major CDNs publish ECH configs in
# DNS (HTTPS RR ech=). Advisory only — not folded into the score. Share-safe: the
# cover domain is shown only via reveal().
probe_xray_sni_privacy() {
  local sec net sni q=""
  sec=$(_xray_cfg_field security '.outbounds[0].streamSettings.security')
  net=$(_xray_cfg_field type     '.outbounds[0].streamSettings.network')
  sni=$(_xray_cover_sni)
  [ -z "$sni" ] && sni=$(_xray_cfg_field sni '.outbounds[0].streamSettings.tlsSettings.serverName')
  # share-link fallback when there's no JSON config
  if [ -n "$XRAY_CONFIG" ]; then
    case "$XRAY_CONFIG" in *\?*) q=${XRAY_CONFIG#*\?}; q=${q%%#*} ;; esac
    [ -z "$sec" ] && sec=$(_qp "$q" security)
    [ -z "$net" ] && net=$(_qp "$q" type)
    [ -z "$sni" ] && sni=$(_qp "$q" sni)
  fi
  [ -z "$net" ] && net=tcp
  if [ -z "$sni" ] || { [ "$sec" != "reality" ] && [ "$sec" != "tls" ]; }; then
    XRAY_SNIPRIV_STATUS="skipped"; return 0
  fi

  hdr "SNI privacy / ECH posture (advisory)"

  XRAY_SNIPRIV_CLEARTEXT=1
  local ech_applies
  if [ "$sec" = "reality" ]; then ech_applies=0; else ech_applies=1; fi
  XRAY_SNIPRIV_ECH_APPLIES="$ech_applies"

  # Only spend a DNS lookup where ECH could actually apply (a TLS transport).
  local ech_cover="unknown"
  [ "$ech_applies" = "1" ] && ech_cover=$(_ech_dns_probe "$sni")
  XRAY_SNIPRIV_ECH_COVER="$ech_cover"

  local _r code msg
  _r=$(_sni_privacy_advisory "$sec" "$ech_cover")
  code=${_r%%|*}; msg=${_r#*|}
  XRAY_SNIPRIV_CODE="$code"
  XRAY_SNIPRIV_STATUS="ok"

  info "SNI is sent in cleartext in the ClientHello$( [ "$sec" = "reality" ] && printf ' (Reality: that cover IS the mechanism)' )"
  case "$code" in
    reality)
      ok "cover-SNI model — ECH N/A; cover QUALITY (probe 26) is the lever, not encryption"
      info "$msg" ;;
    ech-available-unused)
      warn "the front already publishes an ECH config, yet the SNI is still sent in cleartext"
      add_verdict "SNI privacy (advisory): the endpoint's front publishes an Encrypted-ClientHello (ECH) config, but the client still sends the cover SNI in cleartext — a SNI-blocklist DPI (the cheap default: a national domain registry, or provider-level SNI blocking seen in some regions) can match it. Enabling ECH client-side removes the cleartext SNI entirely — the highest-leverage SNI fix for a TLS/WS-over-CDN transport. Not folded into the detectability score (ECH is a censor-/time-dependent tradeoff, like the uTLS fp)" ;;
    ech-unpublished)
      warn "SNI stays visible — the front does not offer ECH"
      info "$msg" ;;
    ech-unknown)
      info "$msg" ;;
    *) info "$msg" ;;
  esac
  if [ "$sec" != "reality" ] && [ "$ech_cover" != "1" ]; then
    reveal "front/cover serverName = \"$sni\" — its DNS shows no usable ECH config; to hide the SNI, front behind a provider that publishes ECH"
  fi
  # dialerProxy desync layer partially covers the cleartext SNI (it fragments the
  # ClientHello) — name that so ECH reads as belt-and-suspenders, not redundant.
  if [ "$sec" != "reality" ] && [ "$(_dialer_is_local_desync)" = "1" ]; then
    info "a client-side desync proxy is chained (dialerProxy) — it typically fragments the ClientHello so a DPI can't reassemble the cleartext SNI (the split-ClientHello evasion). That mitigates the SNI exposure IF the desync actually splits the SNI record; ECH removes it unconditionally, independent of the desync landing"
  fi
  info "advisory only — not scored (ECH adoption isn't universal and Reality forgoes it by design; probe 26 scores the cover-SNI quality that matters today)"
}

# Pure scorers for two probe-26 active signals, split out so the "don't score
# what you couldn't observe" rule is unit-testable without a live (un)reachable
# server. Each echoes "points|description".
#
# Cover certificate (probe 15). KEY: an UNREACHABLE cover means we never saw a
# cert — so it's UNVERIFIED (+5), not "authentic" (+0). The old code keyed only on
# the cert fields, so an unreachable cover fell through to "authentic, matches
# serverName" — a false-clean. Mirrors the +5 unverified path probes 20/24 use.
_score_cover_cert() {            # status selfsigned chainvalid cnmatch
  local st="$1" ss="${2:-0}" cv="${3:-1}" cn="${4:-1}" pts=0 desc=""
  if [ "$st" = "unreachable" ]; then
    printf '5|UNVERIFIED (cover unreachable — cert not seen)'; return
  fi
  if   [ "$ss" = "1" ]; then pts=40; desc="self-signed"
  elif [ "$cv" = "0" ]; then pts=15; desc="not CA-valid"; fi
  if [ "$cn" = "0" ]; then pts=$(( pts + 10 )); desc="${desc:+$desc + }CN≠serverName"; fi
  [ -z "$desc" ] && desc="authentic, matches serverName"
  printf '%d|%s' "$pts" "$desc"
}

# Active-probe behaviour (probe 20). KEY: "exposed" (relay-code=000, no coherent
# HTTP) is a +25 tell ONLY if the server's TLS was actually reachable. If the
# cover was unreachable too, the silence is the blackhole, not a relay refusal —
# so downgrade to UNVERIFIED (+5): you can't tell "won't relay" from "can't reach".
_score_active() {                # status cover_status nxnote
  local st="$1" cst="${2:-}" nx="${3:-}"
  case "$st" in
    ok)       printf '0|relays unauth probes to the real cover' ;;
    exposed)  if [ "$cst" = "unreachable" ]; then
                printf '5|UNVERIFIED (server unreachable — cannot tell relay-refusal from blackhole)'
              else printf '25|no coherent HTTP to an unauth prober'; fi ;;
    mismatch) printf '15|unauth response differs from cover' ;;
    no-baseline) printf '5|UNVERIFIED%s' "${nx:- (no genuine cover to baseline)}" ;;
    *)        printf '0|not evaluated (%s)' "${st:-skipped}" ;;
  esac
}

# SNI-privacy / ECH advisory (probe 27). Pure, so it's unit-testable like the
# scorers above. Echoes "code|message". Deliberately NOT scored — ECH adoption
# isn't universal and Reality forgoes it by design (same "tradeoff, not scored"
# treatment the uTLS fp gets in probe 26); this only names WHICH lever removes
# the cleartext-SNI exposure for THIS transport. Inputs:
#   sec       — streamSettings.security (reality | tls)
#   ech_cover — 1 | 0 | unknown : does the cover/front publish an ECH config (DNS)
_sni_privacy_advisory() {        # sec ech_cover
  local sec="$1" ech="${2:-unknown}"
  case "$sec" in
    reality)
      printf 'reality|SNI is cleartext BY DESIGN (Reality cover) — ECH does not apply; the mitigation is cover-SNI quality (probe 26). A SNI-inspecting DPI acts on the cover domain, so the cover must be popular AND not itself SNI-blocked in-region' ;;
    tls)
      case "$ech" in
        1) printf 'ech-available-unused|the front publishes an ECH config but the ClientHello still sends the SNI in cleartext — enabling ECH client-side removes the SNI tell entirely (an available-but-unused mitigation, like a missing vision flow)' ;;
        0) printf 'ech-unpublished|the front does NOT publish an ECH config, so the SNI stays visible in every ClientHello — front the endpoint behind a provider that offers ECH (e.g. a major CDN) to be able to hide it' ;;
        *) printf 'ech-unknown|could not determine whether the front publishes an ECH config (needs a modern dig HTTPS lookup or DoH) — treat the SNI as visible until confirmed' ;;
      esac ;;
    *)
      printf 'na|not a TLS/Reality outbound — no cleartext-SNI exposure to assess' ;;
  esac
}

# Best-effort: does <domain> publish an ECH config? Looks for the "ech=" SvcParam
# in an HTTPS/SVCB (type 65) record — dig (HTTPS then TYPE65), then a DoH-JSON
# fallback for where local dig is too old to format type 65. Echoes 1 (ech=
# present) / 0 (an HTTPS RR was formatted but carries no ech=) / unknown (couldn't
# tell). Never guesses ECH out of raw "\# <hex>" rdata — inconclusive stays unknown.
_ech_dns_probe() {               # domain
  local host="$1" rr="" ans=""
  if check_cmd dig; then
    rr=$( { dig +short -t HTTPS "$host" 2>/dev/null; dig +short -t TYPE65 "$host" 2>/dev/null; } )
    if printf '%s' "$rr" | grep -qi 'ech='; then echo 1; return; fi
    # A modern dig formats the SvcParams (alpn=/ipv4hint=…). Seeing those but no
    # ech= means the RR genuinely lacks ECH → 0. Raw "\# <hex>" from an old dig is
    # unreadable → don't guess; fall through to DoH / unknown.
    if printf '%s' "$rr" | grep -qiE 'alpn=|ipv4hint=|ipv6hint=|port=|mandatory='; then echo 0; return; fi
  fi
  if check_cmd curl; then
    ans=$(_curl "https://dns.google/resolve?name=${host}&type=HTTPS" 2>/dev/null)
    printf '%s' "$ans" | grep -qi 'ech=' && { echo 1; return; }
  fi
  echo unknown
}

# Cross-probe TEMPORAL synthesis (pure, so it's unit-testable). Did the tunnel
# carry real data EARLY (probe 12 up + a successful data-plane pull in 13/14) but
# then degrade on EVERY later sustained use (16 egress / 17 stability / 22
# bufferbloat)? That ordering — fast early, fails after the throughput pull — is
# the in-region signature of cumulative-VOLUME throttling, and it's the one such
# effect a single run can hint at, because the tool itself generates the load
# (probe 14 pulls up to ~50 MB) so there's a natural before/after-load boundary.
# Requires >=2 independent late degradations (one alone is too FP-prone). HEDGED
# and never scored: also consistent with transient congestion. Echoes 1 / 0.
# Args: json_status throughput_status speedtest_status egress_status stability_status bufferbloat_status
_volume_throttle_suspected() {
  local js="$1" tp="$2" sp="$3" eg="$4" st="$5" bb="$6" early_ok=0 n=0
  [ "$js" = "ok" ] || { printf 0; return; }              # tunnel must have worked
  case "$tp" in ok|throttled-severe|throttled-mild) early_ok=1 ;; esac  # 13 moved data
  [ "$sp" = "ok" ] && early_ok=1                          # or 14 pulled the big multi-stream
  [ "$early_ok" = "1" ] || { printf 0; return; }
  [ "$eg" = "no-data" ] && n=$(( n + 1 ))                 # 16: all egress lookups failed thru tunnel
  case "$st" in slow|killed|unstable) n=$(( n + 1 )) ;; esac  # 17: pulses degraded
  [ "$bb" = "no-data" ] && n=$(( n + 1 ))                 # 22: couldn't measure thru tunnel
  [ "$n" -ge 2 ] && printf 1 || printf 0
}

# Emits the volume-throttle advisory when the pattern holds. Advisory only — not
# folded into the detectability score; the cause is unproven, so it points at the
# disambiguating re-run rather than asserting a block.
probe_volume_synthesis() {
  [ "$XRAY_JSON_STATUS" = "ok" ] || return 0
  XRAY_VOLUME_THROTTLE_HINT=$(_volume_throttle_suspected \
    "$XRAY_JSON_STATUS" "$XRAY_THROUGHPUT_STATUS" "$XRAY_SPEEDTEST_STATUS" \
    "$XRAY_EGRESS_STATUS" "$XRAY_STABILITY_STATUS" "$XRAY_BUFFERBLOAT_STATUS")
  [ "$XRAY_VOLUME_THROTTLE_HINT" = "1" ] || return 0
  hdr "Cross-probe synthesis (load ordering)"
  warn "the tunnel carried data early (probes 12-14) but degraded on every later sustained use (egress / stability / bufferbloat) — ordering consistent with VOLUME-triggered throttling (a cumulative byte/time threshold crossed mid-run)"
  info "this is a HINT, not a verdict — equally consistent with transient congestion or a flaky egress. The tool generates the load itself (probe 14 pulls up to ~50 MB), so the 'after heavy pull' boundary is real, but the cause is not proven"
  info "disambiguate: re-run with a small pull — XRAY_SPEEDTEST_MAX_BYTES=2097152 and/or --no-speedtest. If the later probes then pass, it's volume-triggered; if they still fail, it's path congestion / server health"
  add_verdict "Possible volume-triggered throttling: the tunnel worked early (probes 12-14) then degraded on all later sustained use (egress/stability/bufferbloat) — a cumulative-load pattern a single clean vantage usually can't see. UNPROVEN (also consistent with transient congestion); re-run with a small XRAY_SPEEDTEST_MAX_BYTES / --no-speedtest to confirm"
}

# Probe 26 — detectability score. THE FINAL SYNTHESIS: folds every detection
# signal — ACTIVE probing (15 cover cert / 20 active-probe / 24 TLS parity) AND
# PASSIVE structure (cover served on a non-443 port; server IP not on the cover
# domain's network, i.e. SNI↔IP mismatch) — into one 0-100 fingerprintability
# score. Active tells weigh heaviest; passive tells are real but FP-prone for a
# censor at scale, so they weigh less individually — but when BOTH passive tells
# co-occur (the VLESS-Reality structural signature) the conjunction is bumped and
# named explicitly, since together it's low-FP even against a perfectly
# active-cloaked server. Always runs last.
probe_xray_detectability() {
  # Only meaningful when the stealth probes ran (a Reality config was present).
  case "$XRAY_COVER_STATUS" in ''|skipped) XRAY_DETECT_STATUS="skipped"; return 0 ;; esac

  hdr "26. Detectability score (active + passive synthesis)"

  local score=0

  # Resolve the cover SNI ONCE, up front. A non-resolving (self-cooked) SNI is
  # both a passive tell AND the single reason probes 20/24 and the SNI↔IP check
  # can't baseline — so every line that reads "not evaluated" can name the cause
  # instead of looking like the tool gave up.
  local sni sni_resolves="" nxnote=""
  sni=$(_xray_cover_sni)
  if [ -n "$sni" ]; then
    case "$sni" in
      *[!0-9.]*)  # a hostname (a bare-IP serverName is its own probe-18 lint)
        if [ -n "$(_resolve_a_records "$sni" 2>/dev/null | _first_word)" ] \
           || [ -n "$(_resolve_aaaa_records "$sni" 2>/dev/null | _first_word)" ]; then
          sni_resolves=1
        elif _dns_nxdomain "$sni"; then
          sni_resolves=0   # authoritative NXDOMAIN — a real tell, not a hiccup
        fi
        # else: lookup inconclusive (SERVFAIL/timeout/no dig) → leave "" (don't flag)
        ;;
    esac
  fi
  XRAY_PASSIVE_SNI_RESOLVES="$sni_resolves"
  [ "$sni_resolves" = "0" ] && nxnote=" — cover SNI is NXDOMAIN"

  # Each input is scored AND described, so the total is explainable even at 0.
  # --- cover certificate (probe 15) --- (UNVERIFIED +5 when the cover was
  # unreachable: a cert we never saw must NOT default to "authentic").
  local cover_pts cover_desc _r
  _r=$(_score_cover_cert "$XRAY_COVER_STATUS" "${XRAY_COVER_SELFSIGNED:-0}" "${XRAY_COVER_CHAIN_VALID:-1}" "${XRAY_COVER_CN_MATCH:-1}")
  cover_pts=${_r%%|*}; cover_desc=${_r#*|}
  score=$(( score + cover_pts ))

  # --- active-probe behaviour (probe 20) --- ("couldn't baseline"/no-baseline and
  # "exposed-but-server-unreachable" both score a small UNVERIFIED risk, not a
  # confirmed +25 tell: an unconfirmed/unobservable stealth dimension is an open
  # risk, not a clean pass and not proof. A missing local tool stays +0.)
  local active_pts active_desc
  _r=$(_score_active "$XRAY_ACTIVE_STATUS" "$XRAY_COVER_STATUS" "$nxnote")
  active_pts=${_r%%|*}; active_desc=${_r#*|}
  score=$(( score + active_pts ))

  # --- TLS-negotiation parity (probe 24) ---
  local tls_pts=0 tls_desc
  case "$XRAY_TLSPAR_STATUS" in
    ok)          tls_desc="version+ALPN+cipher match cover" ;;
    mismatch)    tls_pts=15; tls_desc="negotiation differs from cover" ;;
    unreachable) tls_pts=5;  tls_desc="UNVERIFIED${nxnote:- (cover unreachable)}" ;;
    unverified)  tls_pts=5;  tls_desc="UNVERIFIED (openssl reported no fields)" ;;
    *)           tls_desc="not evaluated (${XRAY_TLSPAR_STATUS:-skipped})" ;;
  esac
  score=$(( score + tls_pts ))

  # --- passive structure: non-443 port + SNI↔IP network (no active probe) ---
  # Weighted low: real tells, but FP-prone for a censor at scale (legit CDN /
  # domain fronting mismatches too), so they rarely block on them alone.
  local port_pts=0 port_desc
  if [ "$VPN_PORT_TCP" = "443" ]; then
    XRAY_PASSIVE_PORT_STD=1; port_desc="standard (443)"
  else
    XRAY_PASSIVE_PORT_STD=0; port_pts=10; port_desc="non-standard (real cover sites use 443)"
  fi
  score=$(( score + port_pts ))

  local sni_pts=0 sni_desc="not evaluated" srv_ip cov_ips srv_asn cov_asn on_net=""
  [ "$sni_resolves" = "0" ] && sni_desc="not evaluated${nxnote} (see SNI quality)"
  if [ -n "$sni" ] && [ "$sni_resolves" != "0" ] && check_cmd curl; then
    srv_ip=$(_resolve_a_records "$VPN_HOST" 2>/dev/null | _first_word)
    cov_ips=$(_resolve_a_records "$sni" 2>/dev/null | _join_words)
    # (1) DNS membership — no external API, so it survives ASN-lookup rate
    #     limits: if the cover domain actually resolves to THIS server IP, the
    #     server legitimately fronts it → definitively on-network.
    if [ -n "$srv_ip" ] && [ -n "$cov_ips" ]; then
      case " $cov_ips " in *" $srv_ip "*) on_net=1 ;; esac
    fi
    # (2) Else decide by ASN — covers the large-CDN case where the exact edge IP
    #     differs but the network is the same (so a DNS miss alone would FP).
    #     ASN undetermined → leave unknown (don't flag; avoids FP under rate limits).
    if [ -z "$on_net" ] && [ -n "$srv_ip" ]; then
      srv_asn=$(_asn_of "$srv_ip")
      cov_asn=$(_asn_of "$(printf '%s' "$cov_ips" | _first_word)")
      if [ -n "$srv_asn" ] && [ -n "$cov_asn" ]; then
        if [ "$srv_asn" = "$cov_asn" ]; then on_net=1; else on_net=0; fi
      fi
    fi
    case "$on_net" in
      1) XRAY_PASSIVE_ASN_MATCH=1; sni_desc="server IP on the cover's network" ;;
      0) XRAY_PASSIVE_ASN_MATCH=0; sni_pts=10; sni_desc="server IP NOT on the cover's network (SNI↔IP mismatch)" ;;
    esac
  fi
  score=$(( score + sni_pts ))

  # --- cover-SNI quality (cheap, low-FP; a perfect cert can't fix these) ---
  # A Reality cover should be a real, popular third-party domain so the cleartext
  # SNI a censor sees looks innocuous and high-value. Two tells a valid cert
  # cannot mask — and this is also WHY probes 20/24 go "not evaluated" on a
  # self-cooked cover: there's no genuine site to baseline against.
  #   (a) the SNI does not publicly resolve (NXDOMAIN) → not a site you hide
  #       behind; a censor resolving the cleartext SNI learns that instantly;
  #   (b) the SNI carries a circumvention/antagonistic keyword → sent in
  #       cleartext in every ClientHello, so a keyword-matching DPI flags it.
  local sniq_pts=0 sniq_desc="real-looking" sni_lc=""
  XRAY_PASSIVE_SNI_KEYWORD=0
  if [ -n "$sni" ]; then
    # (a) non-resolving cover SNI — only a confirmed NXDOMAIN (computed up top),
    #     never a transient/geo-DNS miss. A soft tell: it only bites a censor
    #     that actively resolves SNIs, unlike the keyword below which a passive
    #     blocklist matches directly.
    if [ "$sni_resolves" = "0" ]; then
      sniq_pts=$(( sniq_pts + 10 ))
      sniq_desc="NXDOMAIN (self-cooked SNI — soft tell)"
    fi
    # (b) circumvention/antagonistic keyword in the cleartext SNI (see _sni_keyword_hit).
    if [ "$(_sni_keyword_hit "$sni")" = "1" ]; then
      XRAY_PASSIVE_SNI_KEYWORD=1; sniq_pts=$(( sniq_pts + 10 ))
      case "$sniq_desc" in
        real-looking) sniq_desc="contains a circumvention keyword (cleartext SNI)" ;;
        *)            sniq_desc="$sniq_desc + circumvention keyword" ;;
      esac
    fi
    # (c) cover popularity: a good Reality cover is a popular site on a major CDN
    #     (blocking it costs the censor collateral). A cover that resolves to a
    #     hosting/VPS network is self-owned / obscure — low collateral to block,
    #     and often a brand/operator domain → a detectability tell AND a provider
    #     identifier. Skipped for a non-resolving/keyword SNI (already flagged).
    if [ "$sni_resolves" = "1" ] && [ "${XRAY_PASSIVE_SNI_KEYWORD:-0}" != "1" ] \
       && [ -n "${cov_ips:-}" ] && check_cmd curl; then
      local cov_ip1 cov_info cov_dc=""
      cov_ip1=$(printf '%s' "$cov_ips" | _first_word)
      # HTTPS-first for the cover's org (the CDN-keyword match); ip-api (HTTP) only
      # as a fallback — see _asn_of on why plaintext reputation is MITM-spoofable.
      cov_info=$(curl -sS --max-time "$TIMEOUT" "https://ipinfo.io/${cov_ip1}/json" 2>/dev/null)
      [ -z "$cov_info" ] && cov_info=$(curl -sS --max-time "$TIMEOUT" "http://ip-api.com/json/${cov_ip1}?fields=status,hosting,org,isp,as" 2>/dev/null)
      if printf '%s' "$cov_info" | tr '[:upper:]' '[:lower:]' | grep -qiE 'cloudflare|akamai|fastly|google|amazon|aws|cloudfront|microsoft|azure|apple|edgecast|verizon|limelight|lumen|level ?3|g.?core|bunny|stackpath|cdn77|incapsula|sucuri|netlify|vercel|github'; then
        XRAY_PASSIVE_COVER_OBSCURE=0   # popular CDN/cloud cover — blends, good
      else
        # Not a major CDN. Is it a hosting/datacenter network? Use the flags
        # (ip-api hosting, then ipapi.is is_datacenter) — org-keyword alone misses
        # small hosts an org-keyword list misses, the v0.9.1 lesson.
        if printf '%s' "$cov_info" | grep -q '"hosting":true'; then cov_dc=1
        else cov_dc=$(curl -sS --max-time "$TIMEOUT" "${XRAY_EGRESS_DC_URL}?q=${cov_ip1}" 2>/dev/null \
              | jq -r 'if (.is_datacenter==true) or ((((.asn.type // .company.type) // "")|ascii_downcase)|test("hosting")) then 1 else 0 end' 2>/dev/null); fi
        if [ "$cov_dc" = "1" ]; then
          XRAY_PASSIVE_COVER_OBSCURE=1; sniq_pts=$(( sniq_pts + 10 ))
          case "$sniq_desc" in
            real-looking) sniq_desc="self-owned/obscure cover (resolves to a hosting network, not a popular CDN site)" ;;
            *)            sniq_desc="$sniq_desc + obscure cover" ;;
          esac
        fi
      fi
    fi
    # --reveal: show the operator the actual offending serverName (terminal only).
    [ "$sniq_pts" -gt 0 ] && reveal "cover serverName = \"$sni\" — the cleartext SNI flagged above; replace with a real, popular, resolving third-party domain (one on a major CDN)"
  fi
  score=$(( score + sniq_pts ))

  # --- uTLS fingerprint (JA3) — a TRADEOFF, deliberately NOT scored ---
  # Reality mimics a browser's ClientHello via uTLS, and the fp choice cuts both
  # ways depending on the censor's model:
  #   - SIGNATURE / deny-list (what TSPU does to Reality): it blocklists known
  #     circumvention JA3s, and `chrome` is the near-universal default → the
  #     most-signatured, most-blocked. A rare/regional fp (qq, 360) is NOT on the
  #     list → it EVADES. Rarity is the feature here.
  #   - ANOMALY / allow-list: flags anything that isn't a common browser, so a
  #     rare fp is a JA3 OUTLIER → more visible.
  # The operator's empirical result against the TARGET censor is authoritative,
  # so we report the fp and fold it into the deployment fingerprint (it still
  # IDENTIFIES the deployment), but add NO points either way.
  local fp_pts=0 fp_desc utls_fp
  utls_fp=$(_xray_utls_fp)
  XRAY_PASSIVE_UTLS_FP="$utls_fp"
  case "$utls_fp" in
    qq|360)
      XRAY_PASSIVE_UTLS_RARE=1
      fp_desc="'${utls_fp}' regional/uncommon — evades signature blocklists (e.g. TSPU), JA3/JA4 outlier to anomaly detection (tradeoff, not scored)" ;;
    ""|chrome|firefox|safari|ios|android|edge|random|randomized|randomizedalpn|randomizednoalpn)
      XRAY_PASSIVE_UTLS_RARE=0
      fp_desc="${utls_fp:-unset} — common/randomized (chrome is the most-signatured circumvention fp)" ;;
    *)
      XRAY_PASSIVE_UTLS_RARE=1
      fp_desc="'${utls_fp}' non-standard JA3 (tradeoff, not scored)" ;;
  esac
  score=$(( score + fp_pts ))

  # --- passive conjunction: the Reality structural signature ---
  # Either passive tell alone is FP-prone (legit services use 8443; domain
  # fronting legitimately mismatches ASN). TOGETHER — presenting an SNI for a
  # domain that lives on a different network AND serving it on a non-standard
  # port — is a recognized VLESS-Reality fingerprint a passive censor can match
  # with low FP, even against a server that defeats every active probe. Bump it
  # modestly and, more importantly, name it.
  local conj_pts=0 conj_desc="no"
  if [ "${XRAY_PASSIVE_PORT_STD:-1}" = "0" ] && [ "${XRAY_PASSIVE_ASN_MATCH:-1}" = "0" ]; then
    XRAY_PASSIVE_FP_STRONG=1; conj_pts=10
    conj_desc="yes — borrowed SNI on a non-standard port"
  else
    XRAY_PASSIVE_FP_STRONG=0
  fi
  score=$(( score + conj_pts ))

  # --- TLS-in-TLS exposure: VLESS-Reality without xtls-rprx-vision (SCORED) ---
  # The most advanced censors' marquee PASSIVE attack detects TLS-in-TLS: when an
  # HTTPS site is proxied, the inner TLS records carry a length/timing signature
  # visible INSIDE the outer Reality TLS. flow=xtls-rprx-vision splices/pads the
  # stream to erase it; REALITY with a non-XTLS (non-vision) flow is officially
  # discouraged for exactly this. Detected statically from flow/transport — no
  # tshark needed: we detect the MITIGATION, not the packet signature. NOT a
  # tradeoff like the uTLS fp — vision is near-universally correct, so it scores.
  local vis_pts=0 vis_desc="n/a (not a REALITY / VLESS-Encryption proxy)" v_sec v_net v_flow v_mux v_encmode=""
  v_sec=$(_xray_cfg_field security '.outbounds[0].streamSettings.security')
  v_net=$(_xray_cfg_field type     '.outbounds[0].streamSettings.network')
  v_flow=$(_xray_cfg_field flow    '.outbounds[0].settings.vnext[0].users[0].flow')
  [ -z "$v_net" ] && v_net=tcp
  # VLESS Encryption (Xray 2025+) lifts vision's raw-TCP restriction — vision runs
  # on ANY transport when it's present (the VLESSENC + XHTTP + vision frontier).
  case "${XRAY_VLESS_ENC:-}" in native|xorpub|random) v_encmode=1 ;; esac
  if [ "$v_sec" = "reality" ] || [ "$v_encmode" = "1" ]; then
    # Match the whole vision FAMILY, not just the bare value: xtls-rprx-vision-udp443
    # (which additionally lets UDP/443 through) splices/pads the stream against
    # TLS-in-TLS identically, so an exact "= xtls-rprx-vision" test wrongly reads a
    # valid -udp443 config as "no vision" and over-scores +15.
    case "$v_flow" in
      xtls-rprx-vision|xtls-rprx-vision-udp443)
        XRAY_PASSIVE_VISION=1
        if [ "$v_encmode" = "1" ] && [ "$v_net" != "tcp" ] && [ "$v_net" != "raw" ]; then
          vis_desc="${v_flow} over ${v_net} via VLESS Encryption (anti TLS-in-TLS)"
        else
          vis_desc="${v_flow} present (anti TLS-in-TLS)"
        fi ;;
      *)
      case "$v_net" in
        tcp|raw)
          if [ "$v_sec" = "reality" ]; then
            # Raw TCP + REALITY and no vision = a clear, available mitigation unused.
            XRAY_PASSIVE_VISION=0; vis_pts=15
            vis_desc="no vision flow on REALITY+TCP — TLS-in-TLS exposure"
          else
            # VLESS Encryption on raw TCP, no vision: no outer TLS, so the classic
            # TLS-in-TLS length signature doesn't apply — vision would still add
            # inner-handshake padding. Advisory, not scored.
            XRAY_PASSIVE_VISION=2
            vis_desc="VLESS Encryption on raw TCP, no vision — inner-handshake padding available (not scored)"
          fi ;;
        *)
          # Non-raw transport. Without VLESS Encryption, REALITY can't use vision —
          # a censor-dependent TRADEOFF, not scored (the fp=qq lesson; XTLS #2593).
          # WITH VLESS Encryption, vision IS available here (encryption lifts the
          # raw-TCP limit) but isn't enabled — still not scored (no outer-TLS
          # TLS-in-TLS to erase). State 2 → JSON tls_in_tls_protected:null.
          XRAY_PASSIVE_VISION=2
          if [ "$v_encmode" = "1" ]; then
            vis_desc="VLESS Encryption over ${v_net}, no vision — vision is available (encryption lifts the raw-TCP limit), not scored"
          else
            vis_desc="REALITY over ${v_net} — vision N/A on a non-raw transport (tradeoff, not scored)"
          fi ;;
      esac
      ;;
    esac
  fi
  score=$(( score + vis_pts ))
  # mux.cool state (traffic-shape note, not scored): generally unnecessary with
  # vision and adds a correlation/shape surface — folded into the suggestion.
  v_mux=$(_xray_cfg_field _nourl '.outbounds[0].mux.enabled')
  case "$v_mux" in true|1) XRAY_TRANSPORT_MUX=1 ;; false|0) XRAY_TRANSPORT_MUX=0 ;; *) XRAY_TRANSPORT_MUX="" ;; esac

  [ "$score" -gt 100 ] && score=100
  XRAY_DETECT_SCORE="$score"
  if   [ "$score" -ge 70 ]; then XRAY_DETECT_BAND="critical"
  elif [ "$score" -ge 40 ]; then XRAY_DETECT_BAND="high"
  elif [ "$score" -ge 15 ]; then XRAY_DETECT_BAND="moderate"
  else XRAY_DETECT_BAND="low"; fi
  XRAY_DETECT_STATUS="ok"

  # Component breakdown — always shown, so the score is never a black box.
  info "$(printf 'active · cover cert (15):   %-38s +%d' "$cover_desc" "$cover_pts")"
  info "$(printf 'active · active-probe (20): %-38s +%d' "$active_desc" "$active_pts")"
  info "$(printf 'active · TLS parity (24):   %-38s +%d' "$tls_desc" "$tls_pts")"
  info "$(printf 'passive · port:             %-38s +%d' "$port_desc" "$port_pts")"
  info "$(printf 'passive · SNI↔IP network:   %-38s +%d' "$sni_desc" "$sni_pts")"
  info "$(printf 'passive · SNI quality:      %-38s +%d' "$sniq_desc" "$sniq_pts")"
  info "$(printf 'passive · uTLS fp (JA3):    %-38s +%d' "$fp_desc" "$fp_pts")"
  info "$(printf 'passive · conjunction:      %-38s +%d' "$conj_desc" "$conj_pts")"
  info "$(printf 'passive · TLS-in-TLS:       %-38s +%d' "$vis_desc" "$vis_pts")"
  info "bands: 0-14 low · 15-39 moderate · 40-69 high · 70-100 critical"

  if [ "$score" -ge 40 ]; then
    fail "detectability ${score}/100 (${XRAY_DETECT_BAND}) — a censor would flag this server"
    add_verdict "Detectability ${score}/100 (${XRAY_DETECT_BAND}) — active and/or passive signals combine into a strong fingerprint. Fix the cover relay (real 'dest'/'serverNames'), serve on 443, and pick a cover on a large shared CDN; see the breakdown for which signals fired"
  elif [ "$score" -ge 15 ]; then
    warn "detectability ${score}/100 (${XRAY_DETECT_BAND}) — partially fingerprintable; see the breakdown above"
    add_verdict "Detectability ${score}/100 (${XRAY_DETECT_BAND}) — active probing may be clean, but passive structure (port / SNI↔IP) still leaves a fingerprint. These are FP-prone for a censor at scale, but a targeted check catches them: serve on 443 and choose a cover hosted on a large shared CDN"
  else
    ok "detectability ${score}/100 (${XRAY_DETECT_BAND}) — every active and passive check passed, blends in"
  fi

  # Name it: when both passive tells co-occur, the output should say plainly
  # what the structure is — even at a "moderate" score the conjunction is a
  # recognized VLESS-Reality signature, not two unrelated nitpicks.
  if [ "${XRAY_PASSIVE_FP_STRONG:-0}" = "1" ]; then
    warn "passive Reality/Xray fingerprint: borrowed SNI (cover lives on another network) + non-standard port"
    add_verdict "Passive Reality/Xray fingerprint detected: the server presents an SNI for a domain hosted on a different network AND serves it on a non-standard port. Each tell alone is FP-prone, but the conjunction is a recognized structural signature of VLESS-Reality that a passive censor can match with low FP — no active probe needed, even though every active check here passed. To blend in, serve on 443 and choose a cover domain hosted on the same network as the server (or a large shared CDN)"
  fi

  # Name a weak cover SNI: the serverName is sent in cleartext in every
  # ClientHello, so a valid cert can't hide a self-cooked or keyword-bearing
  # name — and it's also why the active baselines (20/24) couldn't evaluate.
  if [ "${XRAY_PASSIVE_SNI_KEYWORD:-0}" = "1" ] || [ "${XRAY_PASSIVE_SNI_RESOLVES:-1}" = "0" ]; then
    warn "cover SNI quality: $sniq_desc — the cleartext serverName is the weak link, not the cert"
    if [ "${XRAY_PASSIVE_SNI_KEYWORD:-0}" = "1" ]; then
      add_verdict "Reality cover SNI carries a circumvention/antagonistic keyword, sent in cleartext in every ClientHello — a passive SNI-blocklist DPI (the cheap, default method, e.g. RKN) matches and blocks it on sight, no DNS lookup or active probe needed. A valid cert can't hide it. This is the severe one. Use a real, popular third-party domain that looks innocuous as the Reality cover"
    fi
    if [ "${XRAY_PASSIVE_SNI_RESOLVES:-1}" = "0" ]; then
      add_verdict "Reality cover SNI is NXDOMAIN (it doesn't publicly resolve) — a softer tell: it only bites a censor that actively resolves the SNIs it sees (not the cheap default), but it does mean the cover isn't a real site you blend into, and it's why the active-probe/TLS-parity baselines went 'not evaluated' (no genuine cover to compare against). Prefer a real, resolving cover domain"
    fi
  fi

  # Self-owned / obscure cover — resolves, no keyword, but lives on a hosting/VPS
  # network rather than a major CDN: low collateral for a censor to block, and
  # often a brand/operator domain (so it also identifies the deployment).
  if [ "${XRAY_PASSIVE_COVER_OBSCURE:-0}" = "1" ]; then
    warn "cover SNI is self-owned/obscure — resolves to a hosting/VPS network, not a popular CDN site"
    add_verdict "Reality cover resolves to a hosting/VPS network rather than a major CDN — it's a self-owned or obscure cover, not a popular third-party site. A censor can blocklist it with little collateral damage (unlike blocking a big CDN domain), and a self-owned cover often names the operator (a provider tell). Borrow a genuinely popular domain hosted on a large shared CDN (Cloudflare/Akamai/Fastly/Google/Amazon/Microsoft) as the Reality cover"
  fi

  # TLS-in-TLS exposure (vision absent) — the most advanced censors' marquee
  # passive detector. Folds in the traffic-shape advice (XHTTP+padding when
  # vision can't apply; disable mux with vision).
  if [ "${XRAY_PASSIVE_VISION:-}" = "0" ]; then
    warn "TLS-in-TLS exposure: VLESS-Reality without xtls-rprx-vision — advanced censors (e.g. the GFW) detect this passively"
    add_verdict "VLESS-Reality without flow=\"xtls-rprx-vision\" → TLS-in-TLS exposure: when an HTTPS site is proxied, the inner TLS records carry a length/timing signature visible inside the outer Reality TLS, which advanced censors detect passively (REALITY with a non-XTLS flow is officially discouraged for this reason). Set the user 'flow' to \"xtls-rprx-vision\" on BOTH client and server (it requires raw TCP transport, network=tcp/raw). If you must use a CDN-frontable transport (ws/grpc/xhttp) where vision can't apply, prefer XHTTP with padding to blunt the traffic-shape signature$( [ "${XRAY_TRANSPORT_MUX:-}" = "1" ] && printf '%s' '; and disable mux.cool — with vision it is unnecessary and adds a correlation surface' )"
  elif [ "${XRAY_PASSIVE_VISION:-}" = "2" ] && [ "${v_encmode:-}" = "1" ]; then
    info "VLESS Encryption lifts vision's raw-TCP restriction, so vision CAN run on ${v_net} here — it isn't enabled, but with VLESS Encryption there's no outer-TLS TLS-in-TLS signature to erase; vision would add inner-handshake random padding. Not scored."
  elif [ "${XRAY_PASSIVE_VISION:-}" = "2" ]; then
    info "REALITY over ${v_net}: vision (anti-TLS-in-TLS) only works on raw TCP, so it's N/A here — a tradeoff, not a flaw. An HTTP-framed transport (gRPC/XHTTP) is often LESS targeted than raw+vision against current censors, though it's censor- and time-dependent (no consensus; XTLS #2593). For raw TCP, vision stays the recommended anti-TLS-in-TLS choice; on gRPC/XHTTP, padding is the lever instead. Not scored."
  elif [ "${XRAY_PASSIVE_VISION:-}" = "1" ] && [ "${XRAY_TRANSPORT_MUX:-}" = "1" ]; then
    info "mux.cool is enabled alongside vision — most REALITY+vision setups leave mux off (vision handles flow shaping; mux adds overhead and a correlation surface)"
  fi

  # Uncommon uTLS fingerprint — reported as a TRADEOFF, not a tell (not scored).
  # It's still a per-deployment constant, so it identifies the deployment (and is
  # in the fingerprint hash) even though it doesn't move the score.
  if [ "${XRAY_PASSIVE_UTLS_RARE:-0}" = "1" ]; then
    info "uTLS fp '$utls_fp' is a JA3/JA4 tradeoff, NOT scored: a rare/regional fp EVADES signature/deny-list censors (TSPU blocklists the common chrome-uTLS-Reality JA3 — why qq often works there) but is an outlier to anomaly detection. Your result against the target censor decides; it stays in the deployment fingerprint either way"
    info "note: JA4 (the JA3 successor) SORTS the cipher/extension lists, so the extension-shuffling that broke naive JA3 matching no longer hides a rare fp; and whatever fp you pick, the client must reproduce that browser's FULL ClientHello (extension order, GREASE) — a proxy that tweaks the ClientHello or normalizes HTTP headers breaks JA4 parity and is detectable as a Go proxy (XTLS #4900)"
    reveal "uTLS fingerprint = $utls_fp"
  fi

  # ---- Deployment fingerprint: a stable, share-safe signature of the config's
  # identifying shape, so the SAME provider/template is recognizable across nodes
  # (different IP/keys/SNI, same fingerprint). Hashes only structural constants —
  # never the IP, UUID, keys, or cover domain — so it's safe to share/compare.
  if check_cmd openssl; then
    local _proto _net _flow _sidlen _routesig _canon
    _proto=$(_xray_cfg_field protocol '.outbounds[0].protocol')
    _net=$(_xray_cfg_field network '.outbounds[0].streamSettings.network'); [ -z "$_net" ] && _net=tcp
    _flow=$(_xray_cfg_field flow '.outbounds[0].settings.vnext[0].users[0].flow')
    _sidlen=$(_xray_cfg_field sid '.outbounds[0].streamSettings.realitySettings.shortId'); _sidlen=${#_sidlen}
    # routing signature: sorted unique match-type:outboundTag shapes + domain-set
    # size — the curated routing recipe, a strong per-provider signal.
    _routesig=""
    if [ -n "$XRAY_JSON_CONFIG" ] && [ -r "$XRAY_JSON_CONFIG" ] && command -v jq >/dev/null 2>&1; then
      _routesig=$(jq -r '
        [ .routing.rules[]? | "\(if .domain then "d" else "" end)\(if .ip then "i" else "" end)\(if .protocol then "p" else "" end)\(if .network then "n" else "" end)>\(.outboundTag // "")" ] | sort | join(",")
        + "|dn=" + ([ .routing.rules[]? | (.domain // [])[] ] | length | tostring)
      ' "$XRAY_JSON_CONFIG" 2>/dev/null)
    fi
    _canon="${_proto}|sec=$(_xray_cfg_field security '.outbounds[0].streamSettings.security')|net=${_net}|flow=${_flow}|fp=${utls_fp}|sidlen=${_sidlen}|port=${VPN_PORT_TCP}|route=${_routesig}"
    XRAY_DEPLOY_FINGERPRINT=$(printf '%s' "$_canon" | openssl dgst -sha256 2>/dev/null | sed -nE 's/.*([0-9a-f]{64}).*/\1/p' | cut -c1-12)
    [ -n "$XRAY_DEPLOY_FINGERPRINT" ] && info "deployment fingerprint: ${XRAY_DEPLOY_FINGERPRINT} (stable across nodes of the same provider/template — match it to recognize this deployment)"
    # The fingerprint hashes the config TEMPLATE/shape, not the server's health —
    # a sibling node with the SAME fingerprint can score very differently if its
    # server-side cover relay (probes 15/20) is misconfigured. Flag that when this
    # node scores high, so a matching fingerprint isn't read as a clean bill.
    if [ -n "$XRAY_DEPLOY_FINGERPRINT" ] && [ "$score" -ge 40 ]; then
      info "note: the deployment fingerprint identifies the config TEMPLATE, not its health — a sibling node of the same template/fingerprint can be clean while THIS one scores ${score} (here the active probes 15/20 are what diverge); match fingerprints to cluster a fleet, but score each node on its own"
    fi
    reveal "fingerprint canonical: ${_canon}"
  fi
}

# Echo the ASN ("AS<number>") of an IP, via ip-api (HTTP) then ipinfo (HTTPS).
# Direct lookup (not through the tunnel) — used to compare networks.
_asn_of() {
  local ip="$1" a=""
  [ -n "$ip" ] || return 0
  # HTTPS-first (MITM-resistant): an on-path adversary — the censor we're profiling —
  # could spoof a plaintext ip-api response and skew the SNI↔IP ASN comparison.
  # ip-api (HTTP) stays only as a fallback (its free tier is HTTP-only).
  a=$(curl -sS --max-time "$TIMEOUT" "https://ipinfo.io/${ip}/json" 2>/dev/null \
      | sed -nE 's/.*"org":[[:space:]]*"(AS[0-9]+).*/\1/p' | head -1)
  [ -z "$a" ] && a=$(curl -sS --max-time "$TIMEOUT" "http://ip-api.com/json/${ip}?fields=as" 2>/dev/null \
      | sed -nE 's/.*"as":"(AS[0-9]+).*/\1/p' | head -1)
  printf '%s' "$a"
}

probe_ipv6() {
  hdr "9. IPv6 reachability"

  local aaaa first_v6 https_code
  aaaa=$(_resolve_aaaa_records "$VPN_HOST" | _join_words)
  IPV6_AAAA="$aaaa"

  if [ -z "$aaaa" ]; then
    info "no AAAA records for $VPN_HOST – host is IPv4-only"
    return
  fi

  info "AAAA records: $aaaa"
  first_v6=$(printf '%s\n' "$aaaa" | _first_word)

  if _nc6_tcp_probe "$first_v6" "$VPN_PORT_TCP"; then
    ok "IPv6 TCP $VPN_PORT_TCP reachable via [$first_v6]"
    IPV6_TARGET_OK=1
  else
    fail "IPv6 TCP $VPN_PORT_TCP unreachable via [$first_v6]"
    IPV6_TARGET_OK=0
    # If IPv4 also failed, that's broader. If IPv4 worked but v6 failed,
    # may be a v6 routing issue, not a block.
    if [ "$TCP_OK" = "0" ]; then
      add_verdict "IPv6 transport also unreachable — both stacks blocked / down"
    fi
    return
  fi

  # Also try HTTPS over v6 (the resolver hint in --resolve uses [host:port:ip])
  https_code=$(curl -sk --max-time "$TIMEOUT" -6 \
    --resolve "$VPN_HOST:$VPN_PORT_TCP:$first_v6" \
    -o /dev/null -w '%{http_code}' \
    "$(_target_https_url)" 2>/dev/null || echo "000")
  [ -n "$https_code" ] || https_code="000"
  IPV6_HTTPS_CODE="$https_code"

  if [ "$https_code" = "000" ]; then
    fail "IPv6 HTTPS request failed — TLS handshake or response blocked on v6"
    add_verdict "IPv6 HTTPS layer blocked while v6 TCP reachable"
  else
    info "IPv6 HTTPS: HTTP $https_code"

    # If IPv4 was blocked but IPv6 works — strong signal: IPv4-only DPI/IP block.
    if [ "$TCP_OK" = "0" ]; then
      ok "IPv6 path works while IPv4 is blocked — switch to v6-preferred client"
      add_verdict "IPv4 blocked but IPv6 reachable — prefer v6 transport"
    fi
  fi
}

# ---------- JSON emitter (--json mode) ----------

_emit_json() {
  local verdicts_json="[]"
  if [ "${#VERDICTS[@]}" -gt 0 ]; then
    verdicts_json=$(printf '%s\n' "${VERDICTS[@]}" | jq -R . | jq -sc .)
  fi

  jq -n \
    --arg version           "$DETECT_BLOCKING_VERSION" \
    --arg host              "$VPN_HOST" \
    --argjson port_tcp      "$VPN_PORT_TCP" \
    --argjson port_udp      "$VPN_PORT_UDP" \
    --arg resolved_ip       "$RESOLVED_IP" \
    --arg resolved_source   "$RESOLVED_SOURCE" \
    --arg env_default_if    "$ENV_DEFAULT_IF" \
    --arg run_label         "${RUN_LABEL:-}" \
    --arg wl_status         "${WHITELIST_STATUS:-}" \
    --arg wl_perm_ok        "${WHITELIST_PERMITTED_OK:-}" \
    --arg wl_ctl_ok         "${WHITELIST_CONTROL_OK:-}" \
    --arg env_vpn_ifs       "$ENV_VPN_IFACES" \
    --arg env_connected     "$ENV_CONNECTED_VPN" \
    --argjson env_on_vpn    "${ENV_ON_VPN:-0}" \
    --arg dns_sys_ips       "$DNS_SYS_IPS" \
    --arg dns_doh_ips       "$DNS_DOH_IPS" \
    --arg dns_diverge_class "${DNS_DIVERGE_CLASS:-}" \
    --argjson dns_block_j   "${DNS_BLOCK:-0}" \
    --arg doh_state         "$DOH_INTEGRITY_STATE" \
    --arg doh_ips           "$DOH_INTEGRITY_IPS" \
    --arg dot_state         "$DOT_INTEGRITY_STATE" \
    --arg dot_ips           "$DOT_INTEGRITY_IPS" \
    --arg doh_multi         "$DOH_MULTI_RESULTS" \
    --argjson doh_multi_ok  "${DOH_MULTI_OK:-0}" \
    --argjson doh_multi_bad "${DOH_MULTI_COMPROMISED:-0}" \
    --argjson doh_multi_off "${DOH_MULTI_UNREACHABLE:-0}" \
    --argjson tcp_baseline  "${TCP_BASELINE_OK:-0}" \
    --arg tcp_baseline_ip   "$TCP_BASELINE_IP" \
    --argjson tcp_target    "${TCP_OK:-0}" \
    --arg tcp_target_icmp   "$TARGET_ICMP_OK" \
    --argjson tls_proper    "${TLS_PROPER_SNI_OK:-0}" \
    --argjson tls_no_sni    "${TLS_NO_SNI_OK:-0}" \
    --argjson tls_fake      "${TLS_FAKE_SNI_OK:-0}" \
    --argjson tls_frag      "${TLS_FRAG_SNI_OK:--1}" \
    --arg ua_default        "$UA_DEFAULT_CODE" \
    --arg ua_chrome         "$UA_CHROME_CODE" \
    --arg ua_impersonate    "$UA_IMPERSONATE_CODE" \
    --arg ua_impersonate_bin "$UA_IMPERSONATE_BIN" \
    --arg rst_elapsed       "$RST_ELAPSED" \
    --argjson rst_hs        "${RST_HS_OK:-0}" \
    --argjson rst_rc        "${RST_RC:-0}" \
    --argjson udp_ike500    "${UDP_IKE500_OK:-0}" \
    --argjson udp_ike4500   "${UDP_IKE4500_OK:-0}" \
    --arg udp_quic          "$UDP_QUIC_CODE" \
    --arg udp_quic_base     "$UDP_QUIC_BASELINE" \
    --arg udp_quic_target   "$UDP_QUIC_TARGET" \
    --arg udp_quic_verdict  "$UDP_QUIC_VERDICT" \
    --argjson openvpn_udp   "${OPENVPN_UDP_OK:-0}" \
    --argjson openvpn_tcp   "${OPENVPN_TCP_OK:-0}" \
    --arg openvpn_hs        "$OPENVPN_HANDSHAKE" \
    --argjson openvpn_hs_replied "${OPENVPN_HS_REPLIED:-0}" \
    --argjson openvpn_cfg   "$([ -n "${OVPN_CONFIG:-}" ] && echo 1 || echo 0)" \
    --arg openvpn_proto     "${OVPN_PROTO:-}" \
    --argjson openvpn_tlscrypt "${OVPN_TLS_CRYPT:--1}" \
    --argjson openvpn_tlsauth  "${OVPN_TLS_AUTH:--1}" \
    --argjson openvpn_obfs     "${OVPN_OBFS:--1}" \
    --arg openvpn_posture   "${OVPN_POSTURE:-}" \
    --arg openvpn_fp        "${OVPN_FINGERPRINTABLE:-}" \
    --arg tunnel_status     "${TUNNEL_STATUS:-}" \
    --argjson tunnel_is_tun "${TUNNEL_DEFAULT_IS_TUN:-0}" \
    --arg tunnel_cc         "${TUNNEL_EXIT_CC:-}" \
    --argjson tunnel_differs "${TUNNEL_EXIT_DIFFERS:--1}" \
    --arg loc_status        "${LOCALIZE_STATUS:-}" \
    --arg loc_class         "${LOCALIZE_CLASS:-}" \
    --arg loc_last_hop      "${LOCALIZE_LAST_HOP:-}" \
    --arg loc_last_asn      "${LOCALIZE_LAST_ASN:-}" \
    --arg loc_last_cc       "${LOCALIZE_LAST_CC:-}" \
    --argjson loc_reached   "${LOCALIZE_REACHED:--1}" \
    --argjson ctrl_pass     "${CONTROL_PASS:-0}" \
    --argjson ctrl_total    "${CONTROL_TOTAL:-0}" \
    --arg ctrl_blocked      "$CONTROL_BLOCKED" \
    --arg ipv6_aaaa         "$IPV6_AAAA" \
    --argjson ipv6_target   "${IPV6_TARGET_OK:-0}" \
    --arg ipv6_https        "$IPV6_HTTPS_CODE" \
    --arg xray_status       "$XRAY_STATUS" \
    --arg xray_bin          "$XRAY_TESTER_BIN" \
    --arg xray_rtt          "$XRAY_RTT_MS" \
    --arg xray_target_ip    "$XRAY_TARGET_IP" \
    --arg xray_target_loc   "$XRAY_TARGET_LOC" \
    --arg xray_url_display  "$XRAY_URL_DISPLAY" \
    --arg xray_fail_kind    "$XRAY_FAIL_KIND" \
    --argjson xray_retry    "${XRAY_RETRY_USED:-0}" \
    --arg xj_status         "$XRAY_JSON_STATUS" \
    --arg xj_socks_port     "$XRAY_JSON_SOCKS_PORT" \
    --arg xj_egress_ip      "$XRAY_JSON_EGRESS_IP" \
    --arg xj_egress_loc     "$XRAY_JSON_EGRESS_LOC" \
    --arg xj_rtt            "$XRAY_JSON_RTT_MS" \
    --arg xj_config_path    "$XRAY_JSON_CONFIG" \
    --arg xj_fail_kind      "$XRAY_JSON_FAIL_KIND" \
    --argjson xj_retry      "${XRAY_JSON_RETRY_USED:-0}" \
    --argjson xj_from_url   "${XRAY_JSON_FROM_URL:-0}" \
    --arg xt_status         "$XRAY_THROUGHPUT_STATUS" \
    --arg xt_bps            "$XRAY_THROUGHPUT_BPS" \
    --arg xt_bytes          "$XRAY_THROUGHPUT_BYTES" \
    --arg xt_time_s         "$XRAY_THROUGHPUT_TIME_S" \
    --argjson xt_target     "$XRAY_THROUGHPUT_TARGET_BYTES" \
    --arg xs_status         "$XRAY_SPEEDTEST_STATUS" \
    --arg xs_best_bps       "$XRAY_SPEEDTEST_BEST_BPS" \
    --arg xs_best_name      "$XRAY_SPEEDTEST_BEST_NAME" \
    --arg xs_results        "$XRAY_SPEEDTEST_RESULTS" \
    --argjson xs_streams    "${XRAY_SPEEDTEST_STREAMS:-0}" \
    --arg xc_status         "$XRAY_COVER_STATUS" \
    --arg xc_selfsigned     "$XRAY_COVER_SELFSIGNED" \
    --arg xc_chain          "$XRAY_COVER_CHAIN_VALID" \
    --arg xc_cnmatch        "$XRAY_COVER_CN_MATCH" \
    --arg cs_status         "$XRAY_COVER_SCAN_STATUS" \
    --arg cs_best           "$XRAY_COVER_SCAN_BEST" \
    --arg cs_results        "$XRAY_COVER_SCAN_RESULTS" \
    --arg csw_status        "$XRAY_CENSOR_SWEEP_STATUS" \
    --arg csw_tunnel        "$XRAY_CENSOR_SWEEP_TUNNEL" \
    --arg csw_results       "$XRAY_CENSOR_SWEEP_RESULTS" \
    --arg xe_status         "$XRAY_EGRESS_STATUS" \
    --arg xe_country        "$XRAY_EGRESS_COUNTRY" \
    --arg xe_hosting        "$XRAY_EGRESS_HOSTING" \
    --arg xe_proxy          "$XRAY_EGRESS_PROXY" \
    --arg xe_mobile         "$XRAY_EGRESS_MOBILE" \
    --arg xe_asn_hosting    "$XRAY_EGRESS_ASN_HOSTING" \
    --arg xe_dc             "$XRAY_EGRESS_DC" \
    --arg xe_colocated      "$XRAY_EGRESS_COLOCATED" \
    --arg xe_dns_country    "$XRAY_EGRESS_DNS_COUNTRY" \
    --arg xst_status        "$XRAY_STABILITY_STATUS" \
    --arg xst_total         "$XRAY_STABILITY_TOTAL" \
    --arg xst_ok            "$XRAY_STABILITY_OK" \
    --arg xst_killed        "$XRAY_STABILITY_KILLED" \
    --arg xst_slow          "$XRAY_STABILITY_SLOW" \
    --arg xst_retried       "$XRAY_STABILITY_RETRIED" \
    --arg xst_killbytes     "$XRAY_STABILITY_KILL_BYTES" \
    --arg xst_results       "$XRAY_STABILITY_RESULTS" \
    --arg xst_firstfail     "$XRAY_STABILITY_FIRST_FAIL_S" \
    --arg xst_rttmin        "$XRAY_STABILITY_RTT_MIN" \
    --arg xst_rttmax        "$XRAY_STABILITY_RTT_MAX" \
    --arg xl_status         "$XRAY_LINT_STATUS" \
    --arg xl_findings       "$XRAY_LINT_FINDINGS" \
    --arg xl_fet            "$XRAY_FET_EXPOSED" \
    --arg xl_valid          "$XRAY_CONFIG_VALID" \
    --arg xl_venc           "$XRAY_VLESS_ENC" \
    --arg xl_vencpad        "$XRAY_VLESS_ENC_PADDING" \
    --arg xl_vflowdep       "$XRAY_VLESS_FLOW_DEPRECATED" \
    --arg xl_dproxy         "$XRAY_DIALER_PROXY" \
    --arg xl_desync         "$XRAY_DESYNC_CHAIN" \
    --arg xl_iduuid         "$XRAY_ID_UUID" \
    --arg xck_status        "$XRAY_CLOCK_STATUS" \
    --arg xck_skew          "$XRAY_CLOCK_SKEW_S" \
    --arg xap_status        "$XRAY_ACTIVE_STATUS" \
    --arg xap_relay         "$XRAY_ACTIVE_RELAY_CODE" \
    --arg xap_real          "$XRAY_ACTIVE_REAL_CODE" \
    --arg xap_match         "$XRAY_ACTIVE_MATCH" \
    --arg xf_status         "$XRAY_FLEET_STATUS" \
    --arg xf_total          "$XRAY_FLEET_TOTAL" \
    --arg xf_ok             "$XRAY_FLEET_OK" \
    --arg xf_results        "$XRAY_FLEET_RESULTS" \
    --arg xr_status         "$XRAY_ROUTING_STATUS" \
    --arg xr_dstrat         "$XRAY_ROUTING_DOMAINSTRATEGY" \
    --arg xr_dnsrisk        "$XRAY_ROUTING_DNS_RISK" \
    --arg xr_sniff          "$XRAY_ROUTING_SNIFF" \
    --arg xr_dnssplit       "$XRAY_ROUTING_DNS_SPLIT" \
    --arg xr_sensitive      "$XRAY_ROUTING_PROXY_SENSITIVE" \
    --arg xr_default        "$XRAY_ROUTING_DEFAULT" \
    --arg xr_proxy          "$XRAY_ROUTING_PROXY_TAGS" \
    --arg xr_undef          "$XRAY_ROUTING_UNDEF" \
    --arg xr_live           "$XRAY_ROUTING_LIVE" \
    --arg xr_liveres        "$XRAY_ROUTING_LIVE_RESULTS" \
    --arg xbb_status        "$XRAY_BUFFERBLOAT_STATUS" \
    --arg xbb_idle          "$XRAY_BUFFERBLOAT_IDLE_MS" \
    --arg xbb_load          "$XRAY_BUFFERBLOAT_LOAD_MS" \
    --arg xbb_inflate       "$XRAY_BUFFERBLOAT_INFLATE_MS" \
    --arg xbb_jitter        "$XRAY_BUFFERBLOAT_JITTER_MS" \
    --arg xmtu_status       "$XRAY_MTU_STATUS" \
    --arg xmtu_path         "$XRAY_MTU_PATH" \
    --arg xtp_status        "$XRAY_TLSPAR_STATUS" \
    --arg xtp_server_alpn   "${XRAY_TLSPAR_SERVER_ALPN:-}" \
    --arg xtp_cover_alpn    "${XRAY_TLSPAR_COVER_ALPN:-}" \
    --arg xtp_cover_h3      "${XRAY_TLSPAR_COVER_H3:-}" \
    --arg xtp_h3_parity     "${XRAY_TLSPAR_H3_PARITY:-}" \
    --arg xtp_ver           "$XRAY_TLSPAR_VER_MATCH" \
    --arg xtp_alpn          "$XRAY_TLSPAR_ALPN_MATCH" \
    --arg xtp_cipher        "$XRAY_TLSPAR_CIPHER_MATCH" \
    --arg xtp_ext           "$XRAY_TLSPAR_EXT_MATCH" \
    --arg xtp_sfp           "$XRAY_TLSPAR_SERVER_FP" \
    --arg xtp_cfp           "$XRAY_TLSPAR_COVER_FP" \
    --arg hx_status         "$XRAY_HOSTEXP_STATUS" \
    --arg hx_open           "$XRAY_HOSTEXP_OPEN" \
    --arg hx_cdn            "$XRAY_HOSTEXP_CDN" \
    --arg pp_status         "$PANEL_STATUS" \
    --arg pp_found          "$PANEL_FOUND" \
    --arg cl_status         "$CONN_LIMIT_STATUS" \
    --arg cl_req            "$CONN_LIMIT_REQUESTED" \
    --arg cl_succ           "$CONN_LIMIT_SUCC" \
    --arg cl_fail           "$CONN_LIMIT_FAIL" \
    --arg cl_minms          "$CONN_LIMIT_MINMS" \
    --arg cl_maxms          "$CONN_LIMIT_MAXMS" \
    --arg cl_verdict        "$CONN_LIMIT_VERDICT" \
    --arg yt_status         "$YT_REACH_STATUS" \
    --arg yt_req            "$YT_REACH_REQUESTED" \
    --arg yt_succ           "$YT_REACH_SUCC" \
    --arg yt_fail           "$YT_REACH_FAIL" \
    --arg yt_minms          "$YT_REACH_MINMS" \
    --arg yt_maxms          "$YT_REACH_MAXMS" \
    --arg yt_verdict        "$YT_REACH_VERDICT" \
    --arg hy_status         "$HYSTERIA_STATUS" \
    --arg hy_sni_keyword    "$HYSTERIA_SNI_KEYWORD" \
    --arg hy_sni_explicit   "$HYSTERIA_SNI_EXPLICIT" \
    --arg hy_obfs           "$HYSTERIA_OBFS" \
    --arg hy_insecure       "$HYSTERIA_INSECURE" \
    --arg xct_status        "$XRAY_COVERTHR_STATUS" \
    --arg xct_cover         "$XRAY_COVERTHR_COVER_BPS" \
    --arg xct_base          "$XRAY_COVERTHR_BASE_BPS" \
    --arg xd_status         "$XRAY_DETECT_STATUS" \
    --arg xd_score          "$XRAY_DETECT_SCORE" \
    --arg xd_band           "$XRAY_DETECT_BAND" \
    --arg xd_voltht         "$XRAY_VOLUME_THROTTLE_HINT" \
    --arg xpf_port_std      "$XRAY_PASSIVE_PORT_STD" \
    --arg xpf_asn_match     "$XRAY_PASSIVE_ASN_MATCH" \
    --arg xpf_fp_strong     "$XRAY_PASSIVE_FP_STRONG" \
    --arg xpf_sni_resolves  "$XRAY_PASSIVE_SNI_RESOLVES" \
    --arg xpf_sni_keyword   "$XRAY_PASSIVE_SNI_KEYWORD" \
    --arg xpf_cover_obscure "$XRAY_PASSIVE_COVER_OBSCURE" \
    --arg xpf_utls_rare     "$XRAY_PASSIVE_UTLS_RARE" \
    --arg xpf_utls_fp       "$XRAY_PASSIVE_UTLS_FP" \
    --arg xpf_vision        "$XRAY_PASSIVE_VISION" \
    --arg xsp_status        "$XRAY_SNIPRIV_STATUS" \
    --arg xsp_cleartext     "$XRAY_SNIPRIV_CLEARTEXT" \
    --arg xsp_ech_applies   "$XRAY_SNIPRIV_ECH_APPLIES" \
    --arg xsp_ech_cover     "$XRAY_SNIPRIV_ECH_COVER" \
    --arg xsp_code          "$XRAY_SNIPRIV_CODE" \
    --arg xtr_mux           "$XRAY_TRANSPORT_MUX" \
    --arg xd_deployfp       "$XRAY_DEPLOY_FINGERPRINT" \
    --argjson verdicts      "$verdicts_json" '
    def words: split(" ") | map(select(length > 0));
    def opt(s): if s == "" then null else s end;
    def bool_int(n): n == 1;
    def tri_bool(n): if n < 0 then null else n == 1 end;
    {
      schema_version: 1,
      version: $version,
      timestamp: (now | todate),
      label: opt($run_label),
      target: {
        host: $host,
        port_tcp: $port_tcp,
        port_udp: $port_udp,
        resolved_ip: opt($resolved_ip),
        resolved_source: opt($resolved_source)
      },
      environment: {
        default_interface: opt($env_default_if),
        vpn_like_interfaces: ($env_vpn_ifs | words),
        system_vpn_services: opt($env_connected),
        on_vpn: bool_int($env_on_vpn)
      },
      probes: {
        dns: {
          system_a: ($dns_sys_ips | words),
          doh_a: ($dns_doh_ips | words),
          divergence_class: opt($dns_diverge_class),
          dns_block: bool_int($dns_block_j),
          doh_integrity: {state: opt($doh_state), returned: ($doh_ips | words)},
          dot_integrity: {state: opt($dot_state), returned: ($dot_ips | words)},
          doh_multi: {
            ok: $doh_multi_ok,
            compromised: $doh_multi_bad,
            unreachable: $doh_multi_off,
            providers: ($doh_multi | split("\n") | map(select(length > 0) | split("|") | {url: .[0], state: .[1], returned: (.[2] | split(" ") | map(select(length > 0)))}))
          }
        },
        tcp: {
          baseline_reachable: bool_int($tcp_baseline),
          baseline_ip: opt($tcp_baseline_ip),
          target_reachable: bool_int($tcp_target),
          target_icmp_ok: tri_bool(($tcp_target_icmp | tonumber? // -1))
        },
        tls: {
          proper_sni_ok: bool_int($tls_proper),
          no_sni_ok: bool_int($tls_no_sni),
          fake_sni_ok: bool_int($tls_fake),
          fragmented_ok: tri_bool($tls_frag)
        },
        request_filter: {
          default_ua_code: opt($ua_default),
          chrome_ua_code: opt($ua_chrome),
          impersonate_code: opt($ua_impersonate),
          impersonate_binary: opt($ua_impersonate_bin)
        },
        rst: {
          elapsed_seconds: (if $rst_elapsed == "" then null else ($rst_elapsed | tonumber? // null) end),
          handshake_ok: bool_int($rst_hs),
          openssl_exit_code: $rst_rc
        },
        udp: {
          ike500_responsive: bool_int($udp_ike500),
          ike4500_responsive: bool_int($udp_ike4500),
          quic_baseline_code: opt($udp_quic),
          quic_baseline: opt($udp_quic_base),
          quic_target: opt($udp_quic_target),
          quic_verdict: opt($udp_quic_verdict)
        },
        openvpn: {
          udp_port_accessible: bool_int($openvpn_udp),
          tcp_port_reachable: bool_int($openvpn_tcp),
          handshake_response_hex: opt($openvpn_hs),
          handshake_replied: bool_int($openvpn_hs_replied),
          config_provided: bool_int($openvpn_cfg),
          proto: opt($openvpn_proto),
          tls_crypt: tri_bool($openvpn_tlscrypt),
          tls_auth: tri_bool($openvpn_tlsauth),
          obfuscated: tri_bool($openvpn_obfs),
          posture: opt($openvpn_posture),
          fingerprintable: opt($openvpn_fp)
        },
        tunnel: {
          status: opt($tunnel_status),
          default_iface_is_tunnel: bool_int($tunnel_is_tun),
          exit_country: opt($tunnel_cc),
          exit_differs: tri_bool($tunnel_differs)
        },
        whitelist: {
          status: opt($wl_status),
          permitted_reachable: (if $wl_perm_ok == "" then null else ($wl_perm_ok|tonumber? // null) end),
          controls_reachable: (if $wl_ctl_ok == "" then null else ($wl_ctl_ok|tonumber? // null) end)
        },
        localize: {
          status: opt($loc_status),
          class: opt($loc_class),
          last_hop: (if $loc_last_hop == "" then null else ($loc_last_hop | tonumber? // null) end),
          last_hop_asn: opt($loc_last_asn),
          last_hop_country: opt($loc_last_cc),
          reached_destination: tri_bool($loc_reached)
        },
        control: {
          passed: $ctrl_pass,
          total: $ctrl_total,
          unreachable: ($ctrl_blocked | words)
        },
        ipv6: {
          aaaa: ($ipv6_aaaa | words),
          target_reachable: bool_int($ipv6_target),
          https_code: opt($ipv6_https)
        },
        xray_protocol: {
          status: opt($xray_status),
          tester_binary: opt($xray_bin),
          rtt_ms: (if $xray_rtt == "" then null else ($xray_rtt | tonumber? // null) end),
          egress_ip: opt($xray_target_ip),
          egress_location: opt($xray_target_loc),
          url_display: opt($xray_url_display),
          failure_kind: opt($xray_fail_kind),
          slow_handshake_retry: bool_int($xray_retry)
        },
        xray_full_config: {
          status: opt($xj_status),
          config_path: (if $xj_from_url == 1 then null else opt($xj_config_path) end),
          synthesized_from_url: bool_int($xj_from_url),
          socks_port_used: (if $xj_socks_port == "" then null else ($xj_socks_port | tonumber? // null) end),
          egress_ip: opt($xj_egress_ip),
          egress_location: opt($xj_egress_loc),
          rtt_ms: (if $xj_rtt == "" then null else ($xj_rtt | tonumber? // null) end),
          failure_kind: opt($xj_fail_kind),
          slow_handshake_retry: bool_int($xj_retry)
        },
        xray_throughput: {
          status: opt($xt_status),
          bytes_per_second: (if $xt_bps == "" then null else ($xt_bps | tonumber? // null) end),
          bytes_received: (if $xt_bytes == "" then null else ($xt_bytes | tonumber? // null) end),
          seconds: (if $xt_time_s == "" then null else ($xt_time_s | tonumber? // null) end),
          target_bytes: $xt_target
        },
        xray_speedtest: {
          status: opt($xs_status),
          streams: $xs_streams,
          best_endpoint: opt($xs_best_name),
          best_bytes_per_second: (if $xs_best_bps == "" then null else ($xs_best_bps | tonumber? // null) end),
          best_mbps: (if $xs_best_bps == "" then null else (($xs_best_bps | tonumber? // 0) * 8 / 1000000) end),
          per_endpoint: (
            if $xs_results == "" then []
            else ($xs_results | split(" ") | map(select(length > 0) | split("|")
                  | { name: .[0], bytes_per_second: (.[1] | tonumber? // null),
                      mbps: ((.[1] | tonumber? // 0) * 8 / 1000000) }))
            end
          )
        },
        xray_cover: {
          status: opt($xc_status),
          self_signed: tri_bool(($xc_selfsigned | tonumber? // -1)),
          chain_valid: tri_bool(($xc_chain | tonumber? // -1)),
          cn_matches_servername: tri_bool(($xc_cnmatch | tonumber? // -1))
        },
        cover_scan: {
          status: opt($cs_status),
          best: opt($cs_best),
          candidates: (
            if ($cs_results | gsub("^\\s+|\\s+$";"")) == "" then []
            else ($cs_results | split("\n") | map(select(length > 0) | split("|")
                  | { domain: .[0], tls13: (.[1]=="yes"), h2: (.[2]=="yes"),
                      ca_valid: (.[3]=="yes"), non_redirect: (.[4]=="yes"), verdict: .[5] }))
            end
          )
        },
        censor_sweep: {
          status: opt($csw_status),
          tunnel_used: tri_bool(($csw_tunnel | tonumber? // -1)),
          results: (
            if ($csw_results | gsub("^\\s+|\\s+$";"")) == "" then []
            else ($csw_results | split("\n") | map(select(length > 0) | split("|")
                  | { host: .[0], direct: (.[1]=="yes"),
                      tunnel: (if .[2]=="yes" then true elif .[2]=="no" then false else null end),
                      verdict: .[3] }))
            end
          )
        },
        xray_egress: {
          status: opt($xe_status),
          country: opt($xe_country),
          hosting: tri_bool(($xe_hosting | tonumber? // -1)),
          proxy: tri_bool(($xe_proxy | tonumber? // -1)),
          mobile: tri_bool(($xe_mobile | tonumber? // -1)),
          asn_hosting: tri_bool(($xe_asn_hosting | tonumber? // -1)),
          datacenter_fallback: tri_bool(($xe_dc | tonumber? // -1)),
          egress_colocated: opt($xe_colocated),
          dns_resolver_geo: opt($xe_dns_country)
        },
        xray_stability: {
          status: opt($xst_status),
          pulses_total: (if $xst_total == "" then null else ($xst_total | tonumber? // null) end),
          pulses_ok: (if $xst_ok == "" then null else ($xst_ok | tonumber? // null) end),
          pulses_killed: (if $xst_killed == "" then null else ($xst_killed | tonumber? // null) end),
          pulses_slow: (if $xst_slow == "" then null else ($xst_slow | tonumber? // null) end),
          pulses_retried_recovered: (if $xst_retried == "" then null else ($xst_retried | tonumber? // null) end),
          kill_at_bytes: (if $xst_killbytes == "" then null else ($xst_killbytes | tonumber? // null) end),
          first_failure_seconds: (if $xst_firstfail == "" then null else ($xst_firstfail | tonumber? // null) end),
          rtt_min_ms: (if $xst_rttmin == "" then null else ($xst_rttmin | tonumber? // null) end),
          rtt_max_ms: (if $xst_rttmax == "" then null else ($xst_rttmax | tonumber? // null) end),
          per_pulse: (
            if $xst_results == "" then []
            else ($xst_results | split(" ") | map(select(length > 0) | split("|")
                  | { bytes: (.[0] | tonumber? // null), state: .[1],
                      rtt_ms: (if (.[2] // "") == "" then null else (.[2] | tonumber? // null) end) }))
            end
          )
        },
        xray_lint: {
          status: opt($xl_status),
          fet_exposed: tri_bool(($xl_fet | tonumber? // -1)),
          config_valid: tri_bool(($xl_valid | tonumber? // -1)),
          vless_encryption: (if $xl_venc == "" then null else $xl_venc end),
          vless_encryption_padding: tri_bool(($xl_vencpad | tonumber? // -1)),
          vless_flow_deprecated: tri_bool(($xl_vflowdep | tonumber? // -1)),
          dialer_proxy: (if $xl_dproxy == "" then null else $xl_dproxy end),
          desync_chain: tri_bool(($xl_desync | tonumber? // -1)),
          id_uuid: tri_bool(($xl_iduuid | tonumber? // -1)),
          findings: (if $xl_findings == "" then [] else ($xl_findings | split("\n") | map(select(length > 0))) end)
        },
        xray_clock: {
          status: opt($xck_status),
          skew_seconds: (if $xck_skew == "" then null else ($xck_skew | tonumber? // null) end)
        },
        xray_active_probe: {
          status: opt($xap_status),
          relay_http_code: opt($xap_relay),
          genuine_http_code: opt($xap_real),
          matches_cover: tri_bool(($xap_match | tonumber? // -1))
        },
        xray_fleet: {
          status: opt($xf_status),
          outbounds_total: (if $xf_total == "" then null else ($xf_total | tonumber? // null) end),
          outbounds_ok: (if $xf_ok == "" then null else ($xf_ok | tonumber? // null) end),
          per_outbound: (
            if $xf_results == "" then []
            else ($xf_results | split(" ") | map(select(length > 0) | split("|")
                  | { tag: .[0], state: .[1], rtt_ms: (.[2] | tonumber? // null) }))
            end
          )
        },
        xray_routing: {
          status: opt($xr_status),
          domain_strategy: opt($xr_dstrat),
          dns_leak_risk: tri_bool(($xr_dnsrisk | tonumber? // -1)),
          sniffing: tri_bool(($xr_sniff | tonumber? // -1)),
          dns_split_horizon: tri_bool(($xr_dnssplit | tonumber? // -1)),
          proxy_sensitive_categories: (if $xr_sensitive == "" then [] else ($xr_sensitive | split(",") | map(select(length > 0))) end),
          default_outbound: opt($xr_default),
          proxy_outbounds: (if $xr_proxy == "" then [] else ($xr_proxy | split(" ") | map(select(length > 0))) end),
          undefined_outbound_tags: (if $xr_undef == "" then [] else ($xr_undef | split(" ") | map(select(length > 0))) end),
          live_test: opt($xr_live),
          live_results: (
            if $xr_liveres == "" then []
            else ($xr_liveres | split(" ") | map(select(length > 0) | split("|")
                  | { domain: .[0], result: .[1] }))
            end
          )
        },
        xray_bufferbloat: {
          status: opt($xbb_status),
          idle_rtt_ms: (if $xbb_idle == "" then null else ($xbb_idle | tonumber? // null) end),
          loaded_rtt_ms: (if $xbb_load == "" then null else ($xbb_load | tonumber? // null) end),
          inflation_ms: (if $xbb_inflate == "" then null else ($xbb_inflate | tonumber? // null) end),
          jitter_ms: (if $xbb_jitter == "" then null else ($xbb_jitter | tonumber? // null) end)
        },
        xray_mtu: {
          status: opt($xmtu_status),
          path_mtu: (if $xmtu_path == "" then null else ($xmtu_path | tonumber? // null) end)
        },
        xray_tls_parity: {
          status: opt($xtp_status),
          version_match: tri_bool(($xtp_ver | tonumber? // -1)),
          alpn_match: tri_bool(($xtp_alpn | tonumber? // -1)),
          cipher_match: tri_bool(($xtp_cipher | tonumber? // -1)),
          ext_match: tri_bool(($xtp_ext | tonumber? // -1)),
          server_alpn: opt($xtp_server_alpn),
          cover_alpn: opt($xtp_cover_alpn),
          cover_http3: opt($xtp_cover_h3),
          http3_parity: opt($xtp_h3_parity),
          server_fingerprint: opt($xtp_sfp),
          cover_fingerprint: opt($xtp_cfp)
        },
        host_exposure: {
          status: opt($hx_status),
          open_ports: (if $hx_open == "" then [] else ($hx_open | split(", ") | map(select(length > 0))) end),
          cdn_edge: tri_bool(($hx_cdn | tonumber? // -1))
        },
        panel_probe: {
          status: opt($pp_status),
          panel_found: tri_bool(($pp_found | tonumber? // -1))
        },
        conn_limit: {
          status: opt($cl_status),
          requested: (if $cl_req == "" then null else ($cl_req | tonumber? // null) end),
          succeeded: (if $cl_succ == "" then null else ($cl_succ | tonumber? // null) end),
          failed: (if $cl_fail == "" then null else ($cl_fail | tonumber? // null) end),
          min_handshake_ms: (if $cl_minms == "" then null else ($cl_minms | tonumber? // null) end),
          max_handshake_ms: (if $cl_maxms == "" then null else ($cl_maxms | tonumber? // null) end),
          verdict: opt($cl_verdict)
        },
        youtube_reach: {
          status: opt($yt_status),
          requested: (if $yt_req == "" then null else ($yt_req | tonumber? // null) end),
          succeeded: (if $yt_succ == "" then null else ($yt_succ | tonumber? // null) end),
          failed: (if $yt_fail == "" then null else ($yt_fail | tonumber? // null) end),
          min_ttfb_ms: (if $yt_minms == "" then null else ($yt_minms | tonumber? // null) end),
          max_ttfb_ms: (if $yt_maxms == "" then null else ($yt_maxms | tonumber? // null) end),
          verdict: opt($yt_verdict)
        },
        hysteria: {
          status: opt($hy_status),
          sni_keyword: tri_bool(($hy_sni_keyword | tonumber? // -1)),
          sni_explicit: tri_bool(($hy_sni_explicit | tonumber? // -1)),
          obfs: tri_bool(($hy_obfs | tonumber? // -1)),
          insecure: tri_bool(($hy_insecure | tonumber? // -1))
        },
        xray_cover_throttle: {
          status: opt($xct_status),
          cover_bytes_per_second: (if $xct_cover == "" then null else ($xct_cover | tonumber? // null) end),
          baseline_bytes_per_second: (if $xct_base == "" then null else ($xct_base | tonumber? // null) end)
        },
        xray_sni_privacy: {
          status: opt($xsp_status),
          sni_cleartext: tri_bool(($xsp_cleartext | tonumber? // -1)),
          ech_applies: tri_bool(($xsp_ech_applies | tonumber? // -1)),
          ech_published_by_cover: (if $xsp_ech_cover == "1" then true elif $xsp_ech_cover == "0" then false else null end),
          posture: opt($xsp_code)
        },
        xray_detectability: {
          status: opt($xd_status),
          score: (if $xd_score == "" then null else ($xd_score | tonumber? // null) end),
          band: opt($xd_band),
          port_standard: tri_bool(($xpf_port_std | tonumber? // -1)),
          sni_ip_asn_match: tri_bool(($xpf_asn_match | tonumber? // -1)),
          passive_fingerprint_strong: tri_bool(($xpf_fp_strong | tonumber? // -1)),
          sni_resolves: tri_bool(($xpf_sni_resolves | tonumber? // -1)),
          sni_keyword: tri_bool(($xpf_sni_keyword | tonumber? // -1)),
          cover_obscure: tri_bool(($xpf_cover_obscure | tonumber? // -1)),
          utls_fp_uncommon: tri_bool(($xpf_utls_rare | tonumber? // -1)),
          utls_fp: opt($xpf_utls_fp),
          tls_in_tls_protected: (($xpf_vision | tonumber? // -1) as $v | if $v == 1 then true elif $v == 0 then false else null end),
          mux_enabled: tri_bool(($xtr_mux | tonumber? // -1)),
          volume_throttle_suspected: tri_bool(($xd_voltht | tonumber? // -1)),
          deployment_fingerprint: opt($xd_deployfp)
        }
      },
      verdicts: $verdicts
    }'
}

# Compare the current run's JSON ($2) against a saved baseline file ($1) and
# print the meaningful changes. Share-safe: the compared "signature" is built
# from statuses / geo / booleans / bucketed numbers only — never raw IPs or
# domains (a changed server/egress IP is reported as a boolean "changed").
_emit_baseline_diff() {
  local bfile="$1" cur="$2" base ts changes
  if [ ! -r "$bfile" ]; then
    warn "baseline not readable: $bfile (run --save-baseline first)"
    return 0
  fi
  base=$(cat "$bfile" 2>/dev/null)
  if ! printf '%s' "$base" | jq -e . >/dev/null 2>&1; then
    warn "baseline file is not valid JSON: $bfile"
    return 0
  fi
  ts=$(printf '%s' "$base" | jq -r '.timestamp // "unknown"' 2>/dev/null)

  hdr "Baseline diff (vs ${ts})"

  # Name both vantages when known (--label / .environment.default_interface). Without
  # this the diff is anonymous — and the whole point of diffing two runs of the SAME
  # endpoint is usually "which network path was different" (e.g. LTE vs Wi-Fi).
  local _blab _clab _bif _cif
  _blab=$(printf '%s' "$base" | jq -r '.label // ""' 2>/dev/null)
  _clab=$(printf '%s' "$cur"  | jq -r '.label // ""' 2>/dev/null)
  _bif=$(printf '%s' "$base"  | jq -r '.environment.default_interface // ""' 2>/dev/null)
  _cif=$(printf '%s' "$cur"   | jq -r '.environment.default_interface // ""' 2>/dev/null)
  if [ -n "$_blab$_clab$_bif$_cif" ]; then
    info "vantage: baseline ${_blab:-<unlabelled>}${_bif:+ (${_bif})} → current ${_clab:-<unlabelled>}${_cif:+ (${_cif})}"
    [ -z "$_blab$_clab" ] && info "tip: pass --label <name> (e.g. --label lte-megafon) so each saved run identifies its network path"
  fi

  # Version-drift note: a baseline from an older build is missing the probe
  # blocks added since, so those probes will show up as "none -> X" changes on
  # the first diff after an upgrade. Flag it so that isn't read as a regression.
  local _bver _cver
  _bver=$(printf '%s' "$base" | jq -r '.version // "?"' 2>/dev/null)
  _cver=$(printf '%s' "$cur"  | jq -r '.version // "?"' 2>/dev/null)
  if [ "$_bver" != "$_cver" ] && [ "$_bver" != "?" ]; then
    info "baseline is from v${_bver} (now v${_cver}) — probes added since will appear as changes, not regressions"
  fi

  changes=$(jq -rn --argjson b "$base" --argjson c "$cur" '
    def sig: {
      proto: .probes.xray_protocol.status,
      full: .probes.xray_full_config.status,
      egress_geo: .probes.xray_full_config.egress_location,
      throughput: .probes.xray_throughput.status,
      capacity_mbps: (.probes.xray_speedtest.best_mbps | if . == null then null else (. / 5 | floor * 5) end),
      cover_selfsigned: .probes.xray_cover.self_signed,
      cover_chain: .probes.xray_cover.chain_valid,
      active: .probes.xray_active_probe.status,
      tls_parity: .probes.xray_tls_parity.status,
      stability: .probes.xray_stability.status,
      killed: .probes.xray_stability.pulses_killed,
      egress_country: .probes.xray_egress.country,
      egress_hosting: .probes.xray_egress.hosting,
      egress_proxy: .probes.xray_egress.proxy,
      mtu: .probes.xray_mtu.path_mtu,
      bufferbloat: .probes.xray_bufferbloat.status,
      cover_throttle: .probes.xray_cover_throttle.status,
      detect: (.probes.xray_detectability.score | if . == null then null else (. / 10 | floor * 10) end),
      fleet_ok: .probes.xray_fleet.outbounds_ok,
      fleet_total: .probes.xray_fleet.outbounds_total,
      verdicts: (.verdicts | length)
    };
    def show: if . == null then "none" else tostring end;
    ($b | sig) as $bs | ($c | sig) as $cs |
    ( [ $cs | keys_unsorted[] as $k | select(($bs[$k]) != ($cs[$k]))
        | "\($k): \($bs[$k] | show) -> \($cs[$k] | show)" ]
      + (if ($b.target.host) != ($c.target.host) then ["server host: changed"] else [] end)
    ) | .[]
  ' 2>/dev/null)

  if [ -z "$changes" ]; then
    ok "no changes since baseline"
  else
    printf '%s\n' "$changes" | while IFS= read -r ln; do
      [ -n "$ln" ] && warn "$ln"
    done
  fi
}

# ---------- main ----------

_init_log

# Cleanup trap: probe-5 temp files + optional tcpdump capture + probe-12
# xray-core child process + patched config tempfile.
_cleanup() {
  rm -f "$RST_TMP_OUT" "$RST_TMP_TIME" 2>/dev/null
  [ -n "$PCAP_PID" ] && kill "$PCAP_PID" 2>/dev/null
  if [ -n "$XRAY_JSON_XRAY_PID" ]; then
    kill "$XRAY_JSON_XRAY_PID" 2>/dev/null
    # Give it ~0.5s to exit gracefully, then SIGKILL if still alive.
    for _ in 1 2 3; do
      kill -0 "$XRAY_JSON_XRAY_PID" 2>/dev/null || break
      sleep 0.2
    done
    kill -9 "$XRAY_JSON_XRAY_PID" 2>/dev/null
  fi
  [ -n "$XRAY_JSON_PATCHED_PATH" ] && rm -f "$XRAY_JSON_PATCHED_PATH" 2>/dev/null
  # Synthesized-from-URL config holds live credentials — remove it too.
  [ -n "$XRAY_JSON_SYNTH_PATH" ] && rm -f "$XRAY_JSON_SYNTH_PATH" 2>/dev/null
  # Inline / stdin JSON we wrote to a temp file holds live credentials — remove it.
  [ -n "$XRAY_INLINE_JSON_PATH" ] && rm -f "$XRAY_INLINE_JSON_PATH" 2>/dev/null
  # --outbound narrowed config holds live credentials too — remove it.
  [ -n "$XRAY_OUTBOUND_PATH" ] && rm -f "$XRAY_OUTBOUND_PATH" 2>/dev/null
  # --subscription extracted configs hold live creds — remove the whole temp dir.
  [ -n "$SUB_DIR" ] && rm -rf "$SUB_DIR" 2>/dev/null
  # Routing-probe xray instance (live split-tunnel test) — don't orphan it.
  [ -n "$XRAY_ROUTING_PID" ] && kill "$XRAY_ROUTING_PID" 2>/dev/null
  # --stub-dialer throwaway socks — kill the listener (its relay children are
  # short-lived and end when the tunnel closes).
  [ -n "${_STUB_PID:-}" ] && kill "$_STUB_PID" 2>/dev/null
}
trap _cleanup EXIT

# --pcap: spawn tcpdump in the background to capture probe-related traffic.
# Scope-narrowed via 'host VPN_HOST' BPF filter — only captures packets to/from
# our target plus baseline. Needs root or cap_net_raw; warns + continues on
# permission denial.
if [ -n "$PCAP_FILE" ]; then
  if ! check_cmd tcpdump; then
    warn "--pcap: tcpdump not installed; capture disabled"
    PCAP_FILE=""
  else
    # Ensure parent dir exists.
    _pcap_dir=$(dirname -- "$PCAP_FILE")
    [ -d "$_pcap_dir" ] || mkdir -p -- "$_pcap_dir" 2>/dev/null || true
    # Capture host VPN_HOST (+ resolved IP added later won't be retroactive,
    # but BPF filter on hostname matches both IPv4 and IPv6 well in practice).
    tcpdump -i any -nn -U -w "$PCAP_FILE" "host $VPN_HOST" \
            >/dev/null 2>&1 &
    PCAP_PID=$!
    sleep 0.3
    if kill -0 "$PCAP_PID" 2>/dev/null; then
      [ "$LOG_QUIET" = "1" ] || printf '%s\n' "${YEL}pcap:${RST} writing to $PCAP_FILE (pid $PCAP_PID)"
    else
      warn "--pcap: tcpdump exited (likely needs sudo / cap_net_raw); continuing without capture"
      PCAP_PID=""
      PCAP_FILE=""
    fi
  fi
fi

# --subscription --sub-test all: walk + score every config, then exit (the normal
# single-host flow doesn't apply to a whole fleet). EXIT trap cleans the temp dir.
if [ -n "${SUB_WALK:-}" ]; then
  probe_subscription_walk
  exit 0
fi

if [ "$LOG_QUIET" != "1" ]; then
  printf '%s\n' "${BLU}VPN-blocking diagnostic for ${VPN_HOST}${RST}"
  printf '%s\n' "${DIM}Run from $(hostname) on $(date)${RST}"

  # Nudge users running with the demo default — the script will probe IANA's
  # www.example.com (a real but VPN-unrelated host), which is fine for a smoke
  # test but not what they probably want.
  if [ "$VPN_HOST" = "www.example.com" ]; then
    printf '\n%s\n' "${YEL}Note:${RST} VPN_HOST is the demo default (IANA www.example.com)."
    printf '%s\n' "  Set your real endpoint:"
    printf '%s\n' "    ./detect_blocking.sh my-host.com              (CLI)"
    printf '%s\n' "    VPN_HOST=my-host.com ./detect_blocking.sh     (env)"
    printf '%s\n' "    edit detect_blocking.conf                     (persistent)"
  fi
fi

# UX hint from feedback #1: surface missing optional deps once, on startup.
if [ -n "$_missing_optional" ]; then
  warn "optional commands missing:$_missing_optional (probes will use fallbacks or skip)"
fi
unset _missing_optional

_should_run env     && probe_environment
_should_run tunnel  && probe_tunnel
[ -n "$XRAY_SCAN_COVERS" ] && probe_cover_scan
_should_run dns     && { probe_dns || true; }
_should_run tcp     && probe_tcp_reachability
_should_run tls     && probe_tls_handshake
_should_run ua      && probe_request_filter
_should_run rst     && probe_rst_injection
_should_run udp     && probe_udp_protocols
_should_run openvpn && probe_openvpn
_should_run control && probe_known_blocked
_should_run whitelist && probe_whitelist
_should_run localize && probe_localize
_should_run ipv6    && probe_ipv6
_should_run compare && probe_compare_matrix

# Hysteria2 (QUIC/UDP) static analysis — runs in place of the Xray probes when a
# Hysteria2 config was detected (which already cleared the Xray config vars).
[ -n "${SUB_DIR:-}" ] && probe_subscription_inventory
[ -n "${HYSTERIA_DETECTED:-}" ] && probe_hysteria
[ -n "${HAPP_ROUTING:-}" ] && probe_happ_routing
[ -n "${HAPP_CRYPT:-}" ] && probe_happ_crypt

# A non-Xray JSON config (e.g. sing-box) can't be parsed by the Xray-protocol
# probes — say so plainly once and skip them. Transport probes (0-10) above
# already ran against the server derived from it.
if [ -n "${XRAY_JSON_FORMAT:-}" ]; then
  hdr "Xray-protocol probes (11-26)"
  warn "this is not an Xray-core config (looks like ${XRAY_JSON_FORMAT}) — Xray-protocol probes skipped"
  info "its outbounds use 'type' / 'server' / 'route' (${XRAY_JSON_FORMAT}), not Xray's 'protocol' / 'settings.vnext' / 'streamSettings'"
  info "transport probes (0-10) above ran against its server; to test the tunnel itself, convert the config to Xray-core JSON"
  add_verdict "Config is ${XRAY_JSON_FORMAT}, not Xray-core — the Xray-protocol / stealth probes (11-26) need an Xray config (outbounds with 'protocol' + 'settings.vnext' + 'streamSettings'). The transport-layer probes still apply to the server; convert the config (or pass the Xray form) to test the tunnel"
  # QUIC-SNI advisory for a sing-box Hysteria2/TUIC/QUIC outbound (read before the
  # config path is cleared below).
  if command -v jq >/dev/null 2>&1 && [ -n "$XRAY_JSON_CONFIG" ] \
     && jq -e '[.outbounds[]? | select((.type // "") | ascii_downcase | test("hysteria|tuic|quic"))] | length > 0' "$XRAY_JSON_CONFIG" >/dev/null 2>&1; then
    _quic_sni_note
  fi
  XRAY_JSON_CONFIG=""   # the Xray-JSON probes below now skip cleanly
fi

# --no-tunnel (NO_TUNNEL): skip every probe that spawns xray-core or moves data
# (11/12/13/14/16/17/21/routing/22/25/volume) and keep only the DIRECT fingerprint
# probes (15 cover-cert, 18 lint, 19 clock, 20 active-probe, 23 MTU, 24 TLS-parity,
# 26 detectability, + host-exposure) — they connect to the server directly, so a
# valid detectability score comes back with no tunnel. Powers the fast fleet walk.
# --stub-dialer: bring up a throwaway plain socks on a local desync dialerProxy's
# port (if it isn't already running) BEFORE the tunnel probes dial through it.
_start_stub_dialer
[ -z "${NO_TUNNEL:-}" ] && _should_run xray    && probe_xray_protocol
[ -z "${NO_TUNNEL:-}" ] && _should_run xrayjson && probe_xray_json
[ -z "${NO_TUNNEL:-}" ] && _should_run xrayjson && probe_xray_throughput
[ -z "${NO_TUNNEL:-}" ] && _should_run xrayjson && probe_xray_speedtest
{ _should_run xray || _should_run xrayjson; } && probe_xray_cover
{ _should_run xray || _should_run xrayjson; } && probe_host_exposure
# Connection-limit probe: opt-in (--conn-test), direct (runs under --no-tunnel too).
[ -n "${CONN_TEST_N:-}" ] && probe_conn_limit
# Panel probe: opt-in (--panel-probe [IP]), direct — audits an origin for x-ui/3x-ui.
# AUTO: host-exposure sets XRAY_HOSTEXP_CDN=0 only when a PANEL port is open AND the
# resolved IP is not a CDN edge — i.e. a real exposed-panel suspicion on this very host.
# Audit it without being asked: it's the operator's own server and the finding (takeover
# risk + a strong detectability tell) is worth the one extra probe. --no-panel-probe opts out.
if [ -z "${PANEL_PROBE:-}" ] && [ "${XRAY_HOSTEXP_CDN:-}" = "0" ]; then
  PANEL_PROBE=1
  info "auto --panel-probe: a proxy-panel port answered on a non-CDN IP — auditing it directly (--no-panel-probe to skip)"
fi
[ -n "${PANEL_PROBE:-}" ] && [ "${PANEL_PROBE:-}" != "0" ] && probe_panel
[ -z "${NO_TUNNEL:-}" ] && _should_run xrayjson && probe_xray_egress
# YouTube fan-out probe: opt-in, needs the tunnel (probe 12) up.
[ -n "${YT_TEST_N:-}" ] && [ -z "${NO_TUNNEL:-}" ] && _should_run xrayjson && probe_yt_reach
[ -z "${NO_TUNNEL:-}" ] && _should_run xrayjson && probe_xray_stability
# Lint + clock-skew run in numeric position (after 17, before 20). They're
# static/cheap and their findings also surface in the consolidated verdict.
{ _should_run xray || _should_run xrayjson; } && probe_xray_lint
{ _should_run xray || _should_run xrayjson; } && probe_clock_skew
{ _should_run xray || _should_run xrayjson; } && probe_xray_active_probe
[ -z "${NO_TUNNEL:-}" ] && _should_run xrayjson && probe_xray_fleet
[ -z "${NO_TUNNEL:-}" ] && _should_run xrayjson && probe_xray_routing
[ -z "${NO_TUNNEL:-}" ] && [ -n "$XRAY_CENSOR_SWEEP" ] && probe_censor_sweep
[ -z "${NO_TUNNEL:-}" ] && _should_run xrayjson && probe_xray_bufferbloat
{ _should_run xray || _should_run xrayjson; } && probe_xray_mtu
{ _should_run xray || _should_run xrayjson; } && probe_xray_tls_parity
[ -z "${NO_TUNNEL:-}" ] && _should_run xrayjson && probe_xray_coverthrottle
# Detectability is the FINAL synthesis (active probes 15/20/24 + passive
# port / SNI↔IP signals) — always run it last.
{ _should_run xray || _should_run xrayjson; } && probe_xray_detectability
# SNI-privacy / ECH posture — advisory, runs AFTER the probe-26 synthesis (like
# the volume advisory) so 26 stays the last SCORED probe. Not folded into score.
{ _should_run xray || _should_run xrayjson; } && probe_xray_sni_privacy
# Cross-probe temporal synthesis — runs after the data-plane + sustained-use
# probes so it can compare early-vs-late tunnel behaviour. Advisory only.
[ -z "${NO_TUNNEL:-}" ] && _should_run xrayjson && probe_volume_synthesis

# ---- cross-reference: drop severe verdicts the rest of the run disproves ----
# A single early/single-stream probe can fire a SEVERE verdict that later probes
# contradict. Probe 5 reads a hung handshake as a "firewall blackhole / full IP
# block"; probe 13 reads a single-stream stall as a "dead data plane". But a
# working tunnel (probe 12) proves the IP is NOT blackholed, and healthy
# multi-stream capacity (probe 14) / held-session stability (probe 17) prove the
# data plane flows. Suppress the contradicted verdicts (and their "rotate
# endpoint" recs) and leave one transient note — same over-alarm hardening as
# probe 2's vantage-aware cross-reference. Runs before the summary so the JSON
# and the printed verdict stay consistent.
if [ "${#VERDICTS[@]}" -gt 0 ]; then
  # Cancel verdicts that a LATER probe disproved. This keys on the verdict CODE, not
  # its prose: keying on wording meant a reworded verdict silently stopped being
  # cancelled, resurfacing a false "likely full IP block — rotate your endpoint" on a
  # demonstrably healthy tunnel. Both arrays are filtered BY INDEX so they stay aligned.
  _vkept=(); _ckept=(); _vsupp=0; _vi=0
  while [ "$_vi" -lt "${#VERDICTS[@]}" ]; do
    v="${VERDICTS[$_vi]}"; _vc="${VERDICT_CODES[$_vi]:-}"
    _vi=$(( _vi + 1 ))
    case "$_vc" in
      transport-silent-drop)
        if [ "${XRAY_JSON_STATUS:-}" = "ok" ]; then _vsupp=1; continue; fi ;;
      data-plane-dead)
        if [ "${XRAY_SPEEDTEST_STATUS:-}" = "ok" ] || [ "${XRAY_STABILITY_STATUS:-}" = "ok" ]; then _vsupp=1; continue; fi ;;
    esac
    _vkept+=("$v"); _ckept+=("$_vc")
  done
  VERDICTS=(); VERDICT_CODES=()
  [ "${#_vkept[@]}" -gt 0 ] && { VERDICTS=("${_vkept[@]}"); VERDICT_CODES=("${_ckept[@]}"); }
  if [ "$_vsupp" = "1" ]; then
    add_verdict "Transient (not a block): an early handshake (probe 5) and/or single-stream throughput (probe 13) read as a hard failure, but the tunnel established (probe 12) and multi-stream capacity (probe 14) / held-session stability (probe 17) are healthy — so that's load / path jitter, not an IP block or a dead data plane. The endpoint is fine; don't rotate it on that evidence."
  fi
fi

# ---------- summary ----------

# Baseline save / diff (longitudinal regression mode). Reuses the JSON emitter
# (captured once), so jq runs at most once extra. No new dependency.
if [ -n "$SAVE_BASELINE" ] || [ -n "$DIFF_BASELINE" ]; then
  if check_cmd jq; then
    _CURRENT_JSON=$(_emit_json)
    if [ -n "$SAVE_BASELINE" ]; then
      if printf '%s\n' "$_CURRENT_JSON" > "$SAVE_BASELINE" 2>/dev/null; then
        [ "$JSON_MODE" = "1" ] || info "baseline saved → $SAVE_BASELINE"
      else
        warn "could not write baseline to $SAVE_BASELINE"
      fi
    fi
    # Human diff section (skipped in --json mode to keep stdout pure JSON).
    if [ -n "$DIFF_BASELINE" ] && [ "$JSON_MODE" != "1" ]; then
      _emit_baseline_diff "$DIFF_BASELINE" "$_CURRENT_JSON"
    fi
  else
    warn "baseline mode needs jq — skipping --save/--diff-baseline"
  fi
fi

if [ "$JSON_MODE" = "1" ]; then
  if [ -n "${_CURRENT_JSON:-}" ]; then printf '%s\n' "$_CURRENT_JSON"; else _emit_json; fi
  _log_line DONE "$VPN_HOST"
  exit 0
fi

hdr "VERDICT"
if [ "${#VERDICTS[@]}" -eq 0 ]; then
  ok "no blocking signals detected – endpoint reachable normally"
else
  for v in "${VERDICTS[@]}"; do
    [ "$LOG_QUIET" = "1" ] || printf "  ${RED}•${RST} %s\n" "$v"
  done

  _recs=()
  _seen_recs=""   # de-dupe: distinct verdicts often map to the same fix
  for v in "${VERDICTS[@]}"; do
    case "$v" in
      *"Detectability "*|*"Passive Reality/Xray fingerprint"*) rec="stealth/fingerprint finding, not a live block — make the server blend in: serve the cover SNI on 443, point Reality 'dest'/'serverNames' at a real CA-valid cover, and choose a cover hosted on the server's own network (or a large shared CDN). The structural fix for the SNI↔IP mismatch and entry/egress co-location tells is CDN-fronting: put the entry behind a CDN (e.g. Cloudflare) so the cover SNI resolves to the CDN's own IPs and the connection terminates on the CDN — eliminating both tells at the source. (Or a 'self-steal' REALITY setup: the server fronts its OWN real site via realitySettings.target + its own serverNames, so the cover resolves to the server itself — no mismatch.) Run with --scan-covers to rank candidate cover domains (TLSv1.3 + H2 + CA-valid + non-redirect)." ;;
      *"Encrypted-ClientHello (ECH)"*) rec="enable ECH (Encrypted ClientHello) in the client — the front already publishes an ECH config, so this hides the cover SNI outright; a chained client-side desync (dialerProxy) also fragments the ClientHello, but ECH is unconditional. This config is ALREADY CDN-fronted, so 'switch to Reality' would be a different architecture, not an upgrade" ;;
      *"SNI-based DPI block"*)    rec="try Reality / domain fronting / ECH-enabled client" ;;  # NOT a bare *"SNI"* glob: that swallowed Reality-cover / Hysteria / routing verdicts (which already carry their own fix) and gave them contradictory "switch to Reality" advice
      *"DNS-level block"*)        rec="switch the client to DoH/DoT — the domain is blocked only at the plaintext-DNS layer; the real host is reachable once you resolve it over encrypted DNS (as this run proved via the DoH IP)" ;;
      *"System DNS failure"*)     rec="use DoH inside the VPN client and check router/provider DNS" ;;
      *"DNS sinkhole"*)           rec="use DoH inside the VPN client, not system resolver" ;;
      *"DoH path is compromised"*) rec="self-host DoH or use a trusted resolver via VPN tunnel – upstream DoH is intercepted on this network" ;;
      *"DoT path is compromised"*) rec="DoH AND DoT both intercepted – use an out-of-band resolver inside the VPN tunnel, not local network DNS" ;;
      *"All DoH providers compromised"*) rec="network does universal DoH MITM (likely national-CA TLS interception) — encrypted DNS is unusable on this network, tunnel DNS over VPN" ;;
      *"Split DoH MITM"*) rec="at least one DoH provider is hijacked — switch DOH_URL to one of the honest providers in DOH_PROVIDERS for this session" ;;
      *"Domain unresolvable"*)    rec="verify the hostname and test from another resolver/network" ;;
      *"Network connectivity"*)   rec="check local internet/VPN state before interpreting target probes" ;;
      *"Target TCP reachability"*) rec="fix DNS first, then rerun transport probes" ;;
      *"Target host responds to ICMP"*) rec="the host is up but TCP-filtered — test from another vantage: filtered only here means a targeted block (rotate port/IP); filtered everywhere means the service isn't running" ;;
      *"Target host is unreachable"*)
        # Vantage-aware: a dark host on a CLEAN vantage (all control sites
        # reachable, probe 8) is far more likely down / null-routed than
        # censored — so don't tell the user to rotate their IP for a server
        # that's simply offline.
        if [ "${CONTROL_TOTAL:-0}" -gt 0 ] && [ "${CONTROL_PASS:-0}" -eq "${CONTROL_TOTAL:-0}" ]; then
          rec="control sites are all reachable, so this isn't broad censorship from here — the server is most likely DOWN / null-routed; verify it's up or get a current IP (rotating your own IP won't help). Only if you're testing from inside the censored region is an IP block likely — retest from a clean vantage"
        elif [ "${CONTROL_TOTAL:-0}" -gt 0 ]; then
          rec="you're on a filtered network (some control sites blocked) and the target is dark too — possibly an IP-level block; rotate to a fresh IP / different /24 and retest from a clean vantage to rule out the node simply being down"
        else
          rec="verify the node is up and reachable from another vantage — if it answers elsewhere, your path to it is blocked (rotate IP / try another network); if it answers nowhere, the server is down"
        fi ;;
      *"Port 443"*)               rec="try TCP 8443, 2083, 2053 (Cloudflare-allowed ports)" ;;
      *"TLS DPI"*)                rec="switch to a non-TLS transport (Hysteria2, IKEv2, WG)" ;;
      *"TLS-record fragmentation"*) rec="this block ignores fragmented ClientHellos — run a DPI-desync proxy: ByeDPI/ciadpi (desktop SOCKS), ByeDPIAndroid (Android), or zapret/GoodbyeDPI. Start with TLS-record split (--tlsrec/--split, what this probe confirmed); if a stricter DPI needs more, escalate to fake-packet+TTL (--fake --ttl) or --disorder" ;;
      *"RST injection"*)          rec="use uTLS-mimicked client, fragmentation, or non-TCP" ;;
      *"Silent packet"*)          rec="likely full IP block, rotate endpoint" ;;
      *"QUIC"*)                   rec="fall back to TCP-based transport for now" ;;
      *"User-Agent"*)             rec="adjust UA header in client; not a TLS-fp problem" ;;
      *"JA3/JA4"*)                rec="use uTLS / curl-impersonate-grade client to mimic real browser ClientHello; vanilla Go/OpenSSL fingerprints get filtered" ;;
      *"OpenVPN handshake"*)      rec="use obfs-wrapped OpenVPN (Obfsproxy/Stunnel) or IKEv2/WG" ;;
      *"OpenVPN TCP port open"*)  rec="confirms targeted port-block; try OpenVPN as fallback" ;;
      *"Broad censorship"*)       rec="expect aggressive DPI; minimum stack: Reality + uTLS" ;;
      *"Selective control-site"*) rec="retest with VPN off/on; if stable, expect category filtering" ;;
      *"IPv4 blocked but IPv6 reachable"*) rec="enable IPv6-preferred mode in client; IPv4 path is being filtered while v6 is clean" ;;
      *"IPv6 transport also unreachable"*) rec="both v4 and v6 down — verify network connectivity end-to-end before blaming DPI" ;;
      *"IPv6 HTTPS layer blocked"*) rec="v6 TCP works but TLS/HTTPS doesn't — likely SNI-DPI applied to v6 too, same mitigation as v4" ;;
      *"Bypass candidate found in compare matrix"*) rec="reconfigure client to use the working (SNI, port) combo from the matrix above" ;;
      *"Xray protocol bypasses local DPI"*) rec="your protocol stack is working as designed — local DPI sees the cover, not the payload" ;;
      *"Xray-protocol handshake fails while plain TLS"*) rec="protocol-fingerprint DPI or config drift — verify UUID/keys, try Reality with a fresh target SNI, or switch to a different protocol family" ;;
      *"Xray-protocol handshake fails"*) rec="end-to-end test failed; address the underlying transport probe verdicts first, then re-run with the same --xray-config" ;;
      *"Xray full-config bypasses local DPI"*) rec="full config (with chained outbounds / fragment / noises) tunnels through — keep deploying this exact config to clients" ;;
      *"Fragment / chained-outbound layer is the bypass"*) rec="the lost-in-translation pieces of the share-link form (fragment, dialerProxy, noises) ARE the bypass; clients must consume the full json, not the URL" ;;
      *"Xray full-config tunnel fails while plain TLS"*) rec="protocol-fingerprint DPI on the tunnel — verify UUID/keys, try a different SNI front, or change flow= variant" ;;
      *"timed out (even at"*)     rec="raise TIMEOUT (high-RTT / multi-hop tunnel) or check the server's upstream/egress health — this is latency, not a fingerprint block" ;;
      *"rejected (reset / closed pipe)"*) rec="protocol-fingerprint DPI or config drift — verify UUID / keys / flow / target SNI" ;;
      *"Reality cover is fake"*)  rec="server-side fix: point Reality 'dest' at the real cover host:443 and add it to 'serverNames' so unauthenticated probes get relayed to a genuine CA-valid cert (run --scan-covers to rank candidate covers). (For a non-REALITY VLESS+TLS inbound, the equivalent active-probe defense is a 'fallbacks' array routing unauthenticated clients to a real local web server.)" ;;
      *"Reality cover/serverName mismatch"*) rec="align the client 'serverName' with the server's Reality dest / serverNames" ;;
      *"Egress is on datacenter/proxy"*) rec="for streaming / payment / banking, route those flows through a residential or clean-IP egress; for censorship circumvention the current egress is fine" ;;
      *"delayed RST"*|*"kill-shaping"*) rec="rotate endpoint / cover SNI, shorten session reuse, or add traffic padding — the handshake is fine, the proven flow is being dropped" ;;
      *"intermittently fails"*)   rec="treat as a flaky path / congested egress, not a hard block; re-test from another vantage" ;;
      *"domainStrategy="*)        rec="set domainStrategy=\"AsIs\" — domain rules match on the sniffed SNI with no local lookup, and 'direct' traffic still resolves locally at the freedom outbound (so you keep the real-user DNS-then-connect pattern); local resolution of PROXIED domains only leaks intent (the censor sees the entry flow, not the proxied destination). If you need geoip routing on domain targets, use a SPLIT-HORIZON 'dns' block: tunneled DoH for foreign/blocked domains (route the resolver's IP to a proxy outbound) + the local resolver for domestic/direct. The canonical China-grade recipe pairs this with routing geosite:cn/geoip:cn → direct and 'fakedns' for the proxied side (no real lookup, no leak, instant routing)" ;;
      *"through the proxy while the egress is on datacenter"*) rec="route the streaming / payment domains through a residential or clean-IP egress (or drop them from the proxy set) — datacenter egress IPs get geo/proxy-blocked by exactly those services" ;;
      *"fully-encrypted-traffic (FET) exposure"*) rec="give the proxy a recognizable shape so it isn't fully random: wrap in TLS or switch to REALITY (matches the GFW's TLS exemption), or use a transport with plaintext HTTP framing (ws/xhttp). For Shadowsocks, add an obfs/TLS plugin or a printable prefix + padding to push set-bits/byte out of the 3.4-4.6 block band; or move to a UDP transport (mKCP/QUIC), which this TCP classifier doesn't cover" ;;
      *) rec="" ;;
    esac
    if [ -n "$rec" ]; then
      case "$_seen_recs" in
        *"<$rec>"*) ;;                                   # already recommended
        *) _recs+=("$rec"); _seen_recs="$_seen_recs<$rec>" ;;
      esac
    fi
  done
  if [ "${#_recs[@]}" -gt 0 ]; then
    [ "$LOG_QUIET" = "1" ] || printf '\n%s\n' "${YEL}Recommendation:${RST}"
    # ByeDPI-vs-Xray in one orienting line, chosen from what actually fired:
    # PARSER block (the DPI can't be made to match → a client-side desync like
    # ByeDPI beats it with no server) vs DESTINATION/PROBE block (the destination
    # or the server itself is the target → you need a destination-hiding tunnel).
    # Parser wins if a fragmentation bypass was confirmed (then a server is
    # optional). Printed with ▸ to set it apart from the → action items.
    _fixclass=""
    for v in "${VERDICTS[@]}"; do
      case "$v" in *"TLS-record fragmentation"*) _fixclass="parser"; break ;; esac
    done
    if [ -z "$_fixclass" ]; then
      for v in "${VERDICTS[@]}"; do
        case "$v" in
          *"RST injection"*|*"unauthenticated prober"*|*"cover is fake"*|*"Silent packet"*|*"unreachable"*|*"IP-level"*|*"SNI-BASED"*|*"SNI inspection"*|*"fully-encrypted-traffic"*)
            _fixclass="destprobe"; break ;;
        esac
      done
    fi
    if [ "$LOG_QUIET" != "1" ]; then
      if [ "$_fixclass" = "parser" ]; then
        printf "  ${YEL}▸${RST} %s\n" "Fix class — PARSER: the block dies to packet desync (probe 3), so a client-side tool (ByeDPI / zapret / GoodbyeDPI) beats it with NO server, on your own IP. A Reality/Xray tunnel is only needed if you also want to hide the destination or change your exit country."
      elif [ "$_fixclass" = "destprobe" ]; then
        printf "  ${YEL}▸${RST} %s\n" "Fix class — DESTINATION/PROBE: packet desync (ByeDPI) won't beat this — the destination or the server itself is the target (IP block / active probing / detectable protocol). That needs a destination-hiding tunnel (Reality/Xray) — set one up, or harden yours per the items below."
      fi
    fi
    [ "$_fixclass" = "parser" ]   && _log_line REC "[fix-class=parser] client-side desync (ByeDPI) suffices; no server needed"
    [ "$_fixclass" = "destprobe" ] && _log_line REC "[fix-class=destprobe] needs a destination-hiding tunnel (Reality/Xray), not a client desync"
    for rec in "${_recs[@]}"; do
      _side=$(_rec_side "$rec")
      if [ "$LOG_QUIET" != "1" ]; then
        if [ -n "$_side" ]; then printf "  → [%s] %s\n" "$_side" "$rec"; else printf "  → %s\n" "$rec"; fi
      fi
      _log_line REC "$rec"
    done
  fi
fi

[ "$LOG_QUIET" = "1" ] || printf '\n%s\n' "${DIM}Done.${RST}"
_log_line DONE "$VPN_HOST"
