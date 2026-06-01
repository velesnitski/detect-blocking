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
#   CONFIG_FILE=/path/to/file ./detect_blocking.sh
#
# Precedence: CLI arg > env var > config file > built-in default.
# See detect_blocking.conf.example for all knobs (including STRICT_OPENVPN_VERDICT).

set -u

readonly DETECT_BLOCKING_VERSION="0.4.0"

# Capture original CLI invocation before parsing — needed so --watch and
# --from-file can re-invoke ourselves with the same flags minus the looping
# flag (set via _WATCH_CHILD / _BATCH_CHILD to break recursion).
# shellcheck disable=SC2034
_ORIGINAL_ARGS=("$@")

# ---------- early helpers ----------

die()       { printf 'Error: %s\n' "$1" >&2; exit 2; }
check_cmd() { command -v "$1" >/dev/null 2>&1; }

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

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
CONFIG_FILE="${CONFIG_FILE:-$SCRIPT_DIR/detect_blocking.conf}"
if [ -f "$CONFIG_FILE" ]; then
  # shellcheck disable=SC1090
  . "$CONFIG_FILE"
fi

# ---------- CLI args ----------

LOG_FILE="${LOG_FILE:-}"
LOG_QUIET="${LOG_QUIET:-0}"
ONLY_PROBES="${ONLY_PROBES:-}"
SKIP_PROBES="${SKIP_PROBES:-}"
JSON_MODE="${JSON_MODE:-0}"
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

while [ $# -gt 0 ]; do
  case "$1" in
    --log-file)    LOG_FILE="${2:-}"; shift 2 ;;
    --log-file=*)  LOG_FILE="${1#--log-file=}"; shift ;;
    --only)        ONLY_PROBES="${2:-}"; shift 2 ;;
    --only=*)      ONLY_PROBES="${1#--only=}"; shift ;;
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
    --xray-config)    XRAY_CONFIG="${2:-}"; shift 2 ;;
    --xray-config=*)  XRAY_CONFIG="${1#--xray-config=}"; shift ;;
    --xray-config-json)    XRAY_JSON_CONFIG="${2:-}"; shift 2 ;;
    --xray-config-json=*)  XRAY_JSON_CONFIG="${1#--xray-config-json=}"; shift ;;
    --speedtest)    XRAY_SPEEDTEST=1; XRAY_SPEEDTEST_FORCE=1; shift ;;
    --no-speedtest) XRAY_SPEEDTEST=0; shift ;;
    --no-egress-check) XRAY_EGRESS_CHECK=0; shift ;;
    --stability)    XRAY_STABILITY=1; XRAY_STABILITY_FORCE=1; shift ;;
    --no-stability) XRAY_STABILITY=0; shift ;;
    --fleet)        XRAY_FLEET=1; XRAY_FLEET_FORCE=1; shift ;;
    --no-fleet)     XRAY_FLEET=0; shift ;;
    --no-bufferbloat) XRAY_BUFFERBLOAT=0; shift ;;
    --quiet|-q)    LOG_QUIET=1; shift ;;
    --json)        JSON_MODE=1; LOG_QUIET=1; shift ;;
    --version|-V)
      printf 'detect_blocking %s\n' "$DETECT_BLOCKING_VERSION"
      exit 0
      ;;
    --help|-h)
      sed -n '2,27p' "$0"
      printf '\nversion: %s\n' "$DETECT_BLOCKING_VERSION"
      printf '\nProbe names (for --only / --skip): env, dns, tcp, tls, ua, rst, udp, openvpn, control, ipv6, compare, xray, xrayjson\n'
      printf '\nFlags:\n'
      printf '  --json (needs jq)   machine-readable JSON output (compact in batch/watch loops)\n'
      printf '  --quiet, -q         suppress stdout (logging still works)\n'
      printf '  --log-file PATH     append timestamped entries to PATH\n'
      printf '  --only LIST         run only listed probes (comma-separated)\n'
      printf '  --skip LIST         skip listed probes\n'
      printf '  --watch SECONDS     repeat probe every SECONDS, until interrupted\n'
      printf '  --from-file PATH    iterate over hosts in file (one per line, # comments)\n'
      printf '  --pcap PATH         tcpdump probe traffic to PATH (needs root / cap_net_raw)\n'
      printf '  --compare-sni LIST  comma-separated SNI values to test (vs proper / FAKE_SNI)\n'
      printf '  --compare-port LIST comma-separated TCP ports to test (vs VPN_PORT_TCP)\n'
      printf '  --port-survey       scan common alternative VPN/proxy ports (8443, 2083, 2087, ...)\n'
      printf '  --xray-config URL   delegate end-to-end protocol test to xray-knife (optional dep)\n'
      printf '                      accepts vless://, vmess://, trojan://, ss://, hysteria2:// URLs\n'
      printf '  --xray-config-json FILE  full-config probe via xray-core + SOCKS5 (covers fragment,\n'
      printf '                      dialerProxy, chained outbounds; needs xray + jq)\n'
      printf '  --speedtest         force probe 14 (multi-stream capacity) even inside --watch/--from-file\n'
      printf '  --no-speedtest      disable probe 14 (it runs by default when probe 12 succeeds)\n'
      printf '  --no-egress-check   disable probe 16 (egress geo/reputation; avoids a 3rd-party IP-info call)\n'
      printf '  --no-stability      disable probe 17 (held-session RST detection; it runs by default)\n'
      printf '  --stability         force probe 17 even inside --watch/--from-file loops\n'
      printf '  --no-fleet          disable probe 21 (it auto-enables on multi-outbound configs; N xray spawns)\n'
      printf '  --fleet             force probe 21 even inside --watch/--from-file loops\n'
      printf '  --no-bufferbloat    disable probe 22 (latency-under-load; saturates the tunnel briefly)\n'
      exit 0
      ;;
    -*) die "unknown option: $1" ;;
    *)  VPN_HOST="${1}"; shift ;;
  esac
done

if [ "$JSON_MODE" = "1" ]; then
  check_cmd jq || die "--json requires jq (install: brew install jq / apt-get install jq)"
fi

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
        _derived_host=$(printf '%s' "$XRAY_CONFIG" \
          | sed -nE 's|^[a-z0-9]+://[^@]+@([^:?#/]+).*|\1|p')
        # Also derive the URL's port if present — aligns transport probes
        # (2 / 3 / 5) with the same destination instead of leaving them
        # on the 443 default. Critical for non-standard-port deployments.
        _derived_port=$(printf '%s' "$XRAY_CONFIG" \
          | sed -nE 's|^[a-z0-9]+://[^@]+@[^:?#/]+:([0-9]+).*|\1|p')
        if [ -n "$_derived_host" ]; then
          VPN_HOST="$_derived_host"
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
  if [ -n "$_derived_host" ]; then
    VPN_HOST="$_derived_host"
    if [ -n "$_derived_port" ] && [ -z "${VPN_PORT_TCP:-}" ]; then
      VPN_PORT_TCP="$_derived_port"
      printf '%s\n' "note: VPN_HOST + VPN_PORT_TCP auto-derived from --xray-config-json → ${_derived_host}:${_derived_port}" >&2
    else
      printf '%s\n' "note: VPN_HOST auto-derived from --xray-config-json → $_derived_host" >&2
    fi
  fi
  unset _derived_host _derived_port
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
IKEV2_HOST="${IKEV2_HOST:-$VPN_HOST}"
OPENVPN_HOST="${OPENVPN_HOST:-$VPN_HOST}"
OPENVPN_PORT_UDP="${OPENVPN_PORT_UDP:-1194}"
OPENVPN_PORT_TCP="${OPENVPN_PORT_TCP:-1194}"

BASELINE_DOMAIN="${BASELINE_DOMAIN:-cloudflare.com}"
BASELINE_IPS="${BASELINE_IPS:-${BASELINE_IP:-1.1.1.1} 8.8.8.8 9.9.9.9}"

FAKE_SNI="${FAKE_SNI:-www.microsoft.com}"
CONTROL_SITES="${CONTROL_SITES:-www.protonvpn.com www.torproject.org www.discord.com}"
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
OPENVPN_HANDSHAKE=""     # raw 2-hex-byte response or empty
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
XRAY_JSON_STATUS=""      # ok, failed, xray-missing, jq-missing, config-missing,
                         # config-malformed, no-port, xray-bind-failed, no-config
XRAY_JSON_SOCKS_PORT=""  # actual port the patched config binds (random high)
XRAY_JSON_EGRESS_IP=""   # ip= line from cloudflare trace
XRAY_JSON_EGRESS_LOC=""  # colo= line from cloudflare trace (e.g. AMS, FRA)
XRAY_JSON_RTT_MS=""      # round-trip via the SOCKS tunnel
XRAY_JSON_FAIL_KIND=""   # on failure: timeout | reset | other (drives verdict)
XRAY_JSON_RETRY_USED=0   # 1 if the slow-handshake auto-retry ran
XRAY_JSON_SYNTH_PATH=""  # temp config synthesized from --xray-config URL (cleaned on exit)
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
XRAY_SPEEDTEST_URLS="${XRAY_SPEEDTEST_URLS:-cloudflare|https://speed.cloudflare.com/__down|cf hetzner|https://speed.hetzner.de/100MB.bin|range ovh|https://proof.ovh.net/files/100Mb.dat|range}"
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
XRAY_EGRESS_INFO_URL="${XRAY_EGRESS_INFO_URL:-http://ip-api.com/json/?fields=status,countryCode,hosting,proxy,mobile}"
XRAY_EGRESS_DNS_URL="${XRAY_EGRESS_DNS_URL:-http://edns.ip-api.com/json}"
XRAY_EGRESS_STATUS=""       # ok, skipped, disabled, curl-missing, no-data
XRAY_EGRESS_COUNTRY=""      # ISO country code seen at the egress
XRAY_EGRESS_HOSTING=""      # 1 / 0 — datacenter / hosting IP
XRAY_EGRESS_PROXY=""        # 1 / 0 — on a proxy blocklist
XRAY_EGRESS_MOBILE=""       # 1 / 0 — mobile carrier IP
XRAY_EGRESS_DNS_COUNTRY=""  # country of the DNS resolver seen through the tunnel (informational)

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
XRAY_STABILITY_STATUS=""    # ok, killed, slow, unstable, skipped, disabled, curl-missing
XRAY_STABILITY_TOTAL=""     # pulses attempted
XRAY_STABILITY_OK=""        # pulses that succeeded
XRAY_STABILITY_KILLED=""    # pulses dropped by a reset-class error (the real kill signal)
XRAY_STABILITY_SLOW=""      # pulses that timed out (slow, not killed)
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
XRAY_LINT_FINDINGS=""       # newline-joined short codes for JSON

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
XRAY_TLSPAR_STATUS=""       # ok, mismatch, skipped, no-sni, openssl-missing, unreachable
XRAY_TLSPAR_VER_MATCH=""    # 1 / 0  TLS version parity
XRAY_TLSPAR_ALPN_MATCH=""   # 1 / 0  ALPN parity
XRAY_TLSPAR_CIPHER_MATCH="" # 1 / 0  cipher parity

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
add_verdict() { VERDICTS+=("$1"); _log_line VERDICT "$1"; }

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

_resolve_a_records() {
  # System DNS A-records, sorted and deduped.
  local host="$1"
  # Short-circuit: if VPN_HOST is already a bare IPv4 literal, no DNS work
  # needed. Avoids the "Domain unresolvable" verdict on hostless targets.
  if printf '%s' "$host" | grep -qE '^[0-9]+(\.[0-9]+){3}$'; then
    printf '%s\n' "$host"
    return
  fi
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
  if [ "$VPN_PORT_TCP" = "443" ]; then
    printf 'https://%s/' "$VPN_HOST"
  else
    printf 'https://%s:%s/' "$VPN_HOST" "$VPN_PORT_TCP"
  fi
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
  hostport=${after%%\?*}
  query=""; case "$after" in *\?*) query=${after#*\?} ;; esac
  host=${hostport%%:*}
  port=${hostport##*:}
  case "$port" in ''|*[!0-9]*) port=443 ;; esac
  [ -n "$uuid" ] && [ -n "$host" ] || return 1

  local net sec sni fp pbk sid spx flow alpn path hosthdr svc hdr enc
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
  enc=$(_qp "$query" encryption); [ -z "$enc" ] && enc=none

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
      --arg path "$path" --arg hosthdr "$hosthdr" --arg svc "$svc" --arg hdr "$hdr" '
      def nz(s): if s == "" then null else s end;
      def prune: with_entries(select(.value != null));
      def secSettings:
        if $sec == "reality" then
          { realitySettings: ({ show:false, serverName:nz($sni), fingerprint:nz($fp),
                                publicKey:nz($pbk), shortId:nz($sid), spiderX:nz($spx) } | prune) }
        elif $sec == "tls" then
          { tlsSettings: ({ serverName:nz($sni), fingerprint:nz($fp),
                            alpn:(if $alpn=="" then null else ($alpn|split(",")) end) } | prune) }
        else {} end;
      def transportSettings:
        if $net == "ws" then
          { wsSettings: ({ path:(if $path=="" then "/" else $path end),
                           headers:(if $hosthdr=="" then null else {Host:$hosthdr} end) } | prune) }
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

# ---------- probes ----------

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

  local sys_ips doh_json doh_ips
  sys_ips=$(_resolve_a_records "$VPN_HOST" | _join_words)
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

  info "system resolver A: ${sys_ips:-<empty>}"
  info "DoH resolver A:    ${doh_ips:-<empty>}"

  DNS_SYS_IPS="$sys_ips"
  DNS_DOH_IPS="$doh_ips"

  if [ -z "$sys_ips" ] && [ -n "$doh_ips" ]; then
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
    warn "system DNS and DoH returned different public A sets – common with CDN/geo DNS"
    info "not enough evidence for DNS poisoning"
    RESOLVED_IP=$(printf '%s\n' "$sys_ips" | _first_word)
    RESOLVED_SOURCE="system DNS"
  fi

  info "target IP for transport probes: ${RESOLVED_IP:-<none>} (${RESOLVED_SOURCE:-none})"
}

probe_tcp_reachability() {
  hdr "2. TCP reachability"

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
      add_verdict "IP route blocked entirely (TCP 80 and 443 both fail)"
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
    add_verdict "DPI bypassable via TLS-record fragmentation (use small-record / split-SNI client)"
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

  local curl_default curl_chrome curl_impersonate="" http2_opt="" target_url impersonate_cmd
  target_url=$(_target_https_url)
  curl --version 2>/dev/null | grep -qiE 'HTTP2|HTTP/2' && http2_opt="--http2"

  curl_default=$(curl -sk --max-time "$TIMEOUT" \
    --resolve "$VPN_HOST:$VPN_PORT_TCP:$RESOLVED_IP" \
    -o /dev/null -w '%{http_code}' "$target_url" 2>/dev/null)
  [ -n "$curl_default" ] || curl_default="000"

  # shellcheck disable=SC2086
  curl_chrome=$(curl -sk --max-time "$TIMEOUT" $http2_opt \
    --resolve "$VPN_HOST:$VPN_PORT_TCP:$RESOLVED_IP" \
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
      --resolve "$VPN_HOST:$VPN_PORT_TCP:$RESOLVED_IP" \
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

  local rc=0 elapsed hs_ok=0
  RST_TMP_OUT=$(_mktmp tls)
  RST_TMP_TIME=$(_mktmp time)

  { time -p openssl s_client -connect "$RESOLVED_IP:$VPN_PORT_TCP" \
       -servername "$VPN_HOST" -brief </dev/null >"$RST_TMP_OUT" 2>&1
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
    add_verdict "Silent packet drop (firewall blackhole, not DPI reset)"
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

  if curl --version 2>/dev/null | grep -qiE 'HTTP3|HTTP/3'; then
    local quic_code
    quic_code=$(curl -sk --max-time "$TIMEOUT" --http3 \
      -o /dev/null -w '%{http_code}' \
      "https://$BASELINE_DOMAIN/" 2>/dev/null || echo "000")
    UDP_QUIC_CODE="$quic_code"
    if [ "$quic_code" != "000" ]; then
      ok "UDP 443 (QUIC/HTTP3) to baseline works"
    else
      warn "UDP 443 (QUIC) to baseline fails – QUIC may be blocked network-wide"
      add_verdict "UDP 443 / QUIC blocked – common in restrictive networks"
    fi
  else
    info "curl without HTTP/3 support – skipping QUIC probe"
  fi
}

probe_openvpn() {
  hdr "7. OpenVPN reachability + handshake"

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
        ok "OpenVPN handshake replied (server opcode 0x40 received)"
      else
        warn "got data back but not OpenVPN-shaped: $response"
      fi
    else
      if [ "$OPENVPN_UDP_OK" = "1" ]; then
        warn "no OpenVPN handshake reply – inconclusive (DPI, no service, or tls-auth/tls-crypt)"
        if [ "$STRICT_OPENVPN_VERDICT" = "1" ]; then
          add_verdict "OpenVPN handshake silently dropped – protocol-signature DPI"
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
    add_verdict "Reality tunnel handshakes successfully but data plane is unusable — payload doesn't flow (mid-stream RST, MTU clamp, or post-detection kill-shaping). Inspect with --pcap and look for RST flags arriving shortly after the first MB"
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
        printf '%s' "$XRAY_CONFIG" \
          | sed -nE 's|.*[?&]sni=([^&#]*).*|\1|p' | head -1
        return 0 ;;
    esac
  fi
  if [ -n "$XRAY_JSON_CONFIG" ] && [ -r "$XRAY_JSON_CONFIG" ] && command -v jq >/dev/null 2>&1; then
    jq -r '
      .outbounds // []
      | map(select(.streamSettings.security == "reality"))
      | first | .streamSettings.realitySettings.serverName // empty
    ' "$XRAY_JSON_CONFIG" 2>/dev/null
  fi
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

  # `echo Q` makes openssl quit right after the handshake — no `timeout`
  # wrapper needed (and `timeout`/`gtimeout` aren't present on stock macOS).
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

  # CN/SAN covers the configured serverName? Compare case-insensitively,
  # accepting a wildcard parent (*.example.com vs host.example.com). Booleans
  # only — neither the cert CN nor the SNI is emitted.
  local cn lc_cn lc_sni parent
  cn=$(printf '%s' "$subject" | sed -nE 's/.*CN ?= ?([^,/]+).*/\1/p' | head -1)
  lc_cn=$(printf '%s' "$cn"  | tr '[:upper:]' '[:lower:]')
  lc_sni=$(printf '%s' "$sni" | tr '[:upper:]' '[:lower:]')
  parent="${lc_sni#*.}"
  if [ -n "$lc_cn" ] && { [ "$lc_cn" = "$lc_sni" ] || [ "$lc_cn" = "*.$parent" ]; }; then
    XRAY_COVER_CN_MATCH=1
  else
    XRAY_COVER_CN_MATCH=0
  fi

  info "cover cert: self-signed=${XRAY_COVER_SELFSIGNED}, chain-valid=${XRAY_COVER_CHAIN_VALID}, CN-matches-serverName=${XRAY_COVER_CN_MATCH}"

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
  local port="$XRAY_JSON_SOCKS_PORT" info_json dns_json maxt
  maxt=$(( ( ${XRAY_JSON_RTT_MS:-3000} + 999 ) / 1000 + TIMEOUT ))
  info_json=$(curl -sS --max-time "$maxt" \
              --socks5-hostname "127.0.0.1:$port" \
              "$XRAY_EGRESS_INFO_URL" 2>/dev/null)

  if [ -z "$info_json" ] || ! printf '%s' "$info_json" | grep -q '"countryCode"'; then
    fail "egress IP-info lookup returned no data through the tunnel"
    XRAY_EGRESS_STATUS="no-data"
    return 0
  fi

  # Parse with jq if available, else minimal grep/sed (fields are flat).
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

  info "egress: country=${XRAY_EGRESS_COUNTRY:-?}, hosting=${XRAY_EGRESS_HOSTING}, proxy=${XRAY_EGRESS_PROXY}, mobile=${XRAY_EGRESS_MOBILE}"

  # DNS resolver as seen through the tunnel (edns.ip-api echoes the resolver).
  dns_json=$(curl -sS --max-time "$maxt" \
             --socks5-hostname "127.0.0.1:$port" \
             "$XRAY_EGRESS_DNS_URL" 2>/dev/null)
  if printf '%s' "$dns_json" | grep -q '"dns"'; then
    if command -v jq >/dev/null 2>&1; then
      XRAY_EGRESS_DNS_COUNTRY=$(printf '%s' "$dns_json" | jq -r '.dns.geo // empty' 2>/dev/null | sed -nE 's/^([A-Za-z ]+) -.*/\1/p')
      [ -z "$XRAY_EGRESS_DNS_COUNTRY" ] && XRAY_EGRESS_DNS_COUNTRY=$(printf '%s' "$dns_json" | jq -r '.dns.geo // empty' 2>/dev/null)
    fi
    if [ -n "$XRAY_EGRESS_DNS_COUNTRY" ]; then
      info "DNS resolver (via tunnel): ${XRAY_EGRESS_DNS_COUNTRY}"
    fi
  fi

  XRAY_EGRESS_STATUS="ok"
  if [ "$XRAY_EGRESS_PROXY" = "1" ] || [ "$XRAY_EGRESS_HOSTING" = "1" ]; then
    warn "egress IP is flagged as datacenter/proxy — streaming & banking services likely to block it"
    add_verdict "Egress IP is on datacenter/proxy reputation lists — fine for censorship circumvention, but streaming / payment / banking sites will challenge or block it. For those use cases a residential or clean egress is needed"
  else
    ok "egress reputation clean (not flagged datacenter/proxy)"
  fi
}

# Probe 17 — held-session stability (delayed-RST / kill-shaping). Opt-in.
# Holds the probe-12 tunnel and pulses small requests for a while, catching the
# censor tactic of allowing the handshake then RST-ing the proven tunnel
# seconds later — invisible to the short bursts in probes 13/14.
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
  local total=0 okc=0 killc=0 slowc=0 first_fail="" kill_bytes=""
  local rtt rmin="" rmax="" t0 t1 start now size url mt rc state hsz
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
    t1=$(_now_ms); rtt=$(( t1 - t0 ))
    # curl exit codes: 0 ok; 28 timeout (slow, not killed); anything else
    # (18/52/56/35/55/…) = the connection was reset / closed mid-stream = killed.
    case "$rc" in
      0)  state="ok"; okc=$(( okc + 1 ))
          [ -z "$rmin" ] && rmin="$rtt"; [ "$rtt" -lt "$rmin" ] && rmin="$rtt"
          [ -z "$rmax" ] && rmax="$rtt"; [ "$rtt" -gt "$rmax" ] && rmax="$rtt" ;;
      28) state="slow"; slowc=$(( slowc + 1 )) ;;
      *)  state="killed"; killc=$(( killc + 1 )); [ -z "$kill_bytes" ] && kill_bytes="$size" ;;
    esac
    if [ "$state" != "ok" ] && [ -z "$first_fail" ]; then
      now=$(_now_ms); first_fail=$(( ( now - start ) / 1000 ))
    fi
    if [ "$size" = "0" ]; then hsz="tiny"; elif [ "$size" -ge 1048576 ]; then hsz="$(( size / 1048576 ))MB"; else hsz="$(( size / 1024 ))KB"; fi
    info "  $(printf '%-5s' "$hsz") pulse: ${state}$([ "$state" = ok ] && echo " (${rtt} ms)")"
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

  local kb_h=""
  if [ -n "$kill_bytes" ]; then
    if [ "$kill_bytes" = "0" ]; then kb_h="tiny"; elif [ "$kill_bytes" -ge 1048576 ]; then kb_h="$(( kill_bytes / 1048576 ))MB"; else kb_h="$(( kill_bytes / 1024 ))KB"; fi
  fi

  if [ "$total" = "0" ]; then
    warn "no pulses ran"
    XRAY_STABILITY_STATUS="unstable"
  elif [ "$killc" -gt 0 ] && [ "$okc" -gt 0 ] && [ "$kill_bytes" != "0" ]; then
    # Smaller pulses passed, a larger one was reset → volumetric kill-shaping.
    fail "tunnel reset at the ${kb_h} pulse (smaller pulses passed) — volumetric kill-shaping"
    XRAY_STABILITY_STATUS="killed"
    add_verdict "Tunnel survives small flows but is reset once a transfer reaches ~${kb_h} — volumetric kill-shaping. The censor allows the handshake and trivial traffic, then drops the connection past a byte threshold; trace-only probes never see it. Mitigation: rotate endpoint / cover SNI, add padding, or switch transport"
  elif [ "$killc" -gt 0 ]; then
    fail "tunnel reset mid-session (${killc}/${total} pulses killed, first at ${kb_h:-tiny})"
    XRAY_STABILITY_STATUS="killed"
    add_verdict "Tunnel connection was reset mid-session (not a timeout) — post-detection kill-shaping / RST injection. Short connection tests miss this; rotate endpoint/cover or change transport"
  elif [ "$okc" = "$total" ]; then
    ok "tunnel stable across all ${total} pulses up to the largest size (RTT ${rmin:-?}-${rmax:-?} ms)"
    XRAY_STABILITY_STATUS="ok"
  else
    warn "tunnel slow: ${slowc}/${total} pulses timed out (no resets — degraded, not killed)"
    XRAY_STABILITY_STATUS="slow"
    add_verdict "Tunnel is slow — ${slowc}/${total} size-ladder pulses timed out but none were reset, so this is degraded throughput / congestion, not active kill-shaping. See probes 13/14 for capacity"
  fi
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
probe_xray_lint() {
  if [ -z "$XRAY_CONFIG" ] && [ -z "$XRAY_JSON_CONFIG" ]; then
    XRAY_LINT_STATUS="skipped"
    return 0
  fi

  hdr "18. Config pre-flight (lint)"

  local sec net flow pbk sid sni enc fp findings=""
  if [ -n "$XRAY_CONFIG" ]; then
    local q=""
    case "$XRAY_CONFIG" in *\?*) q=${XRAY_CONFIG#*\?}; q=${q%%#*} ;; esac
    sec=$(_qp "$q" security); net=$(_qp "$q" type); flow=$(_qp "$q" flow)
    pbk=$(_qp "$q" pbk); sid=$(_qp "$q" sid); sni=$(_qp "$q" sni)
    enc=$(_qp "$q" encryption); fp=$(_qp "$q" fp)
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
    [ -z "$net" ] && net=tcp
  fi

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

  # flow=vision requires TCP transport.
  if [ -n "$flow" ] && [ "$net" != "tcp" ]; then
    _lint_add "flow=$flow requires network=tcp, but network=$net — handshake will fail"
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
  # vless wants encryption=none.
  if [ -n "$enc" ] && [ "$enc" != "none" ]; then
    case "$XRAY_CONFIG$XRAY_JSON_CONFIG" in
      vless*|*vless*) _lint_add "vless requires encryption=none, got encryption=$enc" ;;
    esac
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
  if date -d "now" >/dev/null 2>&1; then
    date -d "$s" +%s 2>/dev/null
  else
    TZ=UTC date -j -f "%a, %d %b %Y %H:%M:%S GMT" "$s" +%s 2>/dev/null
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

  # Same request, but forced to the VPN server IP with the cover SNI/Host.
  # -k because a (broken) server may present a self-signed cert; we care about
  # whether a coherent HTTP response comes back, not cert validity here.
  XRAY_ACTIVE_RELAY_CODE=$(curl -sS -k --max-time "$TIMEOUT" -o /dev/null \
    --resolve "$sni:443:$VPN_HOST" \
    -w '%{http_code}' "https://$sni/" 2>/dev/null)
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
        | .outbounds = ([ .outbounds[] | select(.tag == $t) ] + [ {protocol:"freedom", tag:"direct"} ])
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
  tags=$(jq -r '.outbounds // [] | map(select(.settings.vnext != null or .settings.servers != null)) | .[].tag // empty' "$XRAY_JSON_CONFIG" 2>/dev/null)
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
    add_verdict "Every outbound in the fleet fails the tunnel test — the problem is in the shared configuration (serverName/cover, keys, flow), not a single dead endpoint"
  else
    warn "${okc}/${count} outbounds healthy — partial fleet degradation"
    add_verdict "${okc} of ${count} fleet outbounds pass — the rest are down; rotate or repair the failing endpoints (see the matrix above by tag)"
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
  local s_out c_out s_ver c_ver s_alpn c_alpn s_ciph c_ciph
  s_out=$(echo Q | openssl s_client -connect "$VPN_HOST:$VPN_PORT_TCP" \
          -servername "$sni" -alpn h2,http/1.1 2>/dev/null)
  c_out=$(echo Q | openssl s_client -connect "$sni:443" \
          -servername "$sni" -alpn h2,http/1.1 2>/dev/null)

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
  s_ciph=$(printf '%s' "$s_out" | sed -nE 's/^[[:space:]]*Cipher[[:space:]]*:[[:space:]]*(.*)/\1/p' | head -1)
  c_ciph=$(printf '%s' "$c_out" | sed -nE 's/^[[:space:]]*Cipher[[:space:]]*:[[:space:]]*(.*)/\1/p' | head -1)

  [ -n "$s_ver" ] && [ "$s_ver" = "$c_ver" ] && XRAY_TLSPAR_VER_MATCH=1 || XRAY_TLSPAR_VER_MATCH=0
  [ "$s_alpn" = "$c_alpn" ] && XRAY_TLSPAR_ALPN_MATCH=1 || XRAY_TLSPAR_ALPN_MATCH=0
  [ -n "$s_ciph" ] && [ "$s_ciph" = "$c_ciph" ] && XRAY_TLSPAR_CIPHER_MATCH=1 || XRAY_TLSPAR_CIPHER_MATCH=0

  info "negotiation: version-match=${XRAY_TLSPAR_VER_MATCH}, ALPN-match=${XRAY_TLSPAR_ALPN_MATCH}, cipher-match=${XRAY_TLSPAR_CIPHER_MATCH} (server ${s_ver:-?}/${s_alpn:-none}, cover ${c_ver:-?}/${c_alpn:-none})"

  if [ "$XRAY_TLSPAR_VER_MATCH" = "1" ] && [ "$XRAY_TLSPAR_ALPN_MATCH" = "1" ] && [ "$XRAY_TLSPAR_CIPHER_MATCH" = "1" ]; then
    ok "TLS negotiation matches the genuine cover (version + ALPN + cipher) → relays cleanly"
    XRAY_TLSPAR_STATUS="ok"
  else
    warn "TLS negotiation differs from the genuine cover"
    XRAY_TLSPAR_STATUS="mismatch"
    add_verdict "Server's TLS negotiation (version/ALPN/cipher) does not match the genuine cover site — it doesn't fully impersonate the host its serverName claims, a fingerprint an active prober can use. Point Reality 'dest' at the exact cover the client's serverName expects (and confirm probes 15/20)"
  fi
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
    --arg env_vpn_ifs       "$ENV_VPN_IFACES" \
    --arg env_connected     "$ENV_CONNECTED_VPN" \
    --argjson env_on_vpn    "${ENV_ON_VPN:-0}" \
    --arg dns_sys_ips       "$DNS_SYS_IPS" \
    --arg dns_doh_ips       "$DNS_DOH_IPS" \
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
    --argjson openvpn_udp   "${OPENVPN_UDP_OK:-0}" \
    --argjson openvpn_tcp   "${OPENVPN_TCP_OK:-0}" \
    --arg openvpn_hs        "$OPENVPN_HANDSHAKE" \
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
    --arg xe_status         "$XRAY_EGRESS_STATUS" \
    --arg xe_country        "$XRAY_EGRESS_COUNTRY" \
    --arg xe_hosting        "$XRAY_EGRESS_HOSTING" \
    --arg xe_proxy          "$XRAY_EGRESS_PROXY" \
    --arg xe_mobile         "$XRAY_EGRESS_MOBILE" \
    --arg xe_dns_country    "$XRAY_EGRESS_DNS_COUNTRY" \
    --arg xst_status        "$XRAY_STABILITY_STATUS" \
    --arg xst_total         "$XRAY_STABILITY_TOTAL" \
    --arg xst_ok            "$XRAY_STABILITY_OK" \
    --arg xst_killed        "$XRAY_STABILITY_KILLED" \
    --arg xst_slow          "$XRAY_STABILITY_SLOW" \
    --arg xst_killbytes     "$XRAY_STABILITY_KILL_BYTES" \
    --arg xst_results       "$XRAY_STABILITY_RESULTS" \
    --arg xst_firstfail     "$XRAY_STABILITY_FIRST_FAIL_S" \
    --arg xst_rttmin        "$XRAY_STABILITY_RTT_MIN" \
    --arg xst_rttmax        "$XRAY_STABILITY_RTT_MAX" \
    --arg xl_status         "$XRAY_LINT_STATUS" \
    --arg xl_findings       "$XRAY_LINT_FINDINGS" \
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
    --arg xbb_status        "$XRAY_BUFFERBLOAT_STATUS" \
    --arg xbb_idle          "$XRAY_BUFFERBLOAT_IDLE_MS" \
    --arg xbb_load          "$XRAY_BUFFERBLOAT_LOAD_MS" \
    --arg xbb_inflate       "$XRAY_BUFFERBLOAT_INFLATE_MS" \
    --arg xbb_jitter        "$XRAY_BUFFERBLOAT_JITTER_MS" \
    --arg xmtu_status       "$XRAY_MTU_STATUS" \
    --arg xmtu_path         "$XRAY_MTU_PATH" \
    --arg xtp_status        "$XRAY_TLSPAR_STATUS" \
    --arg xtp_ver           "$XRAY_TLSPAR_VER_MATCH" \
    --arg xtp_alpn          "$XRAY_TLSPAR_ALPN_MATCH" \
    --arg xtp_cipher        "$XRAY_TLSPAR_CIPHER_MATCH" \
    --argjson verdicts      "$verdicts_json" '
    def words: split(" ") | map(select(length > 0));
    def opt(s): if s == "" then null else s end;
    def bool_int(n): n == 1;
    def tri_bool(n): if n < 0 then null else n == 1 end;
    {
      schema_version: 1,
      version: $version,
      timestamp: (now | todate),
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
          target_reachable: bool_int($tcp_target)
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
          quic_baseline_code: opt($udp_quic)
        },
        openvpn: {
          udp_port_accessible: bool_int($openvpn_udp),
          tcp_port_reachable: bool_int($openvpn_tcp),
          handshake_response_hex: opt($openvpn_hs)
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
        xray_egress: {
          status: opt($xe_status),
          country: opt($xe_country),
          hosting: tri_bool(($xe_hosting | tonumber? // -1)),
          proxy: tri_bool(($xe_proxy | tonumber? // -1)),
          mobile: tri_bool(($xe_mobile | tonumber? // -1)),
          dns_resolver_geo: opt($xe_dns_country)
        },
        xray_stability: {
          status: opt($xst_status),
          pulses_total: (if $xst_total == "" then null else ($xst_total | tonumber? // null) end),
          pulses_ok: (if $xst_ok == "" then null else ($xst_ok | tonumber? // null) end),
          pulses_killed: (if $xst_killed == "" then null else ($xst_killed | tonumber? // null) end),
          pulses_slow: (if $xst_slow == "" then null else ($xst_slow | tonumber? // null) end),
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
          cipher_match: tri_bool(($xtp_cipher | tonumber? // -1))
        }
      },
      verdicts: $verdicts
    }'
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
_should_run dns     && { probe_dns || true; }
_should_run tcp     && probe_tcp_reachability
_should_run tls     && probe_tls_handshake
_should_run ua      && probe_request_filter
_should_run rst     && probe_rst_injection
_should_run udp     && probe_udp_protocols
_should_run openvpn && probe_openvpn
_should_run control && probe_known_blocked
_should_run ipv6    && probe_ipv6
_should_run compare && probe_compare_matrix
_should_run xray    && probe_xray_protocol
_should_run xrayjson && probe_xray_json
_should_run xrayjson && probe_xray_throughput
_should_run xrayjson && probe_xray_speedtest
{ _should_run xray || _should_run xrayjson; } && probe_xray_cover
_should_run xrayjson && probe_xray_egress
_should_run xrayjson && probe_xray_stability
# Lint + clock-skew run in numeric position (after 17, before 20). They're
# static/cheap and their findings also surface in the consolidated verdict.
{ _should_run xray || _should_run xrayjson; } && probe_xray_lint
{ _should_run xray || _should_run xrayjson; } && probe_clock_skew
{ _should_run xray || _should_run xrayjson; } && probe_xray_active_probe
_should_run xrayjson && probe_xray_fleet
_should_run xrayjson && probe_xray_bufferbloat
{ _should_run xray || _should_run xrayjson; } && probe_xray_mtu
{ _should_run xray || _should_run xrayjson; } && probe_xray_tls_parity

# ---------- summary ----------

if [ "$JSON_MODE" = "1" ]; then
  _emit_json
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
  for v in "${VERDICTS[@]}"; do
    case "$v" in
      *"SNI"*)                    rec="try Reality / domain fronting / ECH-enabled client" ;;
      *"System DNS failure"*)     rec="use DoH inside the VPN client and check router/provider DNS" ;;
      *"DNS sinkhole"*)           rec="use DoH inside the VPN client, not system resolver" ;;
      *"DoH path is compromised"*) rec="self-host DoH or use a trusted resolver via VPN tunnel – upstream DoH is intercepted on this network" ;;
      *"DoT path is compromised"*) rec="DoH AND DoT both intercepted – use an out-of-band resolver inside the VPN tunnel, not local network DNS" ;;
      *"All DoH providers compromised"*) rec="network does universal DoH MITM (likely national-CA TLS interception) — encrypted DNS is unusable on this network, tunnel DNS over VPN" ;;
      *"Split DoH MITM"*) rec="at least one DoH provider is hijacked — switch DOH_URL to one of the honest providers in DOH_PROVIDERS for this session" ;;
      *"Domain unresolvable"*)    rec="verify the hostname and test from another resolver/network" ;;
      *"Network connectivity"*)   rec="check local internet/VPN state before interpreting target probes" ;;
      *"Target TCP reachability"*) rec="fix DNS first, then rerun transport probes" ;;
      *"IP route"*)               rec="rotate to a fresh IP / different /24" ;;
      *"Port 443"*)               rec="try TCP 8443, 2083, 2053 (Cloudflare-allowed ports)" ;;
      *"TLS DPI"*)                rec="switch to a non-TLS transport (Hysteria2, IKEv2, WG)" ;;
      *"TLS-record fragmentation"*) rec="exploit naive DPI reassembly: enable record splitting in your client (e.g. byedpi, GreenTunnel, custom uTLS profile)" ;;
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
      *"Reality cover is fake"*)  rec="server-side fix: point Reality 'dest' at the real cover host:443 and add it to 'serverNames' so unauthenticated probes get relayed to a genuine CA-valid cert" ;;
      *"Reality cover/serverName mismatch"*) rec="align the client 'serverName' with the server's Reality dest / serverNames" ;;
      *"Egress IP is on datacenter/proxy"*) rec="for streaming / payment / banking, route those flows through a residential or clean-IP egress; for censorship circumvention the current egress is fine" ;;
      *"delayed RST"*|*"kill-shaping"*) rec="rotate endpoint / cover SNI, shorten session reuse, or add traffic padding — the handshake is fine, the proven flow is being dropped" ;;
      *"intermittently fails"*)   rec="treat as a flaky path / congested egress, not a hard block; re-test from another vantage" ;;
      *) rec="" ;;
    esac
    [ -n "$rec" ] && _recs+=("$rec")
  done
  if [ "${#_recs[@]}" -gt 0 ]; then
    [ "$LOG_QUIET" = "1" ] || printf '\n%s\n' "${YEL}Recommendation:${RST}"
    for rec in "${_recs[@]}"; do
      [ "$LOG_QUIET" = "1" ] || printf "  → %s\n" "$rec"
      _log_line REC "$rec"
    done
  fi
fi

[ "$LOG_QUIET" = "1" ] || printf '\n%s\n' "${DIM}Done.${RST}"
_log_line DONE "$VPN_HOST"
