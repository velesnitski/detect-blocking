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

readonly DETECT_BLOCKING_VERSION="0.2.0"

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
    --quiet|-q)    LOG_QUIET=1; shift ;;
    --json)        JSON_MODE=1; LOG_QUIET=1; shift ;;
    --version|-V)
      printf 'detect_blocking %s\n' "$DETECT_BLOCKING_VERSION"
      exit 0
      ;;
    --help|-h)
      sed -n '2,27p' "$0"
      printf '\nversion: %s\n' "$DETECT_BLOCKING_VERSION"
      printf '\nProbe names (for --only / --skip): env, dns, tcp, tls, ua, rst, udp, openvpn, control, ipv6, compare, xray\n'
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

  if [ "$xk_layout" = "v10" ]; then
    out=$("$XRAY_TESTER_BIN" http -c "$XRAY_CONFIG" \
          -d $(( TIMEOUT * 1000 )) 2>&1 || true)
  else
    out=$("$XRAY_TESTER_BIN" net http -c "$XRAY_CONFIG" \
          -m 1 -d $(( TIMEOUT * 1000 )) 2>&1 || true)
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

  if [ "$XRAY_STATUS" = "ok" ]; then
    ok "tunnel established, RTT ${XRAY_RTT_MS} ms${XRAY_TARGET_LOC:+ (egress: $XRAY_TARGET_LOC)}"
    # Cross-reference: tunnel works despite our other probes seeing DPI.
    if [ "${TLS_PROPER_SNI_OK:-1}" = "0" ] || [ "${DOH_INTEGRITY_STATE:-ok}" = "compromised" ]; then
      add_verdict "Xray protocol bypasses local DPI/DNS-MITM despite environment signals"
    fi
  else
    fail "Xray-protocol end-to-end test failed"
    # Surface a 1-line excerpt of the delegation output to help triage
    # parse/config errors vs network errors. Trim leading whitespace,
    # take the first non-empty line that looks informative.
    local _diag
    _diag=$(printf '%s\n' "$out" \
            | grep -iE 'error|failed|timeout|invalid|refused|unable' \
            | head -1 | sed 's|^[[:space:]│|]*||' | head -c 200)
    [ -n "$_diag" ] && info "$XRAY_TESTER_BIN says: $_diag"
    if [ "${TCP_OK:-1}" = "1" ]; then
      if [ "${TLS_PROPER_SNI_OK:-0}" = "1" ]; then
        # TCP + TLS to the server work but the protocol doesn't — strong signal.
        add_verdict "Xray-protocol handshake fails while plain TLS to the same host succeeds — protocol-fingerprint DPI or config error"
      else
        add_verdict "Xray-protocol handshake fails — see probes 2-3 for root cause"
      fi
    else
      info "TCP to target was already blocked; protocol failure is consistent"
    fi
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
          url_display: opt($xray_url_display)
        }
      },
      verdicts: $verdicts
    }'
}

# ---------- main ----------

_init_log

# Cleanup trap: probe-5 temp files + optional tcpdump capture (--pcap).
_cleanup() {
  rm -f "$RST_TMP_OUT" "$RST_TMP_TIME" 2>/dev/null
  [ -n "$PCAP_PID" ] && kill "$PCAP_PID" 2>/dev/null
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

  [ "$LOG_QUIET" = "1" ] || printf '\n%s\n' "${YEL}Recommendation:${RST}"
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
      *) rec="" ;;
    esac
    if [ -n "$rec" ]; then
      [ "$LOG_QUIET" = "1" ] || printf "  → %s\n" "$rec"
      _log_line REC "$rec"
    fi
  done
fi

[ "$LOG_QUIET" = "1" ] || printf '\n%s\n' "${DIM}Done.${RST}"
_log_line DONE "$VPN_HOST"
