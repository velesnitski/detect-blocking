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
#   ./detect_blocking.sh my-vpn.example.com    # CLI override of VPN_HOST
#   VPN_HOST=h.example.com ./detect_blocking.sh
#   ./detect_blocking.sh --log-file /tmp/d.log --quiet
#   CONFIG_FILE=/path/to/file ./detect_blocking.sh
#
# Precedence: CLI arg > env var > config file > built-in default.
# See detect_blocking.conf.example for all knobs (including STRICT_OPENVPN_VERDICT).

set -u

readonly DETECT_BLOCKING_VERSION="0.1.0"

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

while [ $# -gt 0 ]; do
  case "$1" in
    --log-file)   LOG_FILE="${2:-}"; shift 2 ;;
    --log-file=*) LOG_FILE="${1#--log-file=}"; shift ;;
    --only)       ONLY_PROBES="${2:-}"; shift 2 ;;
    --only=*)     ONLY_PROBES="${1#--only=}"; shift ;;
    --skip)       SKIP_PROBES="${2:-}"; shift 2 ;;
    --skip=*)     SKIP_PROBES="${1#--skip=}"; shift ;;
    --quiet|-q)   LOG_QUIET=1; shift ;;
    --json)       JSON_MODE=1; LOG_QUIET=1; shift ;;
    --version|-V)
      printf 'detect_blocking %s\n' "$DETECT_BLOCKING_VERSION"
      exit 0
      ;;
    --help|-h)
      sed -n '2,27p' "$0"
      printf '\nversion: %s\n' "$DETECT_BLOCKING_VERSION"
      printf '\nProbe names (for --only / --skip): env, dns, tcp, tls, ua, rst, udp, openvpn, control\n'
      printf '\nFlags: --json (requires jq), --quiet/-q, --log-file PATH, --only LIST, --skip LIST\n'
      exit 0
      ;;
    -*) die "unknown option: $1" ;;
    *)  VPN_HOST="${1}"; shift ;;
  esac
done

if [ "$JSON_MODE" = "1" ]; then
  check_cmd jq || die "--json requires jq (install: brew install jq / apt-get install jq)"
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
       && [ -z "$impersonate_cmd" -o "$curl_impersonate" = "000" ]; then
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
          dot_integrity: {state: opt($dot_state), returned: ($dot_ips | words)}
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
        }
      },
      verdicts: $verdicts
    }'
}

# ---------- main ----------

_init_log

# Clean up probe-5 temp files even if the run is interrupted (Ctrl-C) mid-probe.
trap 'rm -f "$RST_TMP_OUT" "$RST_TMP_TIME" 2>/dev/null' EXIT

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
