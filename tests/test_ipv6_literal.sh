#!/usr/bin/env bash
#
# tests/test_ipv6_literal.sh — IPv6-literal endpoints must parse correctly
# (not mangle to "[2001") and short-circuit DNS like IPv4 literals do. Uses
# RFC 3849 documentation addresses (2001:db8::/32) — no real host contacted.

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }

# Case A — [v6]:port in a share-link URL → host parsed bare, port extracted.
out=$(TIMEOUT=1 bash "$SCRIPT" \
      --xray-config 'vless://00000000-0000-0000-0000-000000000000@[2001:db8::1]:8443?security=reality&pbk=AAAA&sid=01&sni=www.example.com&fp=chrome&type=tcp' \
      --only xray --json 2>/dev/null)
host=$(printf '%s' "$out" | jq -r '.target.host')
port=$(printf '%s' "$out" | jq -r '.target.port_tcp')
[ "$host" = "2001:db8::1" ] || fail "IPv6 host mangled: got '$host' (want 2001:db8::1)"
[ "$port" = "8443" ]        || fail "IPv6 port not derived: got '$port' (want 8443)"

# Case B — [v6] with no port → host parsed, port falls back to the default.
out=$(TIMEOUT=1 bash "$SCRIPT" \
      --xray-config 'vless://00000000-0000-0000-0000-000000000000@[2001:db8::5]?security=reality&pbk=AAAA&sni=www.example.com&type=tcp' \
      --only xray --json 2>/dev/null)
[ "$(printf '%s' "$out" | jq -r '.target.host')" = "2001:db8::5" ] \
  || fail "IPv6 host (no port) mangled"

# Case C — a bare IPv6 literal as VPN_HOST short-circuits DNS (resolved_ip is
# the literal, not null/unresolvable).
out=$(VPN_HOST='2001:db8::9' TIMEOUT=1 bash "$SCRIPT" --only dns,tcp --json 2>/dev/null)
rip=$(printf '%s' "$out" | jq -r '.target.resolved_ip')
[ "$rip" = "2001:db8::9" ] \
  || fail "IPv6 literal not short-circuited in DNS: resolved_ip='$rip'"

echo "PASS: IPv6-literal endpoints parse correctly (host/port) + short-circuit DNS"
