#!/usr/bin/env bash
#
# tests/test_target_normalize.sh — a URL or host:port target must be normalized to a
# bare host, not turned into a censorship verdict.
#
# This tool takes a HOST, but --xray-config takes a URL, so pasting
# "https://host/path" into the positional slot is a natural slip. It used to be
# misleadingly fatal: the whole string went to DNS, resolved to nothing, and the run
# concluded "Domain unresolvable (DoH also blocked or domain offline)" about a healthy
# domain — then advised debugging the resolver, while every transport probe skipped as
# collateral. Seen on a real run against a live, reachable host.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

eval "$(awk '/^_normalize_target\(\)/,/^}/' "$SCRIPT")"
n() { _normalize_target "$1" | tr '\t' '|'; }

# ---- URLs: scheme, path, query, fragment, credentials all stripped ----
[ "$(n 'https://host.tld/')"              = "host.tld|" ]      || fail "https URL -> host"
[ "$(n 'http://host.tld/a/b?q=1#frag')"   = "host.tld|" ]      || fail "URL with path/query/fragment -> host"
[ "$(n 'https://host.tld:8443/path')"     = "host.tld|8443" ]  || fail "URL with port -> host+port"
[ "$(n 'vless://user@host.tld:443?x=1')"  = "host.tld|443" ]   || fail "any scheme + credentials -> host+port"
[ "$(n 'user:pw@host.tld')"               = "host.tld|" ]      || fail "credentials without scheme -> host"
[ "$(n 'host.tld/some/path')"             = "host.tld|" ]      || fail "bare host with path -> host"

# ---- host:port ----
[ "$(n 'host.tld:443')"                   = "host.tld|443" ]   || fail "host:port -> host+port"
[ "$(n '1.2.3.4:9000')"                   = "1.2.3.4|9000" ]   || fail "ip:port -> ip+port"

# ---- must NOT mangle what is already correct ----
[ "$(n 'host.tld')"                       = "host.tld|" ]      || fail "plain host must pass through unchanged"
[ "$(n '1.2.3.4')"                        = "1.2.3.4|" ]       || fail "plain IPv4 must pass through unchanged"
# a bare IPv6 literal is full of colons — none of them is a port
[ "$(n '2001:db8::1')"                    = "2001:db8::1|" ]   || fail "bare IPv6 must pass through unchanged"
[ "$(n '[2001:db8::1]:443')"              = "2001:db8::1|443" ]|| fail "bracketed IPv6 + port -> host+port"
# a non-numeric ':suffix' is not a port
[ "$(n 'host.tld:notaport')"              = "host.tld|" ]      || fail "non-numeric port must be discarded, host kept"

# ---- refuse to normalize into a non-host: leave such input completely alone ----
# A batch input line may be arbitrary text (the --from-file matcher deliberately treats
# an indented comment as a host). Stripping a "#fragment" out of that reduced it to
# whitespace and silently replaced the target, so the guard returns the ORIGINAL string.
[ "$(n '   # indented comment, treated as host')" = "   # indented comment, treated as host|" ] \
  || fail "input that cannot be reduced to a host must be returned untouched"
[ "$(n 'has spaces in it')" = "has spaces in it|" ] || fail "spaced text must be returned untouched"
[ "$(n '')" = "|" ]                                || fail "empty input must stay empty"

# ---- integration: the loopback URL form must not produce a DNS-block verdict ----
if command -v jq >/dev/null 2>&1; then
  out=$(TIMEOUT=3 bash "$SCRIPT" --only dns,tcp 'https://127.0.0.1/' --json 2>/dev/null)
  [ "$(printf '%s' "$out" | jq -r '.target.host')" = "127.0.0.1" ] \
    || fail "a URL target must be normalized before it reaches .target.host"
  [ "$(printf '%s' "$out" | jq -r '[.verdicts[]?|select(test("unresolvable"))]|length')" = "0" ] \
    || fail "a URL target must NOT yield a 'domain unresolvable' verdict"
  # and the run must say what it did, rather than silently probing something else
  TIMEOUT=3 bash "$SCRIPT" --only dns 'https://127.0.0.1/' 2>&1 | grep -q "note: target" \
    || fail "normalization must be announced"
  # a plain host must not trigger the note
  TIMEOUT=3 bash "$SCRIPT" --only dns 127.0.0.1 2>&1 | grep -q "note: target" \
    && fail "a plain host must not emit the normalization note"
fi

echo "PASS: target normalization — URL/host:port reduced to a bare host (announced), IPv6 and plain hosts untouched, no false 'unresolvable' verdict"
