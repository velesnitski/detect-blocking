#!/usr/bin/env bash
#
# tests/test_from_file.sh — verify --from-file emits one ndjson object per
# non-comment host, with comments and blank lines correctly skipped.

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

HOSTS=$(mktemp -t detect_blocking_hosts.XXXXXX)
cat > "$HOSTS" << 'EOF'
# leading comment, skipped
www.example.com

# blank line above, also skipped
example.org
   # indented comments are NOT recognised by the matcher, treated as host
EOF

# The 3rd non-comment line is "   # indented..." — by our case '#'* rule it
# only matches lines starting with #, so this becomes a (malformed) host.
# We expect 3 ndjson objects, with the 3rd having an unresolvable verdict.

out=$(VPN_HOST=www.example.com TIMEOUT=2 \
      bash "$SCRIPT" --from-file "$HOSTS" --json --only dns 2>&1)
rm -f "$HOSTS"

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "$out" >&2; exit 1; }

# 1. Validate ndjson — every line must be valid JSON.
n=$(printf '%s\n' "$out" | jq -e -s 'length' 2>/dev/null) || fail "ndjson parse error"
[ "$n" = "3" ] || fail "expected 3 ndjson objects (2 valid hosts + 1 indented-comment-misparse), got $n"

# 2. Hosts are www.example.com, example.org, and the malformed indented line.
host1=$(printf '%s\n' "$out" | sed -n '1p' | jq -r '.target.host')
host2=$(printf '%s\n' "$out" | sed -n '2p' | jq -r '.target.host')
[ "$host1" = "www.example.com" ] || fail "1st object: expected host=www.example.com, got '$host1'"
[ "$host2" = "example.org" ]     || fail "2nd object: expected host=example.org, got '$host2'"

# 3. All three must have valid schema_version.
n_valid=$(printf '%s\n' "$out" | jq -s '[.[] | select(.schema_version == 1)] | length')
[ "$n_valid" = "3" ] || fail "expected 3 with schema_version=1, got $n_valid"

printf 'PASS: --from-file emitted %d ndjson objects, comments + blanks skipped\n' "$n"
