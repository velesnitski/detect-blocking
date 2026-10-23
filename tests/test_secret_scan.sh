#!/usr/bin/env bash
#
# tests/test_secret_scan.sh — the guard must never report clean without reading
# files. Covers the empty-file-set paths (a no-arg run outside a work tree used to
# print a clean verdict having scanned nothing, because `git ls-files` is silently
# empty there) and asserts the scanner is still not vacuous: a config-shaped id and
# public address must trip it.
#
# The "bad" values are ASSEMBLED AT RUNTIME from fragments: a literal UUID or dotted
# quad in this file would be caught by the very scanner under test, and by the repo
# data guard, since this file is itself tracked and scanned.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCAN="$SCRIPT_DIR/scripts/secret-scan.sh"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
out=""; rc=0
fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }

[ -r "$SCAN" ] || { echo "SKIP: secret-scan.sh not found"; exit 0; }

# ---- 1. no-arg run OUTSIDE a git work tree must REFUSE ----
# The regression: nothing collected, so the scan exited 0 without opening a file.
out=$(cd "$TMP" && bash "$SCAN" 2>&1); rc=$?
[ "$rc" -ne 0 ] || fail "outside a work tree: expected non-zero exit, got $rc"
printf '%s' "$out" | grep -qi 'refusing to report clean' \
  || fail "outside a work tree: must state that it refuses"
if printf '%s' "$out" | grep -qi 'clean ('; then
  fail "outside a work tree: must not print a clean verdict"
fi

# ---- 2. explicit paths that cannot be read must REFUSE ----
out=$(bash "$SCAN" "$TMP/does-not-exist.json" 2>&1); rc=$?
[ "$rc" -ne 0 ] || fail "unreadable explicit path: expected non-zero exit, got $rc"
printf '%s' "$out" | grep -q 'READ NONE' \
  || fail "unreadable explicit path: must report that it read none"

# ---- 3. a placeholder-only file is clean, counted by files actually READ ----
printf '{"address":"127.0.0.1","id":"00000000-0000-0000-0000-000000000000"}\n' > "$TMP/ok.json"
out=$(bash "$SCAN" "$TMP/ok.json" 2>&1); rc=$?
[ "$rc" -eq 0 ] || fail "placeholder file: expected exit 0, got $rc"
printf '%s' "$out" | grep -q '1 file(s) scanned' \
  || fail "placeholder file: must report exactly 1 file scanned"

# ---- 4. NOT VACUOUS: a config-shaped id + public address must still be caught ----
# Assembled here so no scannable literal exists in this file (see header).
_a=7f3a9c2e; _b=4b1d; _c=4e8a; _d=9c3f; _e=2d5b8e1a6f40
bad_id="${_a}-${_b}-${_c}-${_d}-${_e}"
_net=198.18; bad_ip="${_net}.7.9"          # RFC 2544 benchmarking range, not routed
printf '{"address":"%s","id":"%s"}\n' "$bad_ip" "$bad_id" > "$TMP/bad.json"
out=$(bash "$SCAN" "$TMP/bad.json" 2>&1); rc=$?
[ "$rc" -eq 1 ] || fail "planted secret: expected exit 1, got $rc"
printf '%s' "$out" | grep -q 'uuid'      || fail "planted secret: the id was not reported"
printf '%s' "$out" | grep -q 'public-ip' || fail "planted secret: the address was not reported"

# ---- 5. --staged with nothing staged is benign, but must not read as a verdict ----
out=$(cd "$SCRIPT_DIR" && bash "$SCAN" --staged 2>&1); rc=$?
[ "$rc" -eq 0 ] || fail "--staged with an empty set: expected exit 0, got $rc"
if printf '%s' "$out" | grep -q 'nothing to scan'; then
  fail "--staged: the old ambiguous wording is back"
fi

echo "PASS: secret-scan refuses to report clean without reading files"
