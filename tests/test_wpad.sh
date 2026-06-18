#!/usr/bin/env bash
#
# tests/test_wpad.sh — _wpad pads/truncates to a fixed DISPLAY width (not bytes),
# which is what keeps the fleet table aligned when remarks hold Cyrillic / emoji.
# We extract just that helper (same awk trick as the other helper tests) and check
# the padded output's CHARACTER count (via `wc -m` under a UTF-8 locale) equals the
# target width — for ASCII, Cyrillic, and a flag emoji — plus ellipsis truncation.
# Skipped without perl (the byte-pad fallback intentionally can't do display width).
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
command -v perl >/dev/null 2>&1 || { echo "SKIP: perl not installed (byte-pad fallback has no display width)"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }
fn=$(awk '/^_wpad\(\)/,/^}/' "$SCRIPT"); [ -n "$fn" ] || fail "could not extract _wpad"
eval "$fn"

# Display-character count (multibyte) under a UTF-8 locale.
cnt() { LC_ALL=en_US.UTF-8 printf '%s' "$1" | LC_ALL=en_US.UTF-8 wc -m | tr -d '[:space:]'; }

out=$(_wpad "abc" 10);  [ "$(cnt "$out")" = 10 ] || fail "ASCII should pad to 10 display chars (got $(cnt "$out"))"
case "$out" in "abc"*) : ;; *) fail "padded value must start with the original string" ;; esac

out=$(_wpad "АБВ" 8);   [ "$(cnt "$out")" = 8 ]  || fail "Cyrillic should pad to 8 display chars, not bytes (got $(cnt "$out"))"
out=$(_wpad "АБВ 🇫🇮" 12); [ "$(cnt "$out")" = 12 ] || fail "Cyrillic+flag should pad to 12 display chars (got $(cnt "$out"))"

# longer than width → truncated to exactly width, ending in an ellipsis
out=$(_wpad "Самый Быстрый АВТО Резерв" 10)
[ "$(cnt "$out")" = 10 ] || fail "over-long string should truncate to exactly 10 chars (got $(cnt "$out"))"
case "$out" in *"…") : ;; *) fail "truncated string should end with an ellipsis (got '$out')" ;; esac

echo "PASS: _wpad pads/truncates to a fixed DISPLAY width across ASCII / Cyrillic / emoji"
