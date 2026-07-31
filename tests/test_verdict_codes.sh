#!/usr/bin/env bash
#
# tests/test_verdict_codes.sh — verdicts carry a stable machine CODE, and the
# consumers key off that code instead of the prose.
#
# Why this exists: verdict wording is explicitly NOT part of the 1.x contract, yet
# consumers used to match it with globs. Rewording a verdict therefore had invisible
# consequences — a recommendation silently detaching (seen live: a broad `*"SNI"*`
# glob swallowing three unrelated verdicts), or, worse, the false-positive SUPPRESSOR
# failing to cancel a verdict, resurfacing "likely full IP block — rotate your
# endpoint" for a tunnel later probes proved healthy. Codes make wording free to change.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

# ---- unit: add_verdict accepts CODE + text, and detects an uncoded legacy call ----
VERDICTS=(); VERDICT_CODES=(); LOG_FILE=""
_log_line() { :; }
eval "$(awk '/^add_verdict\(\)/,/^}/' "$SCRIPT")"
eval "$(awk '/^_has_verdict_code\(\)/,/^}/' "$SCRIPT")"

add_verdict some-code "a coded verdict"
[ "${VERDICTS[0]}" = "a coded verdict" ] || fail "coded call: text must be stored without the code"
[ "${VERDICT_CODES[0]}" = "some-code" ]  || fail "coded call: code must be recorded"

add_verdict "an uncoded verdict with spaces"
[ "${VERDICTS[1]}" = "an uncoded verdict with spaces" ] || fail "uncoded call: text must be stored verbatim"
[ -z "${VERDICT_CODES[1]}" ]                            || fail "uncoded call: code must be empty, not the text"

# the arrays must stay the same length — they are indexed in parallel
[ "${#VERDICTS[@]}" = "${#VERDICT_CODES[@]}" ] || fail "VERDICTS and VERDICT_CODES must stay parallel"

# ---- unit: the code lookup ----
_has_verdict_code some-code || fail "_has_verdict_code must find a recorded code"
_has_verdict_code nope-code && fail "_has_verdict_code must not match an absent code"

# ---- static: the suppressor must key on CODES, never on verdict prose ----
supp=$(awk '/_vkept=\(\); _ckept=\(\)/,/VERDICT_CODES=\("\$\{_ckept\[@\]\}"\)/' "$SCRIPT")
[ -n "$supp" ] || fail "could not locate the false-positive suppressor block"
printf '%s' "$supp" | grep -q 'transport-silent-drop' \
  || fail "suppressor should match the silent-drop verdict by CODE"
printf '%s' "$supp" | grep -q 'data-plane-dead' \
  || fail "suppressor should match the dead-data-plane verdict by CODE"
printf '%s' "$supp" | grep -qE '\*"(Silent packet drop|data plane is unusable)' \
  && fail "suppressor must NOT match verdict PROSE any more (that is the bug codes remove)"
# and it must rebuild BOTH arrays, or codes desynchronise from verdicts
printf '%s' "$supp" | grep -q '_ckept+=' \
  || fail "suppressor must filter VERDICT_CODES in lockstep with VERDICTS"

# ---- the codes the suppressor depends on must actually be emitted somewhere ----
for c in transport-silent-drop data-plane-dead; do
  grep -q "add_verdict $c " "$SCRIPT" \
    || fail "no add_verdict call emits the code '$c' the suppressor keys on"
done

# ---- integration: a run still emits verdicts, and codes stay parallel in JSON ----
if command -v jq >/dev/null 2>&1; then
  out=$(TIMEOUT=3 bash "$SCRIPT" --only dns,tcp 127.0.0.1 --json 2>/dev/null)
  printf '%s' "$out" | jq -e '.verdicts | type == "array"' >/dev/null \
    || fail "the frozen .verdicts string array must survive unchanged"
fi

echo "PASS: verdict codes — add_verdict records CODE+text, suppressor keys on codes (not prose) and filters both arrays in lockstep"
