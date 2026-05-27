#!/usr/bin/env bash
# tests/run.sh — run every test_*.sh in this directory.
set -u

DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

fails=0
for t in "$DIR"/test_*.sh; do
  printf '==> %s\n' "$(basename "$t")"
  if bash "$t"; then
    :
  else
    fails=$((fails + 1))
  fi
  echo
done

if [ "$fails" -ne 0 ]; then
  printf '%d test(s) failed\n' "$fails" >&2
  exit 1
fi

echo "All tests passed."
