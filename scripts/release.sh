#!/usr/bin/env bash
#
# scripts/release.sh — cut a detect-blocking release with the full gate.
#
#   Usage:  scripts/release.sh <X.Y.Z>
#
# Assumes you've already made the change + added a `## [X.Y.Z]` CHANGELOG section
# on the `dev` branch. It then: runs the hard checks (syntax + shellcheck +
# secret-scan), bumps the version constant, commits any pending work as the release
# commit (with the CHANGELOG notes), fast-forwards main, tags, and publishes the
# GitHub release. Fails loudly and does nothing partial on a failed gate.
set -euo pipefail
cd -- "$(dirname -- "$0")/.."

ver="${1:-}"
[ -n "$ver" ] || { echo "usage: scripts/release.sh <X.Y.Z>  (e.g. 1.4.0)" >&2; exit 2; }
printf '%s' "$ver" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' || { echo "version must be X.Y.Z" >&2; exit 2; }

branch=$(git rev-parse --abbrev-ref HEAD)
[ "$branch" = dev ] || { echo "release from 'dev' (currently on '$branch')" >&2; exit 2; }

grep -qE "^## \[$ver\]" CHANGELOG.md \
  || { echo "CHANGELOG.md has no '## [$ver]' section — add one first" >&2; exit 2; }

# --- hard gate (same checks CI + the standing workflow enforce) ---
echo "→ syntax + shellcheck + secret-scan"
bash -n detect_blocking.sh
shellcheck -S warning detect_blocking.sh
bash scripts/secret-scan.sh

# --- bump the version constant (idempotent) ---
cur=$(grep -m1 -oE 'DETECT_BLOCKING_VERSION="[0-9.]+"' detect_blocking.sh | grep -oE '[0-9.]+')
if [ "$cur" != "$ver" ]; then
  sed -i.bak "s/DETECT_BLOCKING_VERSION=\"${cur}\"/DETECT_BLOCKING_VERSION=\"${ver}\"/" detect_blocking.sh
  rm -f detect_blocking.sh.bak
fi
grep -q "DETECT_BLOCKING_VERSION=\"${ver}\"" detect_blocking.sh || { echo "version bump failed" >&2; exit 2; }

# --- the CHANGELOG notes for this version (used as commit body + release notes) ---
notes=$(awk -v v="$ver" '
  $0 ~ "^## \\[" v "\\]" {f=1; next}
  /^## \[/ {f=0}
  f {print}' CHANGELOG.md)

# --- commit pending work, ff main, tag, publish ---
git add -A
if ! git diff --cached --quiet; then
  git commit -q -m "Release ${ver}

${notes}

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
fi
git push -q origin dev
git checkout -q main
git merge -q --ff-only dev
git push -q origin main
git tag -a "v${ver}" -m "v${ver}"
git push -q origin "v${ver}"
git checkout -q dev

gh release create "v${ver}" --title "v${ver}" --notes "${notes:-see CHANGELOG.md}"
echo "✓ released v${ver}"
