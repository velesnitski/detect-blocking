#!/usr/bin/env bash
#
# scripts/install-hooks.sh — install a local pre-commit hook that runs the secret
# scanner on staged changes, so a credential/infra leak is blocked BEFORE it ever
# reaches a commit (CI catches it too, but the hook stops it at the source). Opt-in:
# run this once after cloning.
set -u
root=$(git rev-parse --show-toplevel 2>/dev/null) || { echo "not inside a git repo" >&2; exit 1; }
hook="$root/.git/hooks/pre-commit"
cat > "$hook" <<'HOOK'
#!/usr/bin/env bash
# detect-blocking: block leaked credentials / fleet infra before they're committed.
exec "$(git rev-parse --show-toplevel)/scripts/secret-scan.sh" --staged
HOOK
chmod +x "$hook"
echo "installed pre-commit hook → scripts/secret-scan.sh --staged"
