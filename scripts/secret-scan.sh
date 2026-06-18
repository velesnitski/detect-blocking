#!/usr/bin/env bash
#
# scripts/secret-scan.sh — block real credentials / fleet infra from entering this
# PUBLIC repo. Two layers:
#   (1) explicit banned strings — known fleet infra (products, hosts, IPs, ids).
#   (2) GENERIC credential patterns in config context — so a NEW real id / key / IP
#       that isn't on the banned list is still caught (the gap that let a real
#       VLESS id slip into a fixture before the list covered it).
# Obvious placeholders (all-zero UUID, all-`A` pubkey, RFC1918 / TEST-NET / loopback
# / public-DNS-baseline IPs) are allowlisted so the scan stays low-noise.
#
# Usage:
#   secret-scan.sh [FILE...]   scan the given files (default: all git-tracked)
#   secret-scan.sh --staged    scan staged additions (for the pre-commit hook)
# Exit 0 = clean, 1 = potential secret found.
set -u

# ---- layer 1: explicit banned strings (known fleet infra) ----
BANNED='REDACTED-PRODUCT|REDACTED-PRODUCT|REDACTED-PRODUCT|REDACTED-PRODUCT|REDACTED-PROVIDER|REDACTED-PROVIDER|REDACTED-PROVIDER|REDACTED-PROVIDER|REDACTED-PROVIDER|REDACTED-PRODUCT|REDACTED-PROVIDER|blocked-rkn|REDACTED-DOMAIN|relay-b|relay-a|REDACTED-CREDENTIAL|REDACTED|REDACTED-CREDENTIAL|REDACTED-CREDENTIAL|REDACTED-CREDENTIAL|REDACTED|REDACTED-CREDENTIAL|REDACTED-CREDENTIAL|REDACTED-CREDENTIAL|REDACTED-CREDENTIAL|203\.0\.113\.|203\.0\.113\.|198\.51\.100\.|203\.0\.113\.|203\.0\.113\.|203\.0\.113\.9|203\.0\.113\.8'

# ---- collect files ----
files=()
if [ "${1:-}" = "--staged" ]; then
  while IFS= read -r f; do files+=("$f"); done < <(git diff --cached --name-only --diff-filter=ACM 2>/dev/null)
elif [ "$#" -gt 0 ]; then
  files=("$@")
else
  # Tracked AND untracked-but-not-ignored: a brand-new file holding a secret is
  # the highest-risk case, yet `git ls-files` alone (tracked only) would skip it
  # until it's staged — so the no-arg scan would give a false "clean".
  while IFS= read -r f; do files+=("$f"); done < <(git ls-files 2>/dev/null; git ls-files --others --exclude-standard 2>/dev/null)
fi
[ "${#files[@]}" -eq 0 ] && { echo "secret-scan: nothing to scan"; exit 0; }

# A non-RFC1918 / non-reserved / non-baseline IPv4 is "public" → suspicious in a config.
_is_public_ip() {
  case "$1" in
    10.*|127.*|192.168.*|169.254.*|0.*|255.255.255.255) return 1 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*)               return 1 ;;
    192.0.2.*|198.51.100.*|203.0.113.*)                  return 1 ;;  # TEST-NET-1/2/3
    1.1.1.1|1.0.0.1|8.8.8.8|8.8.4.4|9.9.9.9)             return 1 ;;  # DNS baselines
    22[4-9].*|23[0-9].*|24[0-9].*|25[0-5].*)             return 1 ;;  # multicast/reserved
    *) return 0 ;;
  esac
}

findings=$(mktemp "${TMPDIR:-/tmp}/secret-scan.XXXXXX") || exit 2
for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  case "$f" in *secret-scan.sh) continue ;; esac   # don't scan self (holds the banned list)
  {
    # (1) banned strings, anywhere
    grep -niE "$BANNED" "$f" 2>/dev/null | sed "s#^#${f} [banned] #"

    # (2a) real UUID (not the all-zero / all-one placeholder family)
    grep -niE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' "$f" 2>/dev/null \
      | grep -viE '00000000-0000-0000-0000-|11111111-1111-1111-1111-|deadbeef-' \
      | sed "s#^#${f} [uuid] #"

    # (2b) real Reality public key (43-char base64url after publicKey/pbk). A real
    #      key is high-entropy; placeholders (AAAA…, 0000…, TESTPUBKEYxxx…) have an
    #      8+ run of one char or a "test" marker — allowlist those.
    grep -noE '(publicKey"?[[:space:]]*[:=][[:space:]]*"?|pbk=)[A-Za-z0-9_-]{43}' "$f" 2>/dev/null \
      | grep -vE 'A{8,}|0{8,}|x{8,}|X{8,}|[Tt][Ee][Ss][Tt]' \
      | sed "s#^#${f} [pubkey] #"

    # (2c) real public server IP in a config address context ("address":"IP" or @IP:)
    while IFS= read -r ipline; do
      ip=$(printf '%s' "$ipline" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | tail -1)
      [ -n "$ip" ] && _is_public_ip "$ip" && printf '%s [public-ip] %s\n' "$f" "$ipline"
    done < <(grep -noE '("address"[[:space:]]*:[[:space:]]*"|@)([0-9]{1,3}\.){3}[0-9]{1,3}' "$f" 2>/dev/null)
  } >> "$findings"
done

if [ -s "$findings" ]; then
  echo "secret-scan: POTENTIAL SECRET(S) — do NOT commit/push:" >&2
  sed 's/^/  /' "$findings" >&2
  rm -f "$findings"
  exit 1
fi
rm -f "$findings"
echo "secret-scan: clean (${#files[@]} file(s) scanned)"
exit 0
