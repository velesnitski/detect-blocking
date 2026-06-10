#!/usr/bin/env bash
#
# tests/test_hysteria.sh — Hysteria2 (QUIC/UDP) static analyzer. Hysteria2 is a
# different stack from Xray (no Reality cover, UDP/443), so it gets its own
# probe_hysteria instead of the Xray probes. We feed synthetic client configs
# (.invalid hosts → never resolve → offline + deterministic; no real names) and
# assert the static JSON fields: SNI-keyword tell, explicit-SNI, obfs, insecure.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"

command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; printf '%s\n' "${out:-}" >&2; exit 1; }
hy()   { printf '%s' "$1" | jq -c '.probes.hysteria'; }

tmp=$(mktemp -d -t detect_blocking.hytest.XXXXXX) || { echo "FAIL: mktemp"; exit 1; }
trap 'rm -rf "$tmp"' EXIT

# --- Case A: YAML, dedicated host carries a protocol keyword, no tls.sni, no obfs.
#     → detected; status ok; sni_keyword true (host "hysteria2.invalid" → "hysteria");
#       sni_explicit false; obfs false; insecure false. ---
cat > "$tmp/a.yml" <<'EOF'
server: hysteria2.invalid:443
auth: TESTTOKEN
socks5:
  listen: 127.0.0.1:1180
EOF
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$tmp/a.yml" --json 2>/dev/null)
[ "$(hy "$out" | jq -r '.status')" = "ok" ]          || fail "A: hysteria YAML should be detected (status ok)"
[ "$(hy "$out" | jq -r '.sni_keyword')" = "true" ]   || fail "A: keyword in host SNI should flag sni_keyword"
[ "$(hy "$out" | jq -r '.sni_explicit')" = "false" ] || fail "A: no tls.sni → sni_explicit false"
[ "$(hy "$out" | jq -r '.obfs')" = "false" ]         || fail "A: no obfs → obfs false"
[ "$(hy "$out" | jq -r '.insecure')" = "false" ]     || fail "A: no insecure → insecure false"
hy "$out" | jq -e 'has("status") and has("sni_keyword") and has("sni_explicit") and has("obfs") and has("insecure")' >/dev/null \
  || fail "A: hysteria JSON schema missing keys"

# --- Case B: YAML, innocuous explicit tls.sni + obfs salamander → clean shape.
#     → sni_keyword false; sni_explicit true; obfs true; insecure false. ---
cat > "$tmp/b.yml" <<'EOF'
server: gw.invalid:443
auth: TESTTOKEN
tls:
  sni: www.bing.com
  insecure: false
obfs:
  type: salamander
  salamander:
    password: somepass
socks5:
  listen: 127.0.0.1:1180
EOF
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$tmp/b.yml" --json 2>/dev/null)
[ "$(hy "$out" | jq -r '.status')" = "ok" ]          || fail "B: should be detected"
[ "$(hy "$out" | jq -r '.sni_keyword')" = "false" ]  || fail "B: innocuous SNI → sni_keyword false"
[ "$(hy "$out" | jq -r '.sni_explicit')" = "true" ]  || fail "B: tls.sni set → sni_explicit true"
[ "$(hy "$out" | jq -r '.obfs')" = "true" ]          || fail "B: obfs salamander → obfs true"
[ "$(hy "$out" | jq -r '.insecure')" = "false" ]     || fail "B: insecure:false → insecure false"

# --- Case C: insecure:true is detected. ---
cat > "$tmp/c.yml" <<'EOF'
server: edge.invalid:443
auth: TESTTOKEN
tls:
  sni: www.bing.com
  insecure: true
EOF
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config-json "$tmp/c.yml" --json 2>/dev/null)
[ "$(hy "$out" | jq -r '.insecure')" = "true" ] || fail "C: insecure:true should be detected"

# --- Case D: hysteria2:// URI form via --xray-config (obfs + insecure params). ---
out=$(TIMEOUT=2 bash "$SCRIPT" --xray-config 'hysteria2://TESTTOKEN@vpn.invalid:443/?obfs=salamander&insecure=1' --json 2>/dev/null)
[ "$(hy "$out" | jq -r '.status')" = "ok" ]        || fail "D: hysteria2:// URI should be detected"
[ "$(hy "$out" | jq -r '.sni_keyword')" = "true" ] || fail "D: 'vpn' in host → sni_keyword true"
[ "$(hy "$out" | jq -r '.obfs')" = "true" ]        || fail "D: ?obfs= → obfs true"
[ "$(hy "$out" | jq -r '.insecure')" = "true" ]    || fail "D: ?insecure=1 → insecure true"

# --- Case E: a real Xray vless:// config must NOT be misdetected as Hysteria2. ---
out=$(TIMEOUT=2 bash "$SCRIPT" \
        --xray-config 'vless://00000000-0000-0000-0000-000000000000@127.0.0.1:1?security=reality&pbk=AAAA&sid=01&sni=www.example.com&fp=chrome&type=tcp' \
        --only xray --json 2>/dev/null)
[ "$(hy "$out" | jq -r '.status')" = "null" ] || fail "E: an Xray config must not trigger the Hysteria2 analyzer"

echo "PASS: hysteria2 detected (YAML+JSON+URI), SNI-keyword/obfs/insecure flags correct, no Xray false-positive"
