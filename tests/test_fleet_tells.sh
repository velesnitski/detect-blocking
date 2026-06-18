#!/usr/bin/env bash
#
# tests/test_fleet_tells.sh — the fleet-walk "tells" / fp / score-band extractor
# (_fleet_row_fields) WITHOUT a live tunnel. We extract just that pure function
# from the script (same trick as the other classifier tests — avoids running
# main) and feed it synthetic per-server JSON blobs that mimic what a no-tunnel
# self-invoke emits. Asserts: the right tells fire, fp is the 8-char prefix,
# clean configs say "clean", and a garbage payload degrades safely.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
command -v jq >/dev/null 2>&1 || { echo "SKIP: jq not installed"; exit 0; }

fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

# Pull the pure helper out of the script and define it here.
fn=$(awk '/^_fleet_row_fields\(\)/,/^}/' "$SCRIPT")
[ -n "$fn" ] || fail "could not extract _fleet_row_fields from the script"
eval "$fn"

# Parse one TAB-separated result line into score/band/fp/tells.
row() {
  IFS=$'\t' read -r r_score r_band r_fp r_tells <<EOF
$(_fleet_row_fields "$1")
EOF
}

# --- A: the live-fleet shape — fake cover (chain invalid), active prober gets 403
#        instead of a relay, TLS parity diverges on cipher+ext, sni!=ip, ssh open.
#        Asserts every value-carrying tell renders WITH its value. ---
row '{"probes":{"xray_cover":{"status":"fake","chain_valid":false},"xray_active_probe":{"matches_cover":false,"relay_http_code":"403"},"xray_tls_parity":{"status":"mismatch","cipher_match":false,"ext_match":false,"version_match":true,"alpn_match":true},"host_exposure":{"open_ports":["22/ssh","8080/http"]},"xray_detectability":{"score":100,"band":"critical","deployment_fingerprint":"abcdef012345","cover_obscure":false,"sni_ip_asn_match":false,"sni_resolves":true,"port_standard":true,"sni_keyword":false,"tls_in_tls_protected":true,"volume_throttle_suspected":false}}}'
[ "$r_score" = "100" ]      || fail "A: score should be 100 (got '$r_score')"
[ "$r_band"  = "critical" ] || fail "A: band should be critical (got '$r_band')"
[ "$r_fp"    = "abcdef01" ] || fail "A: fp should be the 8-char prefix (got '$r_fp')"
case "$r_tells" in *self-signed*)            : ;; *) fail "A: tells should include self-signed (got '$r_tells')" ;; esac
case "$r_tells" in *chain-invalid*)          : ;; *) fail "A: tells should include chain-invalid (got '$r_tells')" ;; esac
case "$r_tells" in *no-relay:403*)           : ;; *) fail "A: no-relay must carry the HTTP code (got '$r_tells')" ;; esac
case "$r_tells" in *tls-parity:cipher+ext*)  : ;; *) fail "A: tls-parity must name the diverged dims (got '$r_tells')" ;; esac
case "$r_tells" in *sni!=ip*)                : ;; *) fail "A: tells should include sni!=ip (got '$r_tells')" ;; esac
case "$r_tells" in *exposed:22+8080*)        : ;; *) fail "A: exposed must list the actual ports (got '$r_tells')" ;; esac

# --- B: cover relayed OK but obscure + non-standard port (a lower-score outlier) ---
row '{"probes":{"xray_cover":{"status":"ok"},"xray_active_probe":{"matches_cover":true},"xray_tls_parity":{"status":"ok"},"host_exposure":{"open_ports":[]},"xray_detectability":{"score":70,"band":"critical","deployment_fingerprint":"abcd1234ffff","cover_obscure":true,"sni_ip_asn_match":true,"sni_resolves":true,"port_standard":false,"sni_keyword":false,"tls_in_tls_protected":true,"volume_throttle_suspected":false}}}'
[ "$r_fp" = "abcd1234" ] || fail "B: fp prefix (got '$r_fp')"
case "$r_tells" in *cover-obscure*) : ;; *) fail "B: tells should include cover-obscure (got '$r_tells')" ;; esac
case "$r_tells" in *non443*)        : ;; *) fail "B: tells should include non443 (got '$r_tells')" ;; esac
case "$r_tells" in *self-signed*) fail "B: cover is OK — self-signed must NOT fire (got '$r_tells')" ;; *) : ;; esac

# --- C: fully clean config → no signal fires ---
row '{"probes":{"xray_cover":{"status":"ok"},"xray_active_probe":{"matches_cover":true},"xray_tls_parity":{"status":"ok"},"host_exposure":{"open_ports":[]},"xray_detectability":{"score":15,"band":"low","deployment_fingerprint":"0000aaaa1111","cover_obscure":false,"sni_ip_asn_match":true,"sni_resolves":true,"port_standard":true,"sni_keyword":false,"tls_in_tls_protected":true,"volume_throttle_suspected":false}}}'
[ "$r_tells" = "clean" ] || fail "C: a clean config should report tells=clean (got '$r_tells')"

# --- D: SNI does not resolve + sni keyword + vision off (more tells) ---
row '{"probes":{"xray_cover":{"status":"mismatch"},"xray_active_probe":{"matches_cover":false},"xray_tls_parity":{"status":"mismatch"},"host_exposure":{"open_ports":[]},"xray_detectability":{"score":90,"band":"critical","deployment_fingerprint":"deadbe","cover_obscure":false,"sni_ip_asn_match":false,"sni_resolves":false,"port_standard":true,"sni_keyword":true,"tls_in_tls_protected":false,"volume_throttle_suspected":false}}}'
case "$r_tells" in *cover-mismatch*) : ;; *) fail "D: tells should include cover-mismatch (got '$r_tells')" ;; esac
case "$r_tells" in *tls-parity*)     : ;; *) fail "D: tells should include tls-parity (got '$r_tells')" ;; esac
case "$r_tells" in *sni!=ip*)        : ;; *) fail "D: tells should include sni!=ip (got '$r_tells')" ;; esac
case "$r_tells" in *sni-nxdomain*)   : ;; *) fail "D: tells should include sni-nxdomain (got '$r_tells')" ;; esac
case "$r_tells" in *vision-off*)     : ;; *) fail "D: tells should include vision-off (got '$r_tells')" ;; esac
[ "$r_fp" = "deadbe" ] || fail "D: a short fp should pass through unpadded (got '$r_fp')"

# --- E: behavioural/lint tells — clock skew, mux, FET, non-UUID id, rare uTLS,
#        and >2 open ports (collapse to "+Nmore"). ---
row '{"probes":{"xray_cover":{"status":"ok"},"xray_active_probe":{"matches_cover":true},"xray_tls_parity":{"status":"ok"},"host_exposure":{"open_ports":["22/ssh","80/http","3000/node"]},"xray_clock":{"skew_seconds":-12},"xray_lint":{"fet_exposed":true,"id_uuid":false},"xray_detectability":{"score":55,"band":"high","deployment_fingerprint":"feedface0001","mux_enabled":true,"utls_fp_uncommon":true,"sni_ip_asn_match":true,"sni_resolves":true,"port_standard":true,"tls_in_tls_protected":true}}}'
case "$r_tells" in *clock:-12s*)        : ;; *) fail "E: clock skew should carry seconds (got '$r_tells')" ;; esac
case "$r_tells" in *mux*)               : ;; *) fail "E: tells should include mux (got '$r_tells')" ;; esac
case "$r_tells" in *fet*)               : ;; *) fail "E: tells should include fet (got '$r_tells')" ;; esac
case "$r_tells" in *id-nonuuid*)        : ;; *) fail "E: tells should include id-nonuuid (got '$r_tells')" ;; esac
case "$r_tells" in *utls-rare*)         : ;; *) fail "E: tells should include utls-rare (got '$r_tells')" ;; esac
case "$r_tells" in *exposed:22+80+1more*) : ;; *) fail "E: >2 ports should collapse to +Nmore (got '$r_tells')" ;; esac

# --- F: curl "000" relay code (no HTTP response) renders as "noresp", and a
#        named uncommon uTLS fp carries its value (utls-rare:qq). ---
row '{"probes":{"xray_active_probe":{"matches_cover":false,"relay_http_code":"000"},"xray_detectability":{"score":100,"band":"critical","deployment_fingerprint":"abc","utls_fp_uncommon":true,"utls_fp":"qq"}}}'
case "$r_tells" in *no-relay:noresp*) : ;; *) fail "F: relay code 000 should render as no-relay:noresp (got '$r_tells')" ;; esac
case "$r_tells" in *utls-rare:qq*)    : ;; *) fail "F: utls-rare should name the fp (got '$r_tells')" ;; esac

# --- G: garbage payload → empty fields (the caller defaults them to ?/-) ---
row 'not json at all'
[ -z "$r_score" ] && [ -z "$r_band" ] || fail "G: garbage payload should yield empty fields (got score='$r_score' band='$r_band')"

echo "PASS: _fleet_row_fields derives score/band/fp + value-carrying tells; clean + garbage degrade safely"
