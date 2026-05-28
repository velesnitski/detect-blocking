# detect-blocking

A single-file Bash diagnostic that classifies **what kind of network filtering**
is preventing a VPN endpoint from working — DNS poisoning, IP blocks,
SNI-based DPI, mid-handshake RST injection, silent drops, UDP/QUIC bans,
OpenVPN signature blocks, and (via optional `xray-knife` delegation)
authenticated end-to-end protocol tests for Reality / VLESS / VMess / Trojan
/ Shadowsocks-2022 / Hysteria2.

Built for operators who need to answer one question fast: *"is my server
blocked, and if so, by what mechanism?"*

[![Test](https://github.com/velesnitski/detect-blocking/actions/workflows/test.yml/badge.svg)](https://github.com/velesnitski/detect-blocking/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/v/release/velesnitski/detect-blocking?sort=semver&color=blue)](https://github.com/velesnitski/detect-blocking/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Shell: Bash](https://img.shields.io/badge/Shell-Bash%203.2%2B-1f425f.svg)](https://www.gnu.org/software/bash/)

---

## What it does

Runs a deterministic 11-stage probe chain from your local machine to a target
endpoint and emits a clearly labelled verdict for each detected blocking type.

| # | Probe | Detects |
|---|-------|---------|
| 0 | Environment | Whether a VPN is currently active (results then describe the VPN exit path, not the local ISP) |
| 1 | DNS resolution | DNS sinkhole / system-DNS failure / **DoH integrity canary** + **multi-DoH cross-check** (Cloudflare/Google/Quad9) / **DoT canary** / CDN-anycast divergence |
| 2 | TCP reachability | Full IP block vs port-specific (443 dead but 80 alive) |
| 3 | TLS handshake | SNI-based DPI (proper SNI dies, no-SNI works); auto-runs **64-byte record-fragmentation probe** when SNI is blocked |
| 4 | UA / TLS-fp filtering | User-Agent filtering; **real JA3 via `curl-impersonate`** when installed |
| 5 | Mid-handshake RST | Active DPI reset (<1s) vs silent drop (full timeout) |
| 6 | UDP protocols | IKEv2 (valid IKE\_SA\_INIT probe) + QUIC/HTTP3 over UDP 443 |
| 7 | OpenVPN handshake | Random-SID `0x38` initiator, expects `0x40` server reset |
| 8 | Control sites | Broad vs targeted censorship (Tor/Proton/Discord reachability) |
| 9 | IPv6 reachability | AAAA resolution + IPv6 TCP/HTTPS; detects "IPv4-only block" cases |
| 9b | Compare matrix (opt-in) | `--compare-sni A,B,C` × `--compare-port 443,8443,…` grid for bypass discovery; `--port-survey` adds a curated alt-port list |
| 11 | Xray protocol (opt-in) | Authenticated end-to-end test via `xray-knife` (v10 + legacy auto-detect); works for Reality / VLESS / VMess / Trojan / Shadowsocks-2022 / Hysteria2 |

The verdict ends with a list of detected blocks plus an actionable
recommendation for each (rotate IP, switch to Reality, use uTLS, etc).

---

## Sample output

Running against the IANA demo target (`www.example.com`):

```
VPN-blocking diagnostic for www.example.com
Run from your-host on <date>

== 0. Environment ==
          default route interface: <iface>
          VPN-like interfaces:     <none>
  [OK]    no active VPN signal detected

== 1. DNS resolution ==
          DoH integrity:    ok (1.0.0.1 1.1.1.1 for one.one.one.one)
          system resolver A: <cloudflare-anycast>
          DoH resolver A:    <cloudflare-anycast>
  [OK]    system DNS and DoH share at least one A record

== 2. TCP reachability ==
  [OK]    baseline TCP 1.1.1.1:443 reachable (network is up)
  [OK]    VPN host TCP 443 reachable

== 3. TLS handshake behaviour ==
  [OK]    TLS handshake completes – TCP/TLS layer not blocked

(... probes 4–8 ...)

== VERDICT ==
  [OK]    no blocking signals detected – endpoint reachable normally
```

When run from a network that censors the target, the verdict block lists each
detected mechanism and a recommendation, e.g.:

```
== VERDICT ==
  • DoH path is compromised – network intercepts/poisons DoH responses
  • SNI-based DPI block – server name is in censor blacklist
  • Silent packet drop (firewall blackhole, not DPI reset)
  • Broad censorship – none of the control sites reachable

Recommendation:
  → self-host DoH or use a trusted resolver via VPN tunnel
  → try Reality / domain fronting / ECH-enabled client
  → likely full IP block, rotate endpoint
  → expect aggressive DPI; minimum stack: Reality + uTLS
```

---

## Quick start

```sh
git clone https://github.com/velesnitski/detect-blocking.git
cd detect-blocking
chmod +x detect_blocking.sh

# Demo run against the IANA target (no config — produces a clean baseline)
./detect_blocking.sh

# Real run against your endpoint (hostname or bare IP both work)
./detect_blocking.sh your-vpn.example.com

# Or with a protocol URL — VPN_HOST is auto-derived from the URL
./detect_blocking.sh --xray-config 'vless://UUID@your-vpn.example.com:443?security=reality&pbk=PBK&sid=SID&fp=chrome#srv'
```

> When `--xray-config` is given and no positional host, the script extracts
> the host from the URL automatically — probes 0-10 align with the protocol
> probe (11) so cross-referenced verdicts work out of the box.

---

## Requirements

**Required:**

- Bash 3.2+ (default on macOS 10.5+, all modern Linux)
- `openssl` 1.1.1+ *or* LibreSSL 3+
- `curl`, `nc`, `awk`, `sed`, `grep`

**Optional (probes degrade gracefully if missing):**

- `jq` — robust DoH JSON parsing (falls back to `grep` + `cut`)
- `dig` — primary DNS resolver (falls back to `host` / `nslookup`)
- `perl` — IKEv2 and OpenVPN handshake probes (skipped if absent)
- `xxd` — OpenVPN response hex parsing (skipped if absent)

If any optional tool is missing the script reports it once at startup and continues.

---

## Usage

```text
detect_blocking.sh [OPTIONS] [VPN_HOST]

Options:
  -h, --help              Show help.
  -V, --version           Print version and exit.
  -q, --quiet             Suppress stdout (logging to file still works).
      --log-file PATH     Append timestamped entries to PATH. Rotates at 10 MB.
      --only LIST         Run only the listed probes (comma-separated).
      --skip LIST         Skip the listed probes (comma-separated).
      --watch SECONDS     Repeat probe every SECONDS until interrupted.
      --from-file PATH    Iterate over hosts in file (one per line, # comments).
      --pcap PATH         tcpdump probe traffic to PATH (needs root / cap_net_raw).
      --compare-sni LIST  Comma-separated SNI values for the SNI × port matrix.
      --compare-port LIST Comma-separated TCP ports for the SNI × port matrix.
      --port-survey       Scan curated list of common VPN/proxy alt ports.
      --xray-config URL   End-to-end Xray-protocol test (optional dep: xray-knife).
                          Accepts vless://, vmess://, trojan://, ss://, hysteria2:// URLs.
      --json              Emit machine-readable JSON; implies --quiet. Requires jq.

Probe names: env, dns, tcp, tls, ua, rst, udp, openvpn, control, ipv6, compare, xray

Override precedence:
  CLI arg > environment variable > detect_blocking.conf > built-in default
```

### JSON output

`--json` produces a single JSON document on stdout, schema-versioned for
forward compatibility. Convenient for monitoring stacks:

```sh
./detect_blocking.sh --json www.example.com | jq '.verdicts'
./detect_blocking.sh --json www.example.com | jq '.probes.dns.doh_integrity'

# Emit a Prometheus-style counter
./detect_blocking.sh --json www.example.com \
  | jq -r '"vpn_blocking_verdicts \(.verdicts | length)"'
```

Top-level keys: `schema_version`, `version`, `timestamp` (ISO-8601 UTC),
`target`, `environment`, `probes` (`dns`/`tcp`/`tls`/`request_filter`/`rst`/
`udp`/`openvpn`/`control`), and `verdicts`.

### Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `VPN_HOST` | `www.example.com` | Target hostname |
| `VPN_PORT_TCP` | `443` | Target TCP port |
| `IKEV2_HOST` | `$VPN_HOST` | Separate IKEv2 host (if different) |
| `OPENVPN_HOST` | `$VPN_HOST` | Separate OpenVPN host |
| `OPENVPN_PORT_UDP` / `OPENVPN_PORT_TCP` | `1194` | OpenVPN ports |
| `BASELINE_IPS` | `1.1.1.1 8.8.8.8 9.9.9.9` | Baseline reachability chain (any one passes) |
| `BASELINE_DOMAIN` | `cloudflare.com` | Used for QUIC probe |
| `FAKE_SNI` | `www.microsoft.com` | Innocent SNI for SNI-DPI test |
| `CONTROL_SITES` | `www.protonvpn.com www.torproject.org www.discord.com` | Broad-censorship control set |
| `DOH_URL` | `https://1.1.1.1/dns-query` | DoH endpoint |
| `TIMEOUT` | `5` | Per-probe timeout (seconds) |
| `STRICT_OPENVPN_VERDICT` | `0` | Set `1` to emit hard verdict on silent OpenVPN handshake |
| `LOG_FILE` | *(empty)* | Optional log file path |
| `LOG_QUIET` | `0` | Suppress stdout when `1` |

### Configuration file

Copy and edit:

```sh
cp detect_blocking.conf.example detect_blocking.conf
$EDITOR detect_blocking.conf
```

The file is sourced before defaults are applied. It is gitignored. See
`detect_blocking.conf.example` for all knobs with comments.

---

## Examples

### Diagnose your VPN endpoint

```sh
./detect_blocking.sh www.example.com
```

### Increased timeout for slow or high-latency networks

```sh
TIMEOUT=15 ./detect_blocking.sh --log-file /tmp/diag.log www.example.com
```

### Cron: periodic monitoring with log rotation

```sh
# /etc/cron.d/vpn-monitoring
0 */6 * * * root /opt/scripts/detect_blocking.sh \
    --quiet --log-file /var/log/vpn_blocking.log vpn.mycompany.com
```

### Parse verdicts for alerting / monitoring integration

```sh
#!/bin/bash
output=$(./detect_blocking.sh --quiet --log-file /dev/stdout "$1" 2>&1)
verdicts=$(printf '%s\n' "$output" \
  | sed -n '/^== VERDICT ==$/,/^== /p' | grep '•' | cut -d'•' -f2-)

if [ -n "$verdicts" ]; then
    printf 'ALERT: blocking detected on %s\n' "$1"
    printf '%s\n' "$verdicts"
    # Forward to Prometheus/Pushgateway, Slack, PagerDuty, etc.
fi
```

### Batch-check a fleet (ndjson to disk)

```sh
cat servers.txt
# de1.example.com
# us-east-1.example.com
# fra-2.example.com:8443

./detect_blocking.sh --from-file servers.txt --json --only dns,tcp,tls \
  > fleet-$(date +%F).ndjson

# Aggregate verdicts across all hosts:
jq -s 'map({host: .target.host, verdicts: .verdicts})' fleet-*.ndjson
```

### End-to-end Xray-protocol test (Reality / VLESS / VMess / etc.)

Native blind probing of these protocols is **impossible by design** — Reality
is engineered to be indistinguishable from a fallback TLS site without
credentials, Shadowsocks-2022 requires PSK-derived AEAD, etc. The honest
diagnostic is an *authenticated* client connection through your config:

```sh
# Requires xray-knife in PATH (auto-detected, optional):
# go install github.com/lilendian0x00/xray-knife@latest

./detect_blocking.sh \
  --xray-config 'vless://UUID@your-vpn.example.com:443?type=tcp&security=reality&pbk=PBK&sid=SID&fp=chrome&flow=xtls-rprx-vision#prod' \
  --json | jq '.probes.xray_protocol'
```

The script:
- **Auto-derives VPN_HOST** from the URL (probes 0-10 hit the same host as
  the protocol probe; positional arg still wins if given explicitly).
- **Strips whitespace** from the URL (terminal paste-wrap is the #1 footgun)
  and emits a warning if anything was removed.
- **Masks credentials** in any human or JSON output (`<creds>` placeholder),
  so it's safe to pipe to logs / SIEM / chat alerts.
- **Auto-detects xray-knife API** — both v10+ (top-level `http`) and legacy
  (`net http`).
- **Surfaces the delegated error** on failure (`xray-knife says: …`), so
  config-drift vs network-failure is distinguishable at a glance.

The killer signal is the **cross-referenced verdict** when the transport
layer dies but the protocol layer punches through:

```
== 3. TLS handshake behaviour ==
  [FAIL]  all TLS handshakes to this IP fail → TLS-LEVEL DPI or IP block

== 5. Mid-handshake RST detection ==
  [FAIL]  handshake dies fast (0.17s) → likely DPI-injected RST

== 11. Xray-protocol end-to-end test ==
  [OK]    tunnel established, RTT 278 ms

== VERDICT ==
  • TLS DPI rejects any handshake to this IP
  • Active RST injection by DPI mid-handshake
  • Xray protocol bypasses local DPI/DNS-MITM despite environment signals
```

→ *your protocol stack is working as designed — local DPI sees the cover,
not the payload.* That's a passing Reality deployment under active DPI.

### Continuous monitoring with `--watch`

```sh
# Probe every 60s, alert on transition
./detect_blocking.sh --watch 60 --json www.example.com \
  | while read -r line; do
      verdict_count=$(printf '%s' "$line" | jq '.verdicts | length')
      [ "$verdict_count" -gt 0 ] \
        && curl -X POST https://hooks.slack.com/... -d "$line"
    done
```

---

## Notes on detection accuracy

**Probe 4 (UA filtering) is *not* a JA3/JA4 test.** Both `curl` invocations
share the same TLS stack, so the ClientHello fingerprint is identical between
them — only the User-Agent header differs. Detected divergence indicates
header-based filtering, not TLS-fingerprint DPI. For true JA3 testing use
[`curl-impersonate`](https://github.com/lwthiker/curl-impersonate) or
equivalent.

**Probe 7 (OpenVPN) silence is inconclusive by default.** A silent server can
mean DPI signature-block, no service on that port, or HMAC firewall
(`tls-auth` / `tls-crypt`). Opt into the hard verdict with
`STRICT_OPENVPN_VERDICT=1` only when you're certain the target is plain
OpenVPN.

**DoH integrity canary.** The script resolves `one.one.one.one` over the
configured DoH endpoint and verifies the answer matches `1.1.1.1` / `1.0.0.1`.
If it doesn't, DoH itself is MITM'd (e.g. national-CA TLS interception, BGP
anycast hijack) and its answers are discarded for the rest of the run. Note:
this canary does not catch a sophisticated proxy that allowlists
`one.one.one.one` while substituting answers only for target domains.

---

## Testing

```sh
# Full suite
bash tests/run.sh

# Individual:
bash tests/test_smoke.sh
bash tests/test_doh_compromise.sh   # spins up a local fake-DoH server
```

The CI workflow runs shellcheck plus smoke tests on macOS and Ubuntu.

---

## Limitations

- IPv6 probes are not yet implemented.
- TLS fingerprint testing is surface-level (UA only); use `curl-impersonate`
  for real JA3.
- UDP IKE probe needs `perl`; missing → that probe is skipped.
- Some macOS VPN clients hijack DNS in ways that confuse Section 0 detection.

---

## Troubleshooting

### `nc: invalid option -- 'G'`

**Cause:** `netcat-traditional` instead of `netcat-openbsd` is active.

```sh
# Debian / Ubuntu
sudo apt install netcat-openbsd
sudo update-alternatives --set nc /bin/nc.openbsd
```

### `openssl: unknown option -brief`

**Cause:** OpenSSL older than 1.1.1.
**Fix:** upgrade OpenSSL, or on macOS use the system LibreSSL (already 3+).

### `dig: command not found`

The script falls back to `host` → `nslookup` automatically. For full DNS
resolution support:

```sh
sudo apt install dnsutils      # Debian / Ubuntu
sudo dnf install bind-utils    # Fedora / RHEL
brew install bind              # macOS
```

### Log file is not written

1. Does the parent directory of `LOG_FILE` exist?
2. Is it writable by the user running the script?
3. Is `LOG_QUIET=1` set without a `LOG_FILE`?

### Different IPs in DNS and DoH, but no sinkhole verdict

Anycast infrastructure (Cloudflare, Akamai) legitimately returns different IPs
depending on the resolver's location. The script uses set intersection
(`_sets_intersect`) — one shared IP is enough for a clean result. If all IPs
differ and no verdict appears, run `traceroute` to each address to confirm they
converge on the same network.

---

## Intended use

This tool is intended for:

- **VPN operators** diagnosing why their own endpoints are blocked.
- **Researchers** studying network filtering in environments where they
  have explicit authorization.
- **Educators** demonstrating DPI / DNS / TLS interception concepts.

It is **not** intended for:

- Active probing of third-party VPN servers without permission.
- Bypassing terms of service of any network.
- Mass scanning.

The script runs **passively** from your local machine, probes **one** target
you explicitly configure, and does not transmit results anywhere.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

---

## Comparison

- [**OONI Probe**](https://ooni.org/) — measures censorship across many
  protocols and uploads to a global dataset. Different goal: research /
  measurement vs. operator-side diagnosis.
- [**Censored Planet**](https://censoredplanet.org/) — academic remote
  measurement.
- [**`gfw-probe`** (net4people/bbs)](https://github.com/net4people/bbs) —
  active probing of suspected VPN endpoints, mostly for research.

`detect-blocking` sits closer to the operator side: zero install, runs
locally, no telemetry, focused on rapid root-cause diagnosis.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All shell code must pass
`shellcheck -S warning` and `bash -n`, and the test suite must pass.

## License

[MIT](LICENSE).
