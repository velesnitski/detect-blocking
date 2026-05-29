# detect-blocking

A single-file Bash diagnostic that classifies **what kind of network filtering**
is preventing a VPN endpoint from working — DNS poisoning, IP blocks,
SNI-based DPI, mid-handshake RST injection, silent drops, UDP/QUIC bans,
OpenVPN signature blocks, authenticated end-to-end protocol tests (via
optional `xray-knife` delegation), full-fidelity tunnel boot through your
real `xray-core` config, and **data-plane throughput probing** that
catches cover-SNI traffic shaping the handshake-only tests miss.
Supported protocols: Reality / VLESS / VMess / Trojan / Shadowsocks-2022
/ Hysteria2.

Built for operators who need to answer one question fast: *"is my server
blocked, and if so, by what mechanism?"*

[![Test](https://github.com/velesnitski/detect-blocking/actions/workflows/test.yml/badge.svg)](https://github.com/velesnitski/detect-blocking/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/v/release/velesnitski/detect-blocking?sort=semver&color=blue)](https://github.com/velesnitski/detect-blocking/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Shell: Bash](https://img.shields.io/badge/Shell-Bash%203.2%2B-1f425f.svg)](https://www.gnu.org/software/bash/)

---

## What it does

Runs a deterministic 13-stage probe chain from your local machine to a target
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
| 12 | Xray full-config (opt-in) | Spawns `xray-core` with your real config (`--xray-config-json FILE`), exercises chained outbounds / balancers / fragment dialers end-to-end through a local SOCKS inbound; reports egress IP + colo + RTT |
| 13 | Tunnel throughput (auto with 12) | Pulls 10 MB from Cloudflare's speed-test backend through the same SOCKS tunnel; banded thresholds catch **cover-SNI traffic shaping** (RKN/TSPU/CN-style) that handshake-only probes miss |

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

## Using with Xray / Reality / VLESS / VMess / Trojan / SS-2022 / Hysteria2

This is the killer feature. Native blind probing of these protocols is
**impossible by design** — Reality is engineered to be indistinguishable from
a real fallback TLS site without credentials, Shadowsocks-2022 requires
PSK-derived AEAD to trigger any protocol-specific reaction, VLESS-with-
fallback proxies bad UUIDs to a decoy. Honest end-to-end diagnostics needs
an *authenticated* client connection through your config — `detect-blocking`
delegates that to [`xray-knife`](https://github.com/lilendian0x00/xray-knife)
and cross-references the result with its own transport-layer probes.

### 1 — install `xray-knife` once

```sh
# Go required (any 1.20+)
go install github.com/lilendian0x00/xray-knife@latest

# Verify it's on PATH
xray-knife --version    # expect: xray-knife version 10.x.x (or newer)
```

The script auto-detects both the modern v10+ API (`xray-knife http -c …`)
and legacy v9 (`xray-knife net http -c …`). No flag needed.

### 2 — get your protocol URL

Most Xray clients let you export a single share-link:

- **v2rayN / v2rayNG / NekoBox / NekoRay** — right-click server → *Share* /
  *Generate QR* — copy the `vless://…` / `vmess://…` / `trojan://…` string.
- **Hiddify** — long-press server → *Share link*.
- **Shadowrocket / Streisand** — server detail page → *QR code* / *Copy link*.
- **Manual** — assemble from `config.json`: scheme, UUID, host, port, TLS
  type, public key, SID, fingerprint, flow.

Examples by protocol (replace `UUID`, `PBK`, `SID`, `PASSWORD`, etc. with
your real values):

```text
vless://UUID@your-vpn.example.com:443?type=tcp&security=reality&pbk=PBK&sid=SID&sni=www.microsoft.com&fp=chrome&flow=xtls-rprx-vision#prod
vless://UUID@cdn.example.com:443?type=ws&path=%2Fxxx&host=cdn.example.com&security=tls&sni=cdn.example.com#ws-cdn
trojan://PASSWORD@your-vpn.example.com:443?sni=your-vpn.example.com#trojan-srv
ss://2022-blake3-aes-128-gcm:KEY@your-vpn.example.com:8388#ss-srv
hysteria2://PASSWORD@your-vpn.example.com:443?sni=your-vpn.example.com#hy2-srv
```

### 3 — run the diagnostic

The simplest invocation — URL only, host auto-derived:

```sh
./detect_blocking.sh --xray-config 'vless://UUID@your-vpn.example.com:443?security=reality&pbk=PBK&sid=SID&fp=chrome#prod'
```

For monitoring stacks, add `--json`:

```sh
./detect_blocking.sh --xray-config 'vless://…' --json | jq '.probes.xray_protocol, .verdicts'
```

> **Credentials are auto-masked** in every line of output and in the JSON
> document (`url_display: "vless://<creds>@host:port"`). It's safe to pipe
> the result to logs, Slack, PagerDuty, or any SIEM.

Store the URL out-of-band so it doesn't end up in your shell history:

```sh
echo 'vless://UUID@your-vpn.example.com:443?...#prod' > ~/.xray-prod
chmod 600 ~/.xray-prod

./detect_blocking.sh --xray-config "$(cat ~/.xray-prod)"
```

`XRAY_CONFIG=…` as an environment variable works equivalently.

### 4 — read the verdict

The probe table runs end-to-end against the same host. The cross-referenced
verdict at the end tells you which layer is failing:

| Verdict combination | Diagnosis | Action |
|---|---|---|
| `Xray protocol bypasses local DPI/DNS-MITM despite environment signals` | Reality stack is working as designed. Local DPI sees the cover, not the payload. | None — that's a passing setup under active DPI. |
| `TLS DPI rejects any handshake to this IP` + `Xray-protocol end-to-end test failed` | Transport itself is dead — IP/SNI block. | Rotate the IP, switch SNI, try alternative port via `--compare-port`. |
| `Xray-protocol handshake fails while plain TLS to the same host succeeds` | Protocol-fingerprint DPI **or** config drift. | Verify UUID + public key match the server, try a different `fp=` (chrome/safari), check `sni=` is still allowed. |
| `DNS sinkhole / local resolver interception suspected` + `Xray protocol bypasses…` | The network MITMs DNS but your VPN client uses DoH-in-tunnel — fine. | Make sure the client doesn't fall back to the system resolver. |
| Domain unresolvable / Network connectivity broken | You're not online to the target ASN — not a DPI issue. | Try a different network / vantage point. |

If `xray-knife` fails, the script surfaces the first line of its error
output (`xray-knife says: …`) so you can distinguish `closed pipe` (network)
from `proxy/vless: …` (config) at a glance.

### 5 — common scenarios

```sh
# Smoke check a freshly provisioned server before handing the URL to users
./detect_blocking.sh --xray-config "$(cat ~/.xray-prod)"

# Fleet check — N servers from a file, one ndjson record per server
./detect_blocking.sh --from-file servers-with-urls.txt --json | jq -c '{host: .target.host, ok: (.probes.xray_protocol.status == "ok")}'

# Continuous monitoring (cron / systemd / Docker sidecar)
./detect_blocking.sh \
  --xray-config "$(cat ~/.xray-prod)" \
  --watch 300 --json --quiet \
  --log-file /var/log/vpn-monitoring.log

# Forensic — when something starts failing, capture the wire too
sudo ./detect_blocking.sh \
  --xray-config "$(cat ~/.xray-prod)" \
  --pcap /tmp/vpn-incident-$(date +%s).pcap

# Bypass discovery — does any alt SNI / port slip past the local DPI?
./detect_blocking.sh \
  --xray-config "$(cat ~/.xray-prod)" \
  --compare-sni www.microsoft.com,www.cloudflare.com,www.apple.com \
  --compare-port 443,8443,2083
```

### What if `xray-knife` isn't installed?

Probe 11 prints a one-line `[WARN] skipping — no xray-knife / xray / sing-box
in PATH` and the other 10 probes run as usual. The script never hard-fails on
a missing optional dependency — see the gracefully-degrading model in the
[Requirements](#requirements) section.

### Going full-fidelity with `--xray-config-json` (probe 12)

The share-link form is **lossy** — chained outbounds (`dialerProxy:
fragment`), `noises`, custom routing rules, multiple-outbound balancers
(`leastPing` / `random`), `observatory`, `sniffing`, and several Reality
knobs don't fit into the URL spec. If your production setup relies on
those, the URL test only covers what fits — one VLESS endpoint, no chain,
no routing logic. Probe 12 spawns `xray run` against your **actual
`config.json`** and tests end-to-end through its SOCKS inbound.

#### Quickstart — one paste from a fresh shell

```sh
# 1. Install xray-core (one-time; jq is also required but ships with most distros)
brew install xray            # macOS
# OR — Linux/WSL:
# sudo apt install -y jq && go install github.com/xtls/xray-core/main@latest \
#   && sudo mv ~/go/bin/main /usr/local/bin/xray

# 2. Save your client config.json somewhere safe (mode 600 — contains live creds)
#    e.g. ~/.xray-test.json — the path is yours; nothing in the script is bound to it.

# 3. Run the full diagnostic
./detect_blocking.sh --xray-config-json ~/.xray-test.json --json | jq '.probes.xray_full_config'

# 4. Cleanup when done (the file holds your UUID + Reality publicKey)
shred -u ~/.xray-test.json 2>/dev/null || rm -P ~/.xray-test.json
```

The script patches your config in-memory before launching `xray run`: SOCKS
inbound is rebound to a random free port in `49152-65534`, so the test
doesn't collide with a running v2rayN / NekoBox / CLI client that may
already squat on `10808` / `10809`. The patched copy is written to a temp
file (`mktemp -t detect_blocking.xrayjson.XXXXXX`); the EXIT trap removes
it and kills the background `xray` child even on `Ctrl-C` mid-probe.

#### What the verdict gives you

```sh
./detect_blocking.sh --xray-config-json ~/.xray-test.json --json \
  | jq '{verdicts, xray_full: .probes.xray_full_config}'
```

A passing run looks like:

```json
{
  "verdicts": [],
  "xray_full": {
    "status": "ok",
    "config_path": "/Users/you/.xray-test.json",
    "socks_port_used": 52341,
    "egress_ip": "<your VPN exit IP>",
    "egress_location": "<CF colo, e.g. AMS>",
    "rtt_ms": 640
  }
}
```

`egress_ip` is the IP the destination saw — for a config with a
`leastPing` balancer this is **the actual server xray picked as fastest
from your vantage**, i.e. the same one your real users would hit.

#### Combine with probe 11 for the killer cross-reference

You can pass **both** `--xray-config URL` and `--xray-config-json FILE` in
the same invocation. The cross-reference verdict —
`Fragment / chained-outbound layer is the bypass — share-link form alone is
not enough` — fires when the URL probe fails but the JSON probe succeeds,
i.e. the chain layer (fragment, dialerProxy, balancer) is doing the heavy
lifting and a plain share-link client wouldn't reproduce the bypass.

#### What if `xray-core` isn't installed?

Probe 12 prints a one-line warning and the other probes run as usual:

```
== 12. Xray full-config (json) end-to-end test ==
  [WARN]  skipping — 'xray' binary not in PATH
          install: go install github.com/xtls/xray-core/main@latest (rename to 'xray')
          or download: https://github.com/XTLS/Xray-core/releases
```

JSON output records `probes.xray_full_config.status == "xray-missing"`, so
monitoring stacks can branch on "did we run the full-fidelity probe yet?"
deterministically.

### Probe 13 — data-plane throughput (catches cover-SNI shaping)

Probe 12 confirms the Reality / VLESS handshake succeeds, but says nothing
about whether the tunnel can actually move bytes once it's up. That
distinction matters when a censor uses **cover-SNI traffic shaping**
instead of an outright block:

- TLS handshake completes cleanly (the censor lets it — fingerprint looks
  normal).
- TCP-level ping responds (also unaffected).
- The instant payload starts flowing the shaper kicks in and limits the
  flow to a few KB/s, making the tunnel feel "connected but broken".

This pattern shows up against China-popular cover destinations (Bilibili,
Baidu, WeChat properties) in the RU TSPU stack since 2024, and against
YouTube-routed covers under CN GFW for years. Probe 12 alone reports
`[OK]` — the handshake genuinely succeeds — and the diagnostic misses it.

Probe 13 reuses the SOCKS inbound that probe 12 just stood up and pulls
10 MB from Cloudflare's public speed-test backend
(`speed.cloudflare.com/__down?bytes=N`) through the tunnel, then bands
the measured throughput:

| Band | Meaning |
|---|---|
| `≥ 250 KB/s` | healthy — usable for normal browsing |
| `< 250 KB/s` | degraded — partial shaping, congestion, or low-bandwidth egress; re-test from a different vantage |
| `< 50 KB/s` | severely throttled — classic cover-SNI shaping signature; change the Reality cover destination |
| `< 1 KB/s` | tunnel collapsed post-handshake — mid-stream RST or kill-shaping |

When the throttled-severe band fires, the verdict spells out the
mitigation: change the Reality `dest` on the server **and** `serverName`
on the client to a host that isn't shaped in the affected region. Verify
out-of-band (plain `curl` from a tester in that region) before deploying.

Tuning knobs (env vars):

```sh
# Larger sample for slow links (default 10 MB):
XRAY_THROUGHPUT_TARGET_BYTES=$((50*1024*1024)) ./detect_blocking.sh --xray-config-json ~/.xray-test.json

# Longer timeout for high-RTT tunnels (default 20s):
XRAY_THROUGHPUT_TIMEOUT=60 ./detect_blocking.sh --xray-config-json ~/.xray-test.json

# Different throughput target (must support `?bytes=N` query param):
XRAY_THROUGHPUT_URL=https://your.speed-test/down ./detect_blocking.sh --xray-config-json ~/.xray-test.json
```

JSON output:

```json
{
  "probes": {
    "xray_throughput": {
      "status": "ok",
      "bytes_per_second": 1218000,
      "bytes_received": 10485760,
      "seconds": 8.6,
      "target_bytes": 10485760
    }
  }
}
```

Status values: `ok`, `throttled-mild`, `throttled-severe`, `broken`,
`skipped` (when probe 12 didn't succeed), `curl-missing`.

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
      --xray-config URL       End-to-end Xray-protocol test (xray-knife).
                              vless://, vmess://, trojan://, ss://, hysteria2:// URLs.
      --xray-config-json FILE Full-config end-to-end (xray-core + SOCKS5; covers
                              fragment, dialerProxy, noises, chained outbounds).
      --json              Emit machine-readable JSON; implies --quiet. Requires jq.

Probe names: env, dns, tcp, tls, ua, rst, udp, openvpn, control, ipv6, compare, xray, xrayjson

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
| `XRAY_THROUGHPUT_TARGET_BYTES` | `10485760` | Probe 13 download sample size (10 MB); raise for slow links to escape TCP slow-start |
| `XRAY_THROUGHPUT_TIMEOUT` | `20` | Probe 13 download deadline (seconds); raise for high-RTT tunnels |
| `XRAY_THROUGHPUT_URL` | `https://speed.cloudflare.com/__down` | Probe 13 throughput endpoint; must accept `?bytes=N` query |
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
