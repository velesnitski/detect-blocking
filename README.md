# detect-blocking

A single-file Bash diagnostic that classifies **what kind of network filtering**
is preventing a VPN endpoint from working — and, for Xray/Reality stacks, how
healthy, stealthy and stable the tunnel actually is.

At the transport layer it pins down DNS poisoning, IP blocks, SNI-based DPI,
mid-handshake RST injection, silent drops, UDP/QUIC bans and OpenVPN signature
blocks. For **Reality / VLESS / VMess / Trojan / Shadowsocks-2022 / Hysteria2**
it goes further, across six dimensions:

- **Reachability** — authenticated end-to-end test via `xray-knife`, plus a
  full-fidelity boot of your real `xray-core` config (or one synthesized from
  a share link) through a local SOCKS inbound.
- **Performance** — single-stream shaping detection + a multi-stream,
  multi-endpoint capacity estimate (defeats single-stream under-reporting).
- **Stealth** — is the Reality cover real, or a self-signed/mismatched fake an
  active prober flags instantly? Does the server *behave* like the cover site
  under an unauthenticated probe?
- **Integrity** — egress geo + datacenter/proxy reputation flags + DNS region.
- **Stability** — an escalating size-ladder that catches **volumetric
  kill-shaping** (small flows allowed, large flows reset).
- **Correctness** — a static config linter and a clock-skew check that catch
  the typos and time drift that otherwise masquerade as DPI.

Plus a per-outbound **fleet matrix** that auto-enables on balancer configs and
tells a single dead endpoint apart from a fleet-wide fault.

Built for operators who need to answer one question fast: *"is my server
blocked, and if so, by what mechanism — and if not, why does it still feel
broken?"* Every Xray verdict is designed to be **safe to share**: booleans,
counts and status codes only, never a secret, cover domain, or egress IP.

[![Test](https://github.com/velesnitski/detect-blocking/actions/workflows/test.yml/badge.svg)](https://github.com/velesnitski/detect-blocking/actions/workflows/test.yml)
[![Release](https://img.shields.io/github/v/release/velesnitski/detect-blocking?sort=semver&color=blue)](https://github.com/velesnitski/detect-blocking/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Shell: Bash](https://img.shields.io/badge/Shell-Bash%203.2%2B-1f425f.svg)](https://www.gnu.org/software/bash/)

---

## What it does

Runs a deterministic probe chain (transport → protocol → stealth → integrity
→ stability → correctness) from your local machine to a target endpoint and
emits a clearly labelled verdict for each detected issue.

| # | Probe | Detects |
|---|-------|---------|
| 0 | Environment | Whether a VPN is currently active (results then describe the VPN exit path, not the local ISP) |
| 1 | DNS resolution | DNS sinkhole / system-DNS failure / **DoH integrity canary** + **multi-DoH cross-check** (Cloudflare/Google/Quad9) / **DoT canary** / CDN-anycast divergence |
| 2 | TCP reachability | Port-specific (443 dead, 80 alive) vs host unreachable; an unreachable host is split by ICMP (up-but-filtered vs dark) and framed by vantage — a dark host with control sites reachable reads as "server likely down", not "rotate your IP" |
| 3 | TLS handshake | SNI-based DPI (proper SNI dies, no-SNI works); auto-runs **64-byte record-fragmentation probe** when SNI is blocked. For a Reality config it probes the **cover serverName** (not the bare-IP host) and judges the block on that — so Reality's by-design drop of non-matching SNIs isn't misread as DPI |
| 4 | UA / TLS-fp filtering | User-Agent filtering; **real JA3 via `curl-impersonate`** when installed |
| 5 | Mid-handshake RST | Active DPI reset (<1s) vs silent drop (full timeout) |
| 6 | UDP protocols | IKEv2 (valid IKE\_SA\_INIT probe) + **QUIC / UDP-443 reachability** via a dependency-free Version-Negotiation probe (baselines a known QUIC host → detects wholesale UDP/443 blocking; also probes a Hysteria2 server's own port). curl `--http3` used as a fallback |
| 7 | OpenVPN handshake | Random-SID `0x38` initiator, expects `0x40` server reset |
| 8 | Control sites | Broad vs targeted censorship (Tor/Proton/Discord reachability) |
| 9 | IPv6 reachability | AAAA resolution + IPv6 TCP/HTTPS; detects "IPv4-only block" cases |
| 9b | Compare matrix (opt-in) | `--compare-sni A,B,C` × `--compare-port 443,8443,…` grid for bypass discovery; `--port-survey` adds a curated alt-port list |
| 11 | Xray protocol (opt-in) | Authenticated end-to-end test via `xray-knife` (v10 + legacy auto-detect); works for Reality / VLESS / VMess / Trojan / Shadowsocks-2022 / Hysteria2 |
| 12 | Xray full-config (opt-in) | Spawns `xray-core` with your real config (`--xray-config-json FILE`, or synthesized from a `--xray-config URL`), exercises chained outbounds / balancers / fragment dialers end-to-end through a local SOCKS inbound; reports egress IP + colo + RTT. Auto-retries once at 4× `TIMEOUT` on a slow (timeout) handshake |
| 13 | Tunnel throughput (auto with 12) | Pulls 10 MB from Cloudflare's speed-test backend through the same SOCKS tunnel; banded thresholds catch **cover-SNI traffic shaping** (RKN/TSPU/CN-style) that handshake-only probes miss |
| 14 | Tunnel capacity (auto with 12) | N parallel streams × several CDN backends (Cloudflare / DataPacket / OVH) through the tunnel; reports the **best aggregate Mbps** — a real-speedtest-style estimate that defeats the single-stream under-reporting of probe 13. Runs by default; `--no-speedtest` to skip, auto-skipped in `--watch`/`--from-file` loops |
| 15 | Reality cover authenticity (auto) | Plain-TLS probe like a censor's active prober: is the presented cert a CA-valid cover, or **self-signed/mismatched** (fake cover, trivially fingerprinted)? Booleans only — never prints the cover domain |
| 16 | Egress integrity (auto with 12) | Through the tunnel: egress geo + **datacenter/proxy/mobile flags** (is the exit IP already on "this is a VPN" lists?) + DNS-resolver region, across **three sources** — ip-api, an ASN/org pool, and a datacenter-flag fallback (ipapi.is) that fills in when ip-api is rate-limited, so reputation isn't left "n/a". Also flags **entry↔egress co-location** (exit in the same /24 or ASN as the entry — a single-block topology tell). Country + flags only, never the IP. `--no-egress-check` to skip |
| 17 | Held-session stability (auto with 12) | Holds the tunnel ~20s with periodic pulses to catch **delayed mid-session RST / kill-shaping** that short bursts (13/14) miss. `--no-stability` to skip; auto-skipped in `--watch`/`--from-file` loops |
| 18 | Config pre-flight lint (auto) | Static validation of the URL/JSON for common Reality/VLESS misconfigs (`flow`/`network` mismatch, bad `shortId`, bare-IP SNI, missing `pbk`, `allowInsecure=true` masking an invalid cert, …) — so a typo doesn't masquerade as DPI. Also: **GFW fully-encrypted-traffic (FET) exposure** — Shadowsocks / VMess-VLESS over raw TCP with `security: none` is random from byte 0 and blocked by the GFW's entropy classifier ([USENIX'23](https://gfw.report/publications/usenixsecurity23/en/)); TLS/REALITY + HTTP-framed + UDP transports are exempt. And a **share-safe `id`-format note** (UUID vs non-UUID + length — never the value). Names the knob, never the secret |
| 19 | Clock skew (auto) | Reality auth is time-windowed; a client clock off by minutes fails the handshake like a block. Compares local time to a server `Date` header, warns past ±60s |
| 20 | Active-probe resistance (auto) | Probe 15 checks the cover *cert*; this checks the cover *behaviour* — does an unauthenticated HTTPS request get relayed to the genuine cover site (real Reality) or return garbage (fake)? |
| 21 | Per-outbound fleet matrix (auto on multi-outbound) | Tunnel-tests **each outbound** of a balancer/multi-outbound config and prints a health table by tag; tells a single dead endpoint apart from a fleet-wide config fault. Auto-enables when the JSON has >1 outbound; `--no-fleet` to disable |
| — | Routing coverage / split-tunnel (auto on `routing.rules`) | Maps the `routing` table per outbound (domain/geosite/geoip counts), resolves the default route, lints undefined `outboundTag`s, and — when the tunnel is up — fetches a sample of **proxy-routed** sites through the live config to confirm the split actually carries them. Also flags **`domainStrategy` DNS-leak risk** (`IPOnDemand`/`IPIfNonMatch` with no `dns` block → routing resolves via the system resolver; recommends `AsIs` or a **split-horizon** `dns` block — detected separately), and a **streaming/payment-vs-datacenter-egress conflict** (those services geo-block datacenter exits) |
| 22 | Bufferbloat / latency-under-load (auto with 12) | Warm RTT idle vs under a saturating download — the latency the tunnel adds when busy (what makes a "fast" link laggy on calls/gaming). `--no-bufferbloat` to skip |
| 23 | Path MTU to server (auto) | DF-bit `ping` sweep finds the path MTU; a clamp below 1500 fragments the Reality ClientHello and can cause intermittent handshake failures that mimic DPI |
| 24 | TLS-negotiation parity — JA3S-grade (auto) | Does the server negotiate the same TLS version / ALPN / cipher **and present the same ServerHello extension set** as the genuine cover? Emits a comparable **fingerprint hash** (server vs cover) — a JA3S/JA4S fingerprinter's view. Stealth depth-3 (15 cert → 20 HTTP → 24 negotiation); a fake/wrong-`dest` server diverges, often at the extension level even when version/cipher align |
| 25 | Cover-SNI region-throttle (auto) | Is the cover domain itself shaped in-region (which the tunnel silently inherits)? Direct fetch vs a neutral baseline; when the cover root is too small, cross-checks the tunnel throughput (which carries the cover SNI) |
| 26 | Detectability score (synthesis, always last) | Folds **active** stealth (15/20/24) **and passive** structure into one 0-100 score + band: non-443 port, SNI↔IP mismatch + conjunction (the VLESS-Reality signature), **cover-SNI quality** (NXDOMAIN / circumvention keyword / **self-owned-obscure** cover on a hosting net vs a CDN), and **TLS-in-TLS exposure** — VLESS-REALITY without `flow=xtls-rprx-vision` (scored +15; the advanced-censor passive vector, [USENIX'23](https://github.com/net4people/bbs/issues/281)). The uTLS fp is reported as a **tradeoff, not scored**. Emits a share-safe **deployment fingerprint** (identifies the config *template*, not its health) |
| — | Cover-SNI scanner (opt-in, `--scan-covers`) | Ranks candidate Reality `dest`/`serverName` covers by **TLSv1.3 + HTTP/2 + CA-valid cert + non-redirect** and names the best — the *pick-a-good-cover* counterpart to probe 26's *your-cover-is-weak*. Standalone (no config/tunnel). The cover-weak verdicts point you to it. (Only probe that reaches third-party sites, hence opt-in.) |
| — | Censored-URL sweep (opt-in, `--censor-sweep`) | OONI-`web_connectivity`-style: fetches commonly-censored hosts **direct vs through the tunnel** and classifies each (reachable-both / **blocked-direct → tunnel-carries-it** / direct-only → not-carried / blocked-both) — does the tunnel actually unblock what's censored? Direct-only when there's no tunnel. |
| — | Host exposure (auto with a config) | Does the server answer anything **beyond 443**? Checks giveaway ports (SSH/RDP, proxy-**panel** ports like x-ui/3x-ui). A real CDN edge exposes only 443 — an open panel is both a takeover risk and a loud tell to a scanner profiling the IP. |
| — | Volume-throttle hint (auto with 12) | Cross-probe **temporal** synthesis: if the tunnel carried data early (12-14) but every later sustained-use probe (egress/stability/bufferbloat) then degraded, flags possible **cumulative-volume throttling** — the one in-region effect a single run can hint at, since probe 14 generates the load. Advisory only (**never scored**), hedged; points at a small-pull re-test (`XRAY_SPEEDTEST_MAX_BYTES` small / `--no-speedtest`) to confirm |

The verdict ends with the detected blocks plus a recommendation for each, each
**tagged `[server-side]` / `[client-side]` / `[network]`** so you know what to
fix in your config vs. what needs the operator. It opens with a one-line **fix
class** (the ByeDPI-vs-Xray call, chosen from what fired): **PARSER** (a
fragmentation bypass was confirmed → a client-side desync beats it, no server)
vs **DESTINATION/PROBE** (IP block / active probing / detectable protocol →
needs a Reality/Xray tunnel).

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

> **You can also drive probes 12 + 13 straight from a `--xray-config URL`.**
> If you pass only a share link (no `--xray-config-json`), the script
> synthesizes a minimal config from it — one proxy outbound + a freedom
> direct, single socks inbound — so a single `--xray-config URL` runs
> probes 11, 12 **and** 13 together. Supports `vless://` / `trojan://`
> with reality / tls (incl. `allowInsecure`/`insecure`) over tcp / ws / grpc /
> xhttp (xhttp carries `path`/`host`/`mode`). The synthesized file holds live
> credentials, is written `0600`, and is removed by the EXIT trap. For
> `vmess://` (base64), `ss://`, `hysteria*` or `tuic://`, or for any
> chained / balancer / fragment setup, pass a real `--xray-config-json`.

#### Multi-outbound configs — `--outbound TAG`

A config can carry several proxy outbounds — split-tunnel routing (e.g.
`proxy-ru` vs `proxy-foreign`), or a balancer fleet. The full-config probe (12)
runs them all with routing intact; the single-server fingerprint probes (host,
cover cert, active-probe, TLS-parity, detectability) target **one** of them. By
default that's the first proxy outbound, and a note tells you how many there are:

```
note: config has 2 proxy outbounds (proxy-ru, proxy-foreign); the full config is
tested as-is (routing intact), and the single-server probes target the first —
pass --outbound TAG to focus another
```

```
# fingerprint the foreign endpoint specifically
./detect_blocking.sh --xray-config-json cfg.json --outbound proxy-foreign
```

`--outbound TAG` narrows the config to that outbound (chosen + a `freedom`
direct, `routing`/`balancers` dropped) and tests that server standalone. An
unknown tag, or one that isn't a proxy outbound, errors with the valid tags. For
**chained** outbounds (`dialerProxy`) it warns — a hop isn't a standalone server,
so test the full config (no `--outbound`) instead, which probe 12 runs end-to-end.

#### High-RTT tunnels: automatic slow-handshake retry

Multi-hop paths (e.g. a RU-ingress → EU-egress chain) often need 5-8s to
complete the Reality handshake — more than the 5s default `TIMEOUT`. Rather
than mislabel a slow-but-working tunnel as blocked, probes 11 and 12 retry
once at 4× the budget when the first attempt **times out** (as opposed to
being actively reset). On success they report `slow handshake, not blocked`
and suggest the `TIMEOUT=N` that avoids the first-attempt miss:

```
[WARN]  handshake exceeded 5s — retrying once at 20s (high-RTT / multi-hop tunnel?)
[OK]    tunnel established on retry, RTT 5584 ms — slow handshake, not blocked
        tip: this path needs TIMEOUT≥20; set 'TIMEOUT=20' to avoid the first-attempt timeout
```

The verdict text now distinguishes the two failure modes: a *timeout*
(even after the retry) reads "slow or throttled tunnel egress, not a
fingerprint block — raise TIMEOUT"; an active *reset / closed pipe* keeps
the "protocol-fingerprint DPI or config drift" verdict. The JSON exposes
this as `failure_kind` (`timeout` | `reset` | `other`) and
`slow_handshake_retry` (bool) on both `xray_protocol` and
`xray_full_config`.

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

### Hysteria2 configs — static analysis (QUIC/UDP)

Hysteria2 is **QUIC over UDP/443** — a different stack from Xray/Reality (no
cover relay, no TLS-in-TLS). The Xray probes don't apply, and a TCP/TLS probe
against a UDP/443 server would falsely read "unreachable". Pass a Hysteria2
**client config** — YAML or JSON to `--xray-config-json`, or a `hysteria2://`
URI to `--xray-config` — and the script auto-detects it and runs a static
analyzer instead:

```
./detect_blocking.sh --xray-config-json hysteria-config.yml
```

```
== Hysteria2 config analysis (QUIC/UDP — static) ==
          Hysteria2 detected — QUIC over UDP/443. The Xray/Reality probes don't apply; static read.
  [WARN]  the TLS SNI carries a protocol/circumvention keyword — sent in cleartext in the QUIC Initial,
          which the GFW decrypts and reads (since 2024); a censor identifies and blocklists it at a glance
          no explicit tls.sni — the QUIC Initial SNI defaults to the server hostname …
  [WARN]  no obfs (salamander) in the client config — the QUIC handshake is fingerprintable …
          Hysteria2 lives on UDP/443 with no TCP fallback — wholesale UDP/443 blocking takes it down …
```

It checks the **cleartext SNI** (QUIC carries it in the Initial, which the GFW
reads — a protocol/circumvention keyword there, or a dedicated host SNI when no
innocuous `tls.sni` is set, is one-glance identification), whether **obfs
(salamander)** and cert verification are in place, and the **UDP/443
single-point + QUIC-SNI** risks. It also says plainly that what dominates
detectability — the **server's** masquerade target, cert, and enforced obfs —
isn't visible in a client config. JSON: `probes.hysteria.{status, sni_keyword,
sni_explicit, obfs, insecure}` (booleans only — share-safe; the raw SNI prints
only under `--reveal`).

### Happ deep links (`happ://`)

[Happ](https://happ.su) is a popular client whose `happ://` deep links wrap
configs. Pass one straight to `--xray-config`:

```
# a single config wrapped in an import link → unwrapped and tested
./detect_blocking.sh --xray-config 'happ://import/vless://…@host:443?security=reality&…'

# a routing profile → recognised + linted (no server to tunnel-test)
./detect_blocking.sh --xray-config 'happ://routing/add/<base64-json>'
```

- **`happ://import/<url>`** unwraps the inner share-link (vless/vmess/trojan/ss/
  hy2/…) and runs the normal probes against it — including the Hysteria2 analyzer
  for a `hy2://` inner. The inner URL may be plain, percent-encoded, or base64.
- **`happ://routing/add/<b64>`** is a **routing/DNS profile, not a server**. It's
  decoded and summarised, and linted with the same reasoning the routing/egress
  probes use — the `IPOnDemand` DNS-leak vector (and whether `FakeDns` mitigates
  it), and a remote DoH resolver whose domain is itself region-blocked (e.g.
  `cloudflare-dns.com` in RU). There's no tunnel to test; pass the VLESS/Reality
  config the profile is paired with for that.
- **`happ://crypt…`** is **RSA-encrypted** — only the Happ app with the private
  key can open it. The tool detects it and asks for the decrypted `vless://` or
  the plain subscription URL instead.

### Subscriptions (`--subscription`)

Point `--subscription` at a subscription URL and the tool fetches it (with a
cookie jar and a client User-Agent, so the common 302-cookie-challenge and
UA-gated panels work), decodes it (a JSON array of Xray configs, a single config
object, or base64), and prints a **fleet inventory**. By default it then runs the
full suite against one server (`--sub-test N`, default 0). Pass `--sub-test all`
to score **every** server with a fast no-tunnel fingerprint pass — no xray spawn,
no data pull, so a whole fleet is just TLS handshakes, probed **concurrently**
(in batches of `--sub-jobs`, default 8; `--sub-jobs 1` forces serial):

```
./detect_blocking.sh --subscription 'https://example.com/sub/<token>' --sub-test all
```

Add `--yt-test` to also get a per-node **YouTube** column — each node spins a
short-lived tunnel and runs a 6-connection YouTube fan-out (`ok` / `slow`=throttled
/ `capped` / `fail`). This spawns one xray per node, so it's much slower than the
fingerprint walk (batch defaults to 3; `--sub-jobs N` to change):

```
./detect_blocking.sh --subscription 'https://example.com/sub/<token>' --sub-test all --yt-test
```

```
== Subscription fleet scan — 28 configs (fingerprint-only, no tunnel) ==
  fp = deployment template (same fp = same server build); per-node signals are in the 'signal matrix' below
  #   remarks         server:port                cover              detect       fp
  0   Auto            edge01.example.net:443     www.microsoft.com  100/critical abcdef01
  7   Country B       edge07.example.net:443     news.example.io    70/critical  abcdef01
  9   Country C       edge09.example.net:8443    cdn.example.io     60/high      a1b2c3d4
  fleet detectability: 27 critical · 1 high · 0 moderate · 0 low · 0 unreachable …
  signal matrix (x = signal fired; rows grouped by identical signal-set, most common first; 'total' = nodes per signal):
    nodes                         SS CI CN NR TP SI NX CO NP UT EX
    [0-6,8,10-27] (26)            x  x  x  x  x  x  .  x  .  x  x
    [7] (1)                       x  x  x  .  .  .  x  .  .  x  x
    [9] (1)                       .  .  .  .  .  .  .  x  x  .  x
    total                         27 27 27 26 26 26 1  27 1  27 28
    legend: SS=self-signed CI=chain-invalid CN=cn!=sni NR=no-relay TP=tls-parity SI=sni!=ip NX=sni-nxdomain CO=cover-obscure NP=non443 UT=utls-rare EX=exposed
  remediation plan (fixes ranked by nodes affected; a node may need several):
    1. [27 node(s): 0-6,8-27] Reality cover not relayed / cover-cert invalid — point Reality dest + serverNames at the real cover host:443 (server-side; clears self-signed/chain/cn/no-relay/parity at once)
    2. [28 node(s): 0-27] Management/SSH port(s) open on the VPN IP — firewall so only 443 is reachable from outside
    3. [4 node(s): 7,9,16,22] Cover SNI does not resolve or is a low-quality/self-owned domain — use a real, resolvable, popular HTTPS cover the server relays to
    4. [1 node(s): 9] Listener on a non-standard port — move it to 443
  bottom line:
    · uniformity: 2 deployment template(s); abcdef01 covers 27/28 scored nodes — a server-side template fix touches most of the fleet at once
    · single-probe identifiable: 28/28 present a self-signed/mismatched cover cert — one unauthenticated TLS connection to the listener is enough to flag the IP
    · residual after fix #1 (relay the cover): exposed(28) cover-obscure(27) non443(1) — cleared by fixes #2+
  deep-test any server (tunnel + throughput + stability) with: --sub-test N
```

The closing **bottom line** is a short, computed synthesis: how *uniform* the fleet
is (templates), how *cheaply* a censor identifies it (single-probe), and the
*residual* exposure left after the #1 fix — so the plan's payoff and its limits are
explicit. Every number is derived from the measured signals.

The table stays a clean, fixed-width row per server (it never wraps); the per-node
**signals are a `signal matrix`** — a grid with signals as fixed columns and nodes
grouped by identical signal-set, so a uniform fleet collapses to a few rows, you can
scan a column to see which nodes share a signal, and any node that differs stands
out as its own row. The `total` row is the per-signal node count. The
**remediation plan** is the payoff: most signals are *symptoms of one root fix*
(self-signed / chain-invalid / cn!=sni / no-relay / tls-parity all clear when the
cover is relayed), so the plan collapses them into a handful of fixes, tells you
**how many nodes each clears and which** (range-compressed), and ranks by impact.

- **Signal tokens** (decoded by the matrix legend; values carried where they have one):
  - **Cover / active probe:** `self-signed` / `cover-mismatch` / `cover-unreach`
    (Reality cover-cert), `chain-invalid`, `cn!=sni` (cert CN ≠ serverName),
    **`no-relay:CODE`** (the active prober got HTTP `CODE` from the server posing as
    the cover instead of a relay — e.g. `no-relay:403`; curl's `000` = *no response*
    shows as `no-relay:noresp`), **`tls-parity:DIMS`** (server TLS ≠ cover TLS on
    `ver`/`alpn`/`cipher`/`ext`).
  - **Passive fingerprint:** `sni!=ip`, `sni-nxdomain`, `non443`, `sni-kw`,
    `cover-obscure`, `vision-off` (TLS-in-TLS not protected), **`utls-rare:FP`**
    (uncommon uTLS fp, named — e.g. `utls-rare:qq`, which can be deliberate), `mux`.
  - **Correctness / exposure:** `fet`, `id-nonuuid`, `clock:Ns` (clock skew ≥ 5s),
    **`exposed:PORTS`** (the actual open service ports, e.g. `exposed:22+8080`).
  - `clean` means nothing fired.
- **`fp`** is a short **deployment-template fingerprint**; servers built from the
  same template share it. The fleet table is fingerprint-only — for the full
  tunnel + throughput + stability picture on a specific row, run `--sub-test N`.

### Connection-limit probe (`--conn-test [N]`)

Opt-in robustness check: opens **N simultaneous TLS handshakes** (default 16) to the
server and reports how many complete + the handshake-time spread, so you can see
whether the server **caps / rate-limits / degrades under concurrency** — which is
what clients behind CGNAT or with many devices actually hit. It's a *server
robustness / UX* signal, not a censorship one.

```
# standalone against one config/host
./detect_blocking.sh --xray-config 'vless://…' --conn-test 32

# deep-test one fleet node, including its connection handling
./detect_blocking.sh --subscription URL --sub-test 7 --conn-test
```

Verdicts: **clean** (handled N concurrent, stable) · **capped** (only X/N completed
— a low connection cap / rate-limit) · **degraded** (all completed but handshake
time ballooned under load) · **all-failed** (TCP open but every handshake dropped).
It's a direct probe (no tunnel) and never auto-runs — it's not part of `--sub-test
all`. JSON: `probes.conn_limit`.

### YouTube reachability under fan-out (`--yt-test [N]`)

The *destination-side* companion to `--conn-test`: opens **N concurrent connections
through the tunnel** to real YouTube-infra hosts (`www.youtube.com`,
`youtubei.googleapis.com`, `i.ytimg.com`, `yt3.ggpht.com` — override with
`XRAY_YT_HOSTS`) and reports how many complete + the TTFB spread. That's the
parallel-origin fan-out real playback actually generates, so it catches the "VPN
connects but YouTube buffers / won't load" case a single-stream throughput test
misses — and **empirically** confirms what probe 16 only *infers* (googlevideo
throttles datacenter/VPN egress IPs).

**On by default** for any tunnel run (a light **N=6**), including `--sub-test N`:

```
./detect_blocking.sh --xray-config 'vless://…'                 # YouTube fan-out runs automatically (N=6)
./detect_blocking.sh --subscription URL --sub-test 7          # …and on a deep-tested fleet node
./detect_blocking.sh --xray-config 'vless://…' --yt-test 32   # force a thorough run (32 conns)
./detect_blocking.sh --xray-config 'vless://…' --no-yt-test   # disable it
```

It **auto-skips inside `--watch` / `--from-file` loops** (so a monitoring cadence
doesn't hammer YouTube every iteration); pass `--yt-test` to force it there. Same
verdicts as `--conn-test` (clean / capped / degraded / all-failed).

It reuses probe 12's tunnel **inbound** but runs **independently of probe 12's
verdict** — a failure to reach *Cloudflare* (probe 12's target) no longer suppresses
the YouTube measurement, and a divergence is its own signal: *YouTube works but
Cloudflare doesn't* → the tunnel is alive and Cloudflare is blocked at the egress;
*both fail* → the tunnel itself isn't passing traffic (Reality auth/handshake — verify
UUID/keys/flow). It never runs in the `--sub-test all` fleet walk, skips only if
there's no tunnel inbound at all, and is bounded (~10s) so a dead/silent tunnel can't
hang it. Egress-quality / QoE signal, not a censorship one. JSON: `probes.youtube_reach`.

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

### Probe 14 — real capacity (multi-stream, multi-endpoint)

Probe 13 deliberately uses **one** stream — that's what makes it a clean
shaping detector, but it's a terrible *capacity* meter. A single TCP stream
over a high-RTT tunnel is limited by `window ÷ RTT` (the bandwidth-delay
product), so it can read ~10 Mbps on a link that actually carries 100+
Mbps. That's not a bug — it's why every real speedtest (Ookla, fast.com)
opens many parallel connections.

Probe 14 does the same: **N parallel streams (default 4) against several
public CDN backends** (Cloudflare, DataPacket, OVH), through the probe-12
tunnel, and reports the **best aggregate** as the usable-bandwidth
estimate. Multiple endpoints mean one slow/blocked/dead path can't skew the
result; the per-stream timeout is derived from probe 12's measured
handshake RTT so streams clear the Reality handshake before the download
window opens.

```
== 14. Xray tunnel capacity (multi-stream / multi-endpoint) ==
          4 parallel streams × 3 endpoint(s), ≤50 MB total, 12s/stream (~5s handshake + 5s window)
            cloudflare: 9.0 MB/s (75.8 Mbps)
            datapacket: 8.1 MB/s (68.0 Mbps)
            ovh: 7.4 MB/s (62.1 Mbps)
  [OK]    best capacity: 9.0 MB/s (75.8 Mbps) via cloudflare (4 streams)
          note: 4 MB/stream is small for a fast link — raise XRAY_SPEEDTEST_MAX_BYTES for a fuller reading (this is a floor)
```

It **runs by default** whenever probe 12 succeeds. Because each run pulls
tens of MB through your (possibly metered) egress, it auto-skips inside
`--watch` / `--from-file` loops, and you can disable it entirely:

```sh
./detect_blocking.sh --xray-config-json ~/.xray-test.json --no-speedtest   # skip probe 14
./detect_blocking.sh --xray-config-json ~/.xray-test.json --speedtest      # force it even in --watch/--from-file
```

> **Reading the number.** With the default ~50 MB budget split across
> 3 endpoints × 4 streams (~4 MB/stream), a fast link finishes inside TCP
> slow-start, so the figure is a **floor**, not a ceiling. For a reading
> that approaches your real cap, raise the budget:
>
> ```sh
> XRAY_SPEEDTEST_MAX_BYTES=$((300*1024*1024)) ./detect_blocking.sh --xray-config-json ~/.xray-test.json
> ```

Tuning knobs (env vars):

```sh
XRAY_SPEEDTEST_STREAMS=8        # parallel streams per endpoint (default 4)
XRAY_SPEEDTEST_MAX_BYTES=...    # total download budget in bytes (default ~50 MB)
XRAY_SPEEDTEST_SECONDS=10       # download window per stream, after handshake (default 5)
# Endpoints: space-separated name|url|mode triples. mode=cf → ?bytes=N, mode=range → HTTP Range.
XRAY_SPEEDTEST_URLS='cloudflare|https://speed.cloudflare.com/__down|cf datapacket|https://lon.download.datapacket.com/100mb.bin|range'
```

JSON output:

```json
{
  "probes": {
    "xray_speedtest": {
      "status": "ok",
      "streams": 4,
      "best_endpoint": "cloudflare",
      "best_bytes_per_second": 2271145,
      "best_mbps": 18.17,
      "per_endpoint": [
        { "name": "cloudflare", "bytes_per_second": 2271145, "mbps": 18.17 },
        { "name": "ovh",        "bytes_per_second": 2073865, "mbps": 16.59 }
      ]
    }
  }
}
```

Status values: `ok`, `skipped` (probe 12 didn't bring up a tunnel),
`skipped-loop` (inside `--watch`/`--from-file` without `--speedtest`),
`disabled` (`--no-speedtest`), `no-result`, `curl-missing`.

### Probes 15-17 — stealth, integrity, stability

Probes 11-14 answer *"does the tunnel connect, and is it fast?"* — but Reality
exists for **stealth** and a VPN exists for **no leaks**. Probes 15-17 cover
the dimensions the others miss. All three are **safe to share**: their
output and JSON carry verdicts, booleans and a country code only — never the
cover domain, the raw egress IP, or the provider name.

**Probe 15 — Reality cover authenticity.** Connects plain-TLS
(unauthenticated, exactly what a GFW/TSPU active prober does) with the
configured `serverName` and inspects the cert. A genuine Reality server
relays such clients to the **real** cover site, so they see a CA-valid cert
for that name. A self-signed or mismatched cert means the cover is fake and
an active prober flags the server instantly. The match is checked against the
cert's full **SAN** list with wildcard logic (so `CN=example.com` + SAN
`*.example.com` correctly covers a `host.example.com` serverName, not a false
mismatch):

```
== 15. Reality cover authenticity ==
          unauthenticated TLS probe (what an active prober sees)
          cover cert: self-signed=1, chain-valid=0, CN-matches-serverName=1
  [FAIL]  cover certificate is self-signed → fake cover, trivially fingerprinted
```

**Probe 16 — egress integrity.** Through the tunnel, looks up the egress
geo + datacenter/proxy/mobile flags (is the exit already on the lists that
Netflix / banks block?) and the DNS-resolver region:

```
== 16. Egress integrity (geo / reputation / DNS) ==
          egress: country=NL, hosting=1, proxy=0, mobile=0
  [WARN]  egress IP is flagged as datacenter/proxy — streaming & banking services likely to block it
```

It sends the egress IP to a 3rd-party IP-info service (`ip-api.com` by
default). Disable with `--no-egress-check`, or point `XRAY_EGRESS_INFO_URL`
at your own.

**Probe 17 — held-session stability.** Pulses an **escalating size ladder**
through the tunnel (tiny → 256 KB → 1 MB → 4 MB) and classifies each pulse by
curl exit code — **ok**, **slow** (timeout), or **killed** (reset/closed
mid-stream). This catches the censor tactic of allowing the handshake and
trivial traffic, then RST-ing the connection once a transfer crosses a byte
threshold — **volumetric kill-shaping** that trace-only pulses can never
reveal:

```
== 17. Held-session stability (delayed-RST detection) ==
          pulse ladder: 0 262144 1048576 4194304 bytes (0 = tiny), ≤45s total
            tiny  pulse: ok (120 ms)
            256KB pulse: ok (180 ms)
            1MB   pulse: ok (240 ms)
            4MB   pulse: killed
  [FAIL]  tunnel reset at the 4MB pulse (smaller pulses passed) — volumetric kill-shaping
```

A reset that appears only on the larger pulses is the volumetric signature; a
reset on every pulse is a connection-level kill; timeouts with **no** resets
are reported as merely *slow* (degraded), not killed — so a high-RTT tunnel is
no longer mislabelled "unstable." Runs by default; auto-skips in
`--watch`/`--from-file` loops (`--stability` forces it there), `--no-stability`
disables. Tune the ladder with `XRAY_STABILITY_SIZES`.

JSON adds `probes.xray_cover` (booleans), `probes.xray_egress` (country +
flags), and `probes.xray_stability` (per-pulse ladder with ok/slow/killed
states, `kill_at_bytes`, RTT range).

### Probes 18-21 — correctness + behavioural stealth + fleet

**Probe 18 — config pre-flight lint** is static and instant, and catches the
misconfigs that otherwise masquerade as DPI: `flow=xtls-rprx-vision` without
`network=tcp`, a non-hex or over-long `shortId`, a bare-IP `serverName`, a
missing `publicKey`, vless `encryption≠none`, no uTLS fingerprint. It also flags
`allowInsecure=true` (a.k.a. `"insecure": true`) — the client accepts any cert,
which masks a cover cert that won't validate for the SNI (a strong active-probe
tell) and is MITM-able; because the check is static it fires **even against an
unreachable node**. Each finding names the protocol knob, never the secret
value. This is the cheapest, highest-leverage probe — half the "is it DPI?"
scares this tool was built to diagnose turn out to be a typo (its findings also
surface in the consolidated verdict block).

**Probe 19 — clock skew** checks a failure mode nobody thinks to: Reality
authentication is time-windowed, so a client clock off by minutes makes the
handshake fail *exactly* like a fingerprint block. It compares local time to
a server `Date` header and warns past ±60s.

**Probe 20 — active-probe resistance** is the behavioural half of probe 15.
Where 15 inspects the cover *certificate*, 20 inspects the cover *behaviour*
the way a censor's active prober does — it sends a real HTTPS request to the
server using the cover SNI and compares the response to the genuine cover
site fetched out-of-band:

```
== 20. Active-probe resistance (cover behaviour) ==
          unauthenticated HTTP probe (what an active prober sends)
          cover behaviour: relay-code=000, genuine-code=404
  [FAIL]  server returns no coherent HTTP to an unauth prober → not relaying to the cover
```

A real Reality server relays unauthenticated clients to the genuine cover →
matching response. A fake one returns no coherent HTTP (as above) or a
mismatch — a strong VPN fingerprint when combined with the self-signed cert
from probe 15.

**Probe 21 — per-outbound fleet matrix** is for balancer / multi-outbound
configs. It **auto-enables** when the JSON config has more than one proxy
outbound (and stays silent for single-outbound or URL-form configs), then
tunnel-tests every outbound (one xray spawn each) and prints a health table
keyed by the operator-defined tag — never the address or port. `--no-fleet`
disables it; because it's N xray spawns it auto-skips inside
`--watch`/`--from-file` loops unless you pass `--fleet`:

```
== 21. Per-outbound fleet health matrix ==
          testing 3 outbounds (one xray spawn each)
            node-a       [OK]   RTT 612 ms
            node-b       [OK]   RTT 588 ms
            node-c       [FAIL] tunnel unreachable
  [WARN]  2/3 outbounds healthy — partial fleet degradation
```

If *all* outbounds fail, the verdict points at the shared config (cover /
serverName / keys / flow) rather than a single dead endpoint.

JSON adds `probes.xray_lint` (findings list), `probes.xray_clock`
(skew_seconds), `probes.xray_active_probe` (relay vs genuine HTTP code +
match), and `probes.xray_fleet` (per-outbound table).

### Probes 22-24 — quality-of-experience + transport + stealth depth

All three are **pure bash** (no extra dependency beyond `curl`/`openssl`/`ping`)
and share-safe (ms / booleans / generic protocol values only).

**Probe 22 — bufferbloat / latency-under-load.** 13/14 tell you the tunnel is
*fast*; 22 tells you whether it stays *responsive when busy*. It measures warm
RTT (keep-alive, so the handshake is excluded) idle vs under a bounded
saturating download and reports the inflation — the queueing delay added under
load, which is what makes calls/gaming stutter during a download. Bands:
`<100ms` low · `<400ms` moderate · `≥400ms` heavy. `--no-bufferbloat` to skip.

**Probe 23 — path MTU to the server.** A DF-bit `ping` sweep finds the largest
unfragmented payload to the server IP. A clamp below 1500 fragments the Reality
ClientHello and can cause *intermittent* handshake failures that look like
flaky DPI — so if handshakes are sporadic, this tells you to clamp the MSS.
Reports `filtered` when ICMP echo is blocked.

**Probe 24 — TLS-negotiation parity.** The third stealth lens (15 = cert,
20 = HTTP behaviour, 24 = TLS negotiation): does the server negotiate the same
TLS version, ALPN, and cipher as the genuine cover site fetched out-of-band?

```
== 24. TLS-negotiation parity (vs genuine cover) ==
          negotiation: version-match=1, ALPN-match=0, cipher-match=0 (server TLSv1.3/http/1.1, cover TLSv1.3/h2)
  [WARN]  TLS negotiation differs from the genuine cover
```

A real relaying Reality server is byte-identical to the cover; a fake or
wrong-`dest` one diverges (above: it serves `http/1.1` where the real cover
offers `h2`) — a fingerprint an active prober can exploit, reinforcing 15/20.

JSON adds `probes.xray_bufferbloat` (idle/loaded/inflation/jitter ms),
`probes.xray_mtu` (path_mtu), and `probes.xray_tls_parity` (version/ALPN/cipher
match booleans).

### Probes 25-26 + baseline mode — synthesis & regression detection

**Probe 25 — cover-SNI region-throttle** automates a real production trap: the
cover domain itself being shaped in-region, which the Reality tunnel (which
presents that SNI) silently inherits — "fast handshake, slow data." It
compares a direct bulk fetch from the genuine cover vs a neutral baseline from
your vantage; a stark slowdown means *pick a different cover*. When the cover
root is too small to measure directly (common — API/asset hosts), it
**cross-checks the tunnel throughput** (which already carries the cover SNI in
bulk): a healthy tunnel proves the SNI isn't throttled at this vantage, a
collapsed one on clean transport flags it. Note it only detects a throttle
*where it's enforced* — run from the affected region, not a clean vantage.

**Probe 26 — detectability score (active + passive synthesis)** is the final
probe and folds *every* detection signal into one 0-100 number, because a censor
sees one server, not a list of findings. It weighs the **active** stealth probes
(15 cover cert / 20 active-probe resistance / 24 TLS-negotiation parity) *and*
the **passive** structure a censor can read off the wire without probing at all:

- the cover SNI served on a **non-standard port** (real cover sites use 443);
- the server IP **not on the cover domain's network** (SNI↔IP mismatch — decided
  by DNS membership first, then an ASN cross-check so large CDNs don't false-positive);
- the **conjunction** of those two — a *borrowed SNI on a non-standard port* is a
  recognized VLESS-Reality structural signature;
- **cover-SNI quality** — the serverName is sent in cleartext in every
  ClientHello, so a valid cert can't hide it: an SNI that **doesn't publicly
  resolve** (NXDOMAIN — a self-cooked name, not a real site you hide behind) or
  that carries a **circumvention/antagonistic keyword** (vpn, proxy, xray, a
  censor's name…) is exactly what a censor resolves to nothing or keyword-matches.
  A non-resolving cover is *also* why the active baselines (20/24) report "not
  evaluated" — there's no genuine cover site to compare against, and the score
  now says so instead of leaving a silent gap;
- the **uTLS fingerprint** — Reality mimics a browser's ClientHello. This is
  reported as a **tradeoff, not scored**: a rare/regional fp (`qq`/`360`)
  **evades signature/deny-list censors** like TSPU (which blocklists the
  near-universal `chrome`-uTLS-Reality JA3 — so `chrome` is often *more* blocked),
  but is an **outlier to anomaly detection**. Your empirical result against the
  target censor decides; the fp is still folded into the deployment fingerprint.

It also emits a **deployment fingerprint** — a short, stable, share-safe hash of
the config's *identifying shape* (protocol / security / network / flow / uTLS-fp
/ shortId-length / port / routing-recipe, and **nothing** sensitive). Two configs
from the same provider hash identically (only per-node IP/keys/SNI differ), so
you can match a known deployment to answer *"is this the same provider?"*.

Active tells weigh heaviest. Each passive tell alone is FP-prone (legit services
use 8443; domain fronting legitimately mismatches ASN), so they weigh less — but
when both co-occur the conjunction is bumped and the finding is **named**,
because together it's low-FP even against a server that defeats every active
probe. So a perfectly active-cloaked Reality server (0/100 on active probing)
that still serves a borrowed SNI on a non-standard port no longer reads as a
clean bill — it's flagged and named:

```
== 26. Detectability score (active + passive synthesis) ==
          active · cover cert (15):   authentic, matches serverName          +0
          active · active-probe (20): relays unauth probes to the real cover +0
          active · TLS parity (24):   version+ALPN+cipher match cover        +0
          passive · port:             non-standard (real cover sites use 443) +10
          passive · SNI↔IP network:   server IP NOT on the cover's network (SNI↔IP mismatch) +10
          passive · conjunction:      yes — borrowed SNI on a non-standard port +10
          bands: 0-14 low · 15-39 moderate · 40-69 high · 70-100 critical
  [WARN]  detectability 30/100 (moderate) — partially fingerprintable; see the breakdown above
  [WARN]  passive Reality/Xray fingerprint: borrowed SNI (cover lives on another network) + non-standard port
```

The breakdown is always printed, so the score is never a black box — every
signal that did (and didn't) fire is shown with its points.

#### SNI privacy / ECH posture (advisory)

Probe 26 scores the *quality* of the cleartext cover SNI but treats its
**visibility** as fixed. This advisory adds the orthogonal axis: **can that SNI
be hidden at all** (Encrypted ClientHello), and does the transport allow it? It
runs after probe 26 (unnumbered, so 26 stays the last *scored* probe, like the
volume-throttle advisory) and is **never folded into the score** — ECH adoption
isn't universal and Reality forgoes it by design, the same *"tradeoff, not
scored"* treatment the uTLS fp gets.

The posture is transport-aware:

- **Reality** → the cleartext cover SNI *is* the mechanism, so ECH does not
  apply. The lever is cover-SNI *quality* (probe 26), not encryption. Reported as
  `posture: reality`.
- **TLS-over-CDN** (ws/gRPC/xHTTP behind a front — the pattern where the SNI is
  your *own* fronted domain) → ECH **applies**, and the probe checks whether the
  front actually publishes an ECH config in DNS (an `HTTPS`/SVCB record with an
  `ech=` param, looked up via `dig` then a DoH-JSON fallback):
  - front publishes ECH but the client sends the SNI in cleartext →
    `ech-available-unused` — an available-but-unused mitigation (like a missing
    vision flow); enabling ECH client-side removes the cleartext-SNI tell entirely;
  - front publishes no ECH → `ech-unpublished` (front behind a provider that
    offers it to be able to hide the SNI);
  - couldn't tell (old `dig`, no DoH) → `ech-unknown` (treated as visible until
    confirmed — never guessed from raw record bytes).

Share-safe (the cover domain is only shown under `--reveal`); emitted in `--json`
under `.probes.xray_sni_privacy` (`posture`, `ech_applies`,
`ech_published_by_cover`, `sni_cleartext`).

#### Baseline / diff — turn the suite into a regression detector

Point-in-time probes answer *"is X true now?"* The higher-value operational
question is *"what changed since this node was healthy?"*

```sh
# Capture a healthy reference:
./detect_blocking.sh --xray-config-json ~/.xray.json --save-baseline ~/.db-baseline.json

# Later (e.g. from cron) — report only what drifted:
./detect_blocking.sh --xray-config-json ~/.xray.json --diff-baseline ~/.db-baseline.json
```

```
== Baseline diff (vs 2026-05-30T08:00:00Z) ==
  [WARN]  cover_selfsigned: false -> true
  [WARN]  capacity_mbps: 20 -> 5
  [WARN]  detect: 0 -> 80
  [WARN]  server host: changed
```

The compared signature is statuses / geo / booleans / bucketed numbers only —
run-to-run jitter won't trip it, and a changed server/egress IP is reported as
`changed`, never the value (so the diff is safe to paste). jq-only, no new
dependency.

JSON adds `probes.xray_cover_throttle` (cover vs baseline bytes/sec) and
`probes.xray_detectability` (`score`, `band`, `port_standard`,
`sni_ip_asn_match`, `passive_fingerprint_strong`).

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
      --xray-only         Only the Xray-protocol probes (11-26 + routing/egress);
                          skips transport probes 0-10. Alias for
                          --only xray,xrayjson; needs --xray-config[-json].
      --scan-covers[=LIST] Rank candidate Reality dest/serverName covers by
                          TLSv1.3 + H2 + CA-valid + non-redirect. LIST is
                          comma-separated; omit for a built-in set. Standalone.
      --censor-sweep[=LIST] Reachability of commonly-censored hosts, direct vs
                          through the tunnel (does the tunnel unblock them?).
                          LIST comma-separated; omit for a built-in set. Opt-in.
      --full, --thorough  Comprehensive run: enable both opt-in scanners
                          (--scan-covers + --censor-sweep). Everything else
                          already runs by default. Explicit on purpose —
                          --censor-sweep fetches censored sites from THIS machine.
      --skip LIST         Skip the listed probes (comma-separated).
      --watch SECONDS     Repeat probe every SECONDS until interrupted.
      --from-file PATH    Iterate over hosts in file (one per line, # comments).
      --pcap PATH         tcpdump probe traffic to PATH (needs root / cap_net_raw).
      --compare-sni LIST  Comma-separated SNI values for the SNI × port matrix.
      --compare-port LIST Comma-separated TCP ports for the SNI × port matrix.
      --port-survey       Scan curated list of common VPN/proxy alt ports.
      --xray-config URL       End-to-end Xray-protocol test (xray-knife).
                              vless://, vmess://, trojan://, ss://, hysteria2:// URLs.
      --xray-config-json SRC  Full-config end-to-end (xray-core + SOCKS5; covers
                              fragment, dialerProxy, noises, chained outbounds).
                              SRC is a file path, INLINE JSON ('{…}'), or '-'
                              (stdin). Single-quote inline JSON, or pipe it with
                              a quoted heredoc — --xray-config-json - <<'EOF' …
                              EOF — to dodge shell-quoting of { } " entirely.
                              A non-Xray config (e.g. sing-box, which uses
                              type/server/route) is detected and reported as
                              such; the Xray-protocol probes are skipped while
                              transport probes still run against its server.
      --subscription URL  Fetch a subscription (cookie-jar + client UA, so the
                          common 302-cookie-challenge / UA-gated panels work),
                          decode it (JSON array of Xray configs / single config /
                          base64), print a fleet inventory, and run the full suite
                          on one config. --sub-test N picks which (default 0);
                          --sub-test all scores EVERY server (fast fleet table
                          with per-server `tells` + deployment-template `fp`);
                          --sub-ua sets the User-Agent (default Happ/2.6.0).
      --no-tunnel         Run only the direct fingerprint probes (cover / active-
                          probe / TLS-parity / detectability) — no xray spawn, no
                          throughput. Fast detectability read; powers --sub-test all.
      --json              Emit machine-readable JSON; implies --quiet. Requires jq.
      --reveal            Print the real offending values (cover serverName,
                          flagged SNI, egress IP / org) to the TERMINAL. Off by
                          default; terminal-only — never logged, never in --json,
                          never committed. NOT safe to paste / share.

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
`target`, `environment`, `probes`, and `verdicts`. With an Xray config, `probes`
adds the `xray_*` set (`xray_json`, `xray_egress`, `xray_lint`, `xray_routing`,
`xray_detectability`, …) — run `--json | jq '.probes | keys'` for the full list.
Notable fields: `xray_lint.fet_exposed`/`id_uuid`, `xray_routing.dns_leak_risk`/
`dns_split_horizon`, `xray_detectability.tls_in_tls_protected`/`volume_throttle_suspected`/
`deployment_fingerprint`, `udp.quic_verdict`/`quic_baseline`, `host_exposure.status`,
`hysteria.sni_keyword`.

### Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `VPN_HOST` | `www.example.com` | Target hostname |
| `VPN_PORT_TCP` | `443` | Target TCP port |
| `IKEV2_HOST` | `$VPN_HOST` | Separate IKEv2 host (if different) |
| `OPENVPN_HOST` | `$VPN_HOST` | Separate OpenVPN host |
| `OPENVPN_PORT_UDP` / `OPENVPN_PORT_TCP` | `1194` | OpenVPN ports |
| `BASELINE_IPS` | `1.1.1.1 8.8.8.8 9.9.9.9` | Baseline reachability chain (any one passes) |
| `BASELINE_DOMAIN` | `cloudflare.com` | Reference host for the clock-skew `Date` fetch |
| `XRAY_QUIC_BASELINE` | `cloudflare-quic.com` | Known QUIC host for the UDP/443 reachability baseline (probe 6) |
| `FAKE_SNI` | `www.microsoft.com` | Innocent SNI for SNI-DPI test |
| `CONTROL_SITES` | `www.protonvpn.com www.torproject.org www.discord.com` | Broad-censorship control set |
| `DOH_URL` | `https://1.1.1.1/dns-query` | DoH endpoint |
| `TIMEOUT` | `5` | Per-probe timeout (seconds) |
| `STRICT_OPENVPN_VERDICT` | `0` | Set `1` to emit hard verdict on silent OpenVPN handshake |
| `XRAY_THROUGHPUT_TARGET_BYTES` | `10485760` | Probe 13 download sample size (10 MB); raise for slow links to escape TCP slow-start |
| `XRAY_THROUGHPUT_TIMEOUT` | `20` | Probe 13 download deadline (seconds); raise for high-RTT tunnels |
| `XRAY_THROUGHPUT_URL` | `https://speed.cloudflare.com/__down` | Probe 13 throughput endpoint; must accept `?bytes=N` query |
| `XRAY_SPEEDTEST` | `1` | Probe 14 on/off (set `0`, or `--no-speedtest`, to disable) |
| `XRAY_SPEEDTEST_STREAMS` | `4` | Probe 14 parallel streams per endpoint |
| `XRAY_SPEEDTEST_MAX_BYTES` | `52428800` | Probe 14 total download budget (~50 MB); raise for a fuller capacity reading |
| `XRAY_SPEEDTEST_SECONDS` | `5` | Probe 14 download window per stream, after the handshake |
| `XRAY_SPEEDTEST_URLS` | CF / DataPacket / OVH | Probe 14 endpoints — space-separated `name\|url\|mode` triples (`mode`=`cf`\|`range`) |
| `XRAY_EGRESS_CHECK` | `1` | Probe 16 on/off (set `0`, or `--no-egress-check`, to skip the 3rd-party IP-info call) |
| `XRAY_EGRESS_INFO_URL` | `ip-api.com/json` | Probe 16 IP-info endpoint (point at your own to avoid the public service) |
| `XRAY_STABILITY` | `1` | Probe 17 on/off (set `0`, or `--no-stability`, to disable) |
| `XRAY_STABILITY_SIZES` | `0 262144 1048576 4194304` | Probe 17 pulse size ladder in bytes (`0`=tiny); escalate to expose byte-threshold (volumetric) kills |
| `XRAY_STABILITY_SECONDS` | `45` | Probe 17 overall wall-clock cap for the ladder |
| `XRAY_STABILITY_INTERVAL` | `2` | Probe 17 pause between pulses |
| `XRAY_BUFFERBLOAT` | `1` | Probe 22 on/off (set `0`, or `--no-bufferbloat`, to disable) |
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
bash tests/test_doh_compromise.sh        # spins up a local fake-DoH server
bash tests/test_subscription_http.sh     # local fake panel: UA gate + 302 cookie challenge
```

The CI workflow (`.github/workflows/test.yml`) runs shellcheck, the secret-scan, and
smoke + subscription/fleet tests on macOS and Ubuntu. The subscription pipeline
(`--subscription … --sub-test all`) is covered hermetically: `tests/test_subscription_http.sh`
stands up a local stdlib HTTP server (`tests/fixtures/fake_sub_server.py`) that
UA-gates and runs a 302 cookie challenge, then serves a synthetic sub of **safe
placeholders** against loopback closed ports — so the full fetch → decode → walk →
table → remediation-plan path runs with no real infra and no secrets.

### Run a subscription on GitHub Actions (on-demand)

`.github/workflows/sub-run.yml` lets you run the tool **on GitHub** without committing
anything: **Actions → "sub-run (manual)" → Run workflow**, then either paste a
`sub_url` / `sub_json` or rely on a stored secret. Output defaults to a **redacted**
summary (counts + remediation plan — never hostnames/covers/fingerprints).

> ⚠️ **Public repo:** `workflow_dispatch` inputs and run logs are world-readable. For a
> real, tokened subscription URL, **store it as the `SUB_URL` repo secret** (Settings →
> Secrets and variables → Actions) and leave the `sub_url` field blank — secrets are
> masked. Use the paste-in fields only for sharing-safe data, and set `redact: false`
> only on a private repo/fork.

### secret-scan & the banned list

`scripts/secret-scan.sh` blocks real infra (product names, hostnames, IPs, tokens,
ids) from entering this public repo. Because those values *are* the secrets, they are
**not stored in the repo** — copy `scripts/.banned.example` to `scripts/.banned`
(gitignored) and fill in your own ERE patterns, or set them as the `SECRET_SCAN_BANNED`
repo secret for CI. `bash scripts/install-hooks.sh` wires it as a pre-commit hook.
A second, listless layer always catches generic UUIDs / Reality keys / public IPs.

---

## Limitations

- IPv6 probes are not yet implemented.
- TLS fingerprint testing is surface-level (UA only); use `curl-impersonate`
  for real JA3.
- UDP IKE probe needs `perl`; missing → that probe is skipped.
- Some macOS VPN clients hijack DNS in ways that confuse Section 0 detection.
- IP reputation/geo is queried HTTPS-first (`ipinfo.io`/`ipwho.is`/`ipapi.is`) but
  falls back to plain-HTTP `ip-api` (its free tier is HTTP-only), which an on-path
  adversary can spoof — treat reputation as indicative on a hostile network, or set
  `XRAY_EGRESS_INFO_URL` to an HTTPS endpoint.

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

**Never commit real server data.** Use placeholders in tests and docs — all-zero
UUIDs, `www.example.com`/`www.microsoft.com` cover SNIs, and TEST-NET
(`192.0.2.0/24`) or loopback IPs. A secret scanner enforces this: it runs in CI
(`scripts/secret-scan.sh`) and blocks anything that looks like a real credential
or fleet infra — a real UUID, a 43-char Reality public key, or a public server IP
in `"address"`/`@host` position — on top of an explicit banned-string list.
Install it locally so leaks are caught before they're even committed:

```bash
./scripts/install-hooks.sh    # adds a pre-commit hook → secret-scan.sh --staged
```

## License

[MIT](LICENSE).
