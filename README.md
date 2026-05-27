# detect-blocking

A single-file Bash diagnostic that classifies **what kind of network filtering**
is preventing a VPN endpoint from working — DNS poisoning, IP blocks,
SNI-based DPI, mid-handshake RST injection, silent drops, UDP/QUIC bans,
OpenVPN signature blocks, and more.

Built for operators who need to answer one question fast: *"is my server
blocked, and if so, by what mechanism?"*

[![Test](https://github.com/velesnitski/detect-blocking/actions/workflows/test.yml/badge.svg)](https://github.com/velesnitski/detect-blocking/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Shell: Bash](https://img.shields.io/badge/Shell-Bash%203.2%2B-1f425f.svg)](https://www.gnu.org/software/bash/)

---

## What it does

Runs a deterministic 9-stage probe chain from your local machine to a target
endpoint and emits a clearly labelled verdict for each detected blocking type.

| # | Probe | Detects |
|---|---|---|
| 0 | Environment | Whether a VPN is currently active (results then describe the VPN exit path, not the local ISP) |
| 1 | DNS resolution | DNS sinkhole / system-DNS failure / DoH-MITM (via Cloudflare canary) / CDN-anycast divergence |
| 2 | TCP reachability | Full IP block vs port-specific (443 dead but 80 alive) |
| 3 | TLS handshake | SNI-based DPI (proper SNI dies, no-SNI works) |
| 4 | UA filtering | User-Agent based filtering (not full JA3 — see note below) |
| 5 | Mid-handshake RST | Active DPI reset (<1s) vs silent drop (full timeout) |
| 6 | UDP protocols | IKEv2 (valid IKE\_SA\_INIT probe) + QUIC/HTTP3 over UDP 443 |
| 7 | OpenVPN handshake | Random-SID `0x38` initiator, expects `0x40` server reset |
| 8 | Control sites | Broad vs targeted censorship (Tor/Proton/Discord reachability) |

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
          system resolver A: <cloudflare-anycast> <cloudflare-anycast>
          DoH resolver A:    <cloudflare-anycast> <cloudflare-anycast>
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

# Smoke run against the demo target
./detect_blocking.sh

# Real run against your endpoint
./detect_blocking.sh my-vpn.example.org
```

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

If any are missing, the script reports them once at startup and continues.

---

## Usage

```text
detect_blocking.sh [OPTIONS] [VPN_HOST]

Options:
  -h, --help              Show help.
  -V, --version           Print version and exit.
  -q, --quiet             Suppress stdout (logging to file still works).
      --log-file PATH     Append timestamped entries to PATH. Rotates at 10MB.

Override precedence:
  CLI arg > environment variable > detect_blocking.conf > built-in default
```

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
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
anycast hijack) and its answers are discarded for the rest of the run.

**Platform notes.** Section 0 uses platform-specific tools (`route` /
`scutil` / `ifconfig` on macOS; `ip route` / `ip link` / `nmcli` on Linux).
All other probes are portable across both. macOS TCP probes use `nc -G` (the
BSD connect timeout); Linux uses `nc -w`.

---

## Testing

```sh
# Syntax check + smoke test (no network mock)
bash tests/run.sh

# Individual:
bash tests/test_smoke.sh
bash tests/test_doh_compromise.sh   # spins up a local fake-DoH server
```

The CI workflow runs shellcheck plus smoke tests on macOS and Ubuntu.

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

## Limitations

- TLS fingerprint testing is surface-level (UA only); use `curl-impersonate`
  for real JA3.
- UDP IKE probe needs `perl`; missing → that probe is skipped.
- IPv6 probes are not yet implemented.
- The DoH canary protects against most MITM but not against a sophisticated
  proxy that allowlists `one.one.one.one`.
- Some macOS VPN clients hijack DNS in ways that confuse Section 0 detection.

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
