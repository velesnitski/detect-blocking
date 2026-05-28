# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Multi-DoH cross-check** (probe_dns): canary query against every URL in
  `DOH_PROVIDERS` (default Cloudflare + Google + Quad9). Distinguishes
  "single-provider MITM" (split DoH hijack) from "all-DoH MITM" (universal
  national-CA TLS interception). New verdicts:
  `All DoH providers compromised`, `Split DoH MITM`. JSON: `probes.dns.doh_multi`.
- **`--pcap PATH`** spawns tcpdump in background to capture probe traffic,
  scoped by `host VPN_HOST` BPF filter. Auto-cleanup via EXIT trap.
  Graceful fallback if tcpdump unavailable or sans cap_net_raw.
- **`--compare-sni LIST` / `--compare-port LIST`** matrix probe:
  iterates SNI × port grid via TLS handshake, emits a matrix table and
  `Bypass candidate found in compare matrix` verdict when an alt-combo works
  while the canonical (host:port) fails. New probe name: `compare`.
- **`--port-survey`** convenience flag: extends `--compare-port` with a
  curated list of common alt-VPN/proxy ports
  (8443, 2083, 2087, 2053, 8388, 4443, 9443, 51820, 1194, 500).
- **All `vpn.example.org` placeholders replaced with `www.example.com`**
  (IANA-managed, always-resolvable demo target — matches script default,
  copy-paste-runnable). Issue from README/CLI inconsistency.
- **`--from-file PATH` batch mode**: iterates over hosts in a file (one per
  line, `#` comments skipped), invoking the script per host. In `--json`
  mode emits ndjson (one compact JSON object per line) for stream-processing.
- **`--watch SECONDS` continuous mode**: re-runs the probe pipeline on a
  fixed cadence until interrupted (SIGINT/SIGTERM). Useful for monitoring a
  server's blocking state over time. Compatible with `--json` for ndjson
  streams into log pipelines.
- **`probe_ipv6` (probe 9 — IPv6 reachability)**: resolves AAAA records,
  probes IPv6 TCP + HTTPS to the same endpoint. New verdicts:
  `IPv4 blocked but IPv6 reachable` (prefer v6 client), `IPv6 transport
  also unreachable` (broader connectivity issue), `IPv6 HTTPS layer blocked`
  (v6 TCP works but TLS doesn't). New probe name: `ipv6` (for `--only`/`--skip`).
- **`--json` output mode** for monitoring / alerting integration. Emits a
  versioned JSON document with the full probe state (DNS sets, TLS results,
  RST timing, UA codes, verdicts, etc.) and suppresses human-readable
  stdout. Requires `jq`. `schema_version: 1`. New test `tests/test_json.sh`
  validates schema sanity in CI.
- **`--only` / `--skip` probe-selection flags** for fast re-runs of a single
  layer or skipping known-irrelevant probes. Probe names: `env`, `dns`, `tcp`,
  `tls`, `ua`, `rst`, `udp`, `openvpn`, `control`.
- **DoT integrity canary** (TCP 853): cross-checks `one.one.one.one`
  via `dig +tls` (BIND 9.18+) or `kdig` when available. Distinguishes
  "DoH MITM" from "all encrypted DNS MITM" and surfaces a hardened
  `DoT path is compromised` verdict when both fail.
- **TLS-record fragmentation bypass probe** in `probe_tls_handshake`:
  when proper-SNI handshake fails, retries with `openssl -max_send_frag 64`.
  If the fragmented variant succeeds, emits `DPI bypassable via TLS-record
  fragmentation` verdict pointing at split-SNI / record-splitting clients.
- **Real JA3/JA4 detection** in `probe_request_filter`: when
  `curl-impersonate-chrome` (or `curl_chrome116`, `curl_chrome`, etc.) is
  installed, runs a 3rd request with a full browser-grade ClientHello.
  Distinguishes UA filtering from true TLS-fingerprint DPI; emits
  `TLS fingerprint (JA3/JA4) filtering` verdict when only the impersonate
  client passes.

### Fixed

- `--help` no longer bleeds code into the help text — the `sed` range now
  stops at the end of the comment header (line 27) instead of including
  `set -u` and the `readonly` version line.
- **Probe 4 now detects UA filtering via block page.** Previously only a
  connection-level failure (`000`) was flagged; a censor returning an HTTP
  403/451 block page for the default UA while serving Chrome normally went
  undetected. Now a `403`/`451` from the default UA combined with a
  non-block status from the Chrome UA emits the User-Agent-filtering verdict.
- **`nslookup` fallback no longer leaks the resolver's own IP.** Collection
  now starts only after the first `Name:` block, instead of relying solely
  on the `#53` port suffix to filter out the server `Address:` line.
- HTTP/2 capability detection aligned with the HTTP/3 check
  (`grep -qiE 'HTTP2|HTTP/2'`).
- Probe-5 temp files are now removed via an `EXIT` trap, so an interrupted
  run (Ctrl-C mid-handshake) no longer leaks `/tmp/detect_blocking.*` files.

## [0.1.0] - 2026-05-27

### Added

- 9-stage probe chain: environment, DNS, TCP, TLS, UA filter, mid-handshake
  RST, UDP (IKEv2/QUIC), OpenVPN, control sites.
- **DoH integrity canary** against `one.one.one.one` (deterministic
  `1.1.1.1` / `1.0.0.1` answer) to catch MITM'd DoH responses that would
  otherwise mask local DNS poisoning.
- **Platform-aware** support: macOS (BSD `nc -G`, `route` / `scutil` /
  `ifconfig`) and Linux (`nc -w`, `ip route` / `ip link` / `nmcli`).
- Set-based DNS comparison (`_sets_intersect`) — CDN/anycast legitimately
  returns different IPs from different PoPs; one shared IP is sufficient.
- `_is_special_ipv4` / `_contains_special_ipv4`: detects RFC 1918, loopback,
  CGNAT, TEST-NET, multicast for DNS sinkhole detection.
- Configuration precedence: CLI arg > env var > `detect_blocking.conf`
  > built-in default.
- Optional logging to file with timestamps, ANSI-stripping, and 10 MB
  rotation; `--quiet` / `-q` flag for cron use.
- `--version` / `-V` and `--help` / `-h` flags.
- `DETECT_BLOCKING_VERSION` constant (`0.1.0`).
- Demo nudge: when `VPN_HOST` is the default `www.example.com`, the script
  prints a hint to set a real endpoint.
- Test harness:
  - `tests/test_smoke.sh` — end-to-end run against the demo target.
  - `tests/test_doh_compromise.sh` — spins up a local fake DoH server
    that mimics sinkhole responses and verifies the script flags
    `DoH path is compromised`.
- GitHub Actions CI: shellcheck + syntax + smoke test on macOS and Ubuntu.

### Notes

- Probe 4 deliberately uses UA-only variation. True JA3 testing requires
  `curl-impersonate` or similar; documented in README.
- Probe 7 OpenVPN silence is reported as inconclusive by default
  (`STRICT_OPENVPN_VERDICT=0`); set `=1` to opt into a hard verdict.
- Probe 6 IKEv2 uses a valid minimal `IKE_SA_INIT` initiator header per
  RFC 7296 §3.1 to avoid the noise of `nc -uz` zero-byte probes.
