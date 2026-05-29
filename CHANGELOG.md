# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.6] - 2026-05-29

### Added

- **Probes 12 + 13 now run from a `--xray-config URL` share link.**
  Previously the full-config tunnel probe (12) and throughput probe (13)
  required a hand-written `--xray-config-json FILE`. The script now
  synthesizes a minimal xray-core config (one proxy outbound + freedom
  direct, single socks inbound) directly from a `vless://` or `trojan://`
  share link, so a single `--xray-config URL` exercises probes 11, 12 and
  13 together. Supports reality / tls security and tcp / ws / grpc
  transports; reads `type`, `security`, `sni`, `fp`, `pbk`, `sid`, `spx`,
  `flow`, `alpn`, `path`, `host`, `serviceName`, `headerType`,
  `encryption` from the query string. The synthesized config holds live
  credentials and is written 0600, then removed by the EXIT trap.
  `vmess://` (base64 blob), `ss://`, `hysteria*` and `tuic://` are not
  synthesized — pass `--xray-config-json` for those.

- **Slow-handshake auto-retry for probes 11 and 12.** High-RTT / multi-hop
  tunnels (e.g. a RU-ingress → EU-egress chain) routinely need 5-8s to
  complete the Reality handshake, which exceeded the 5s default budget and
  produced a confident-but-wrong "handshake fails — protocol-fingerprint
  DPI or config error" verdict. On a *timeout-class* failure the probe now
  retries exactly once at 4× the budget; on success it reports "slow
  handshake, not blocked" and hints the `TIMEOUT=N` needed to skip the
  first-attempt timeout.

### Changed

- **Verdicts distinguish timeout from active rejection.** A new shared
  classifier (`_classify_tunnel_failure`) labels a failed tunnel attempt as
  `timeout` (Go `context deadline exceeded` / `i/o timeout` /
  `Client.Timeout`; curl exit 28) vs `reset` (RST / closed pipe / refused /
  SSL error; curl 35/52/56). A timeout that survives the 4× retry now reads
  "slow or throttled tunnel egress, not a fingerprint block — raise
  TIMEOUT", instead of implying DPI. Active resets keep the
  protocol-fingerprint-DPI / config-drift verdict. The retry no longer
  gates on probe 2 (a timeout while "awaiting headers" already proves the
  connection was established), so it fires correctly under `--only xray`.

- **JSON schema additions.** `probes.xray_protocol` and
  `probes.xray_full_config` each gain `failure_kind` (timeout | reset |
  other | null) and `slow_handshake_retry` (bool). `xray_full_config` also
  gains `synthesized_from_url` (bool); when true, `config_path` is null
  (the temp path is never emitted).

- New tests: `tests/test_xray_url_synth.sh` (URL synthesis + schema +
  tempfile cleanup, using an RFC 5737 TEST-NET host). Full suite is now 9
  tests, all passing on macOS + Ubuntu CI.

## [0.2.5] - 2026-05-29

### Added

- **Probe 13 — data-plane throughput through the Reality tunnel.**
  Probe 12 confirms the handshake succeeds but says nothing about whether
  the tunnel can move bytes once it's up. Cover-SNI traffic shaping is
  the failure mode this misses: handshake completes cleanly (censor
  permits it — fingerprint is normal), TCP ping is fine, but the moment
  payload starts flowing a shaper limits the stream to a few KB/s. The
  user-visible symptom is "connects but nothing loads."

  Probe 13 reuses the SOCKS inbound brought up by probe 12 and downloads
  10 MB from Cloudflare's public speed-test backend
  (`speed.cloudflare.com/__down?bytes=N`) through the tunnel. Measured
  throughput is banded against thresholds tuned for known regional
  shaping signatures:

  - `≥ 250 KB/s` → healthy
  - `< 250 KB/s` → degraded (partial shaping or cross-region congestion)
  - `< 50 KB/s`  → severely throttled (classic cover-SNI shaping)
  - `< 1 KB/s`   → tunnel collapsed post-handshake (mid-stream RST / MTU clamp)

  The severe-throttle verdict spells out the mitigation: change the
  Reality cover destination on **both** server (`dest` + `serverNames`)
  and client (`serverName`) to a host that isn't shaped in the affected
  region — and verify out-of-band before deploying.

  Tunable via env vars: `XRAY_THROUGHPUT_TARGET_BYTES`,
  `XRAY_THROUGHPUT_TIMEOUT`, `XRAY_THROUGHPUT_URL`. JSON schema adds
  `probes.xray_throughput { status, bytes_per_second, bytes_received,
  seconds, target_bytes }`. Status of `skipped` is emitted when probe 12
  didn't bring up a tunnel — preserving the "did we test this layer?"
  branch for monitoring stacks.

  New tests: `tests/test_throughput.sh` exercises the skip path and JSON
  schema invariants; full suite is now 8 tests, all passing on macOS +
  Ubuntu CI.

## [0.2.4] - 2026-05-29

### Fixed

- **Probe 12: `.json` extension on patched-config tempfile.**
  `xray-core` determines config format from filename extension; without
  `.json` it logs `Failed to get format` and exits before binding the
  SOCKS inbound. The script now renames the `mktemp` output to append
  `.json` before launching `xray run`.
- **Probe 12: auto-derive `VPN_HOST` + `VPN_PORT_TCP` from `--xray-config-json`.**
  Previously only `--xray-config URL` triggered the auto-derive; with
  `--xray-config-json FILE` the diagnostic stayed on the `www.example.com`
  demo default for the host AND `443` for the port. The script now walks
  the JSON outbounds (vless / vmess / trojan / shadowsocks) for the first
  matching entry and uses both its destination address AND port. Probes
  0-10 align with the full-config probe (or with the first outbound in a
  load-balanced fleet, which is still the intended diagnostic baseline).
  Without the port half of this fix, probe 2 in a non-standard-port fleet
  reported a false "IP route blocked entirely" verdict that drowned out
  the real probe-12 finding.
- **Probe 12: portable `curl --socks5-hostname` instead of `--socks5h`.**
  The short form `--socks5h` needs curl ≥ 7.21.7 (2011) and is missing
  from some bundled-with-macOS curl builds; the long form has been
  supported since 7.18.0 (2008) and works everywhere.

## [0.2.3] - 2026-05-29

### Fixed

- **Auto-derive now picks up port from `--xray-config` URL.** Previously only
  the host was extracted, leaving `VPN_PORT_TCP` on its 443 default. That
  produced false "TCP unreachable" on probes 2–5 when the URL pointed at
  a non-standard port — a common pattern for Reality deployments that
  randomise ports across a load-balanced fleet. The transport probes now
  align with the actual URL destination, surfacing real protocol-layer
  findings instead of being drowned by a phantom TCP failure.

  Real-world payoff: this fix is what made it possible to surface a
  fleet-wide Reality `serverName` mismatch on the operator's first run,
  by aligning the transport-layer probes with the actual destination
  rather than the 443 default.

### Gitignore

- Added `.xray-*.json`, `.xray-*-cfg.json`, `xray-test-*.json` patterns
  so ad-hoc local test configs never accidentally end up in commits.

## [0.2.2] - 2026-05-29

### Added

- **`--xray-config-json FILE` full-config probe (probe 12).** Where probe
  11 delegates to `xray-knife` with a share-link (URL form is **lossy** —
  chained outbounds, `dialerProxy: fragment`, `noises`, custom routing don't
  fit), probe 12 spawns a sandboxed `xray run` against the user's actual
  `config.json`, polls the SOCKS inbound, and tests through it via
  `curl --socks5h … https://cloudflare.com/cdn-cgi/trace`.
  - Patches inbound port to a random free port in the dynamic range
    (49152–65534) via `jq`, so the test doesn't collide with a running
    client on 10808/10809.
  - Cross-references with probe 11: when URL form fails but JSON form
    succeeds, emits `Fragment / chained-outbound layer is the bypass` —
    pinpoints what's lost in the share-link round-trip.
  - Cross-references with probes 3 / 5 / 1: emits `Xray full-config
    bypasses local DPI/DNS-MITM despite environment signals` when the
    tunnel works despite TLS-level DPI signals.
  - Graceful degradation on missing `xray` binary, missing `jq`, missing
    config file, or unbindable port — each emits a distinct status in the
    JSON (`xray-missing` / `jq-missing` / `config-missing` /
    `config-malformed` / `no-port` / `xray-bind-failed` / `ok` / `failed`).
  - EXIT trap reliably kills the background `xray` process and removes the
    patched-config tempfile, even on Ctrl-C mid-probe.
  - New probe name `xrayjson` for `--only`/`--skip` plumbing.
  - JSON output: `probes.xray_full_config` block with `status`,
    `config_path`, `socks_port_used`, `egress_ip`, `egress_location`
    (Cloudflare colo), `rtt_ms`.
  - New `tests/test_xrayjson.sh` (CI on both platforms) asserts
    graceful-degradation paths.

## [0.2.1] - 2026-05-28

### Fixed

- **Bare IPv4 targets** — `_resolve_a_records` short-circuits on hostless
  IPs like `203.0.113.10` instead of running `dig` and failing with
  *Domain unresolvable*.
- **xray-knife v10 API compatibility** — top-level `xray-knife http` is
  detected first, legacy `xray-knife net http` falls back. Drops the
  v10-incompatible `-m 1` flag.
- **xray-knife failure diagnostic** — first error line from the delegated
  tool (matching ❌ / closed pipe / EOF / reset by peer / refused / …) is
  surfaced as `xray-knife says: <line>`.
- **`--xray-config` whitespace strip + scheme validation** — terminal
  paste-wrap (embedded newlines) is stripped before any processing; the
  script `die`s early on unrecognised URI schemes.

### Added

- **Auto-derive `VPN_HOST` from `--xray-config`** — when no positional host
  is given, the host is extracted from `vless://` / `trojan://` / `ss://`
  / `hysteria://` / `hysteria2://` / `tuic://` URLs so all 11 probes align
  with the protocol probe.
- **3 new functional tests** (`tests/test_watch.sh`, `tests/test_from_file.sh`,
  `tests/test_pcap.sh`) wired into CI on macOS + Ubuntu. `test_pcap.sh` is
  graceful-dual-mode: passes whether or not the runner has `cap_net_raw`.

## [0.2.0] - 2026-05-28

### Added

- **`--xray-config URL` end-to-end Xray-protocol test** via delegation to
  `xray-knife` (optional dep, auto-discovered in PATH). Honest authenticated
  alternative to native blind probing — Reality / Shadowsocks-2022 /
  Hysteria2 / VLESS-with-fallback are by-design unprobeable from outside
  without credentials. Operator supplies their `vless://…`, `vmess://…`,
  `trojan://…`, `ss://…`, `hysteria2://…` URL and the script runs a real
  end-to-end test through xray-knife, reporting RTT, egress IP/location,
  and cross-referencing with the other probe results.
  Credentials in the URL are auto-masked (`<creds>` placeholder) for human
  + JSON output. New verdicts:
  `Xray protocol bypasses local DPI/DNS-MITM despite environment signals`
  (positive case), and
  `Xray-protocol handshake fails while plain TLS to the same host succeeds`
  → protocol-fingerprint DPI or config drift.
  JSON: `probes.xray_protocol` block with status / rtt_ms / egress info.
  New probe name: `xray` (for `--only`/`--skip`).
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
