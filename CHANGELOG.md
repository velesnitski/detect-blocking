# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.8] - 2026-06-02

### Changed

- **Probe 16 cross-checks egress reputation across multiple sources and
  softens the verdict.** Previously a single source (`ip-api`) decided
  "clean," but its `hosting` flag is demonstrably incomplete — it classifies
  real datacenter IPs (e.g. Microsoft's) as `hosting:false`. Probe 16 now also
  derives the egress **ASN/org** from a pool of free HTTPS sources
  (`ipinfo.io` → `ipwho.is` → `ifconfig.co`, first responder wins, so one
  being rate-limited doesn't blank the check) and applies a hosting-provider
  heuristic. The verdict combines both signals:
  - flagged by ip-api **or** the ASN heuristic → datacenter/proxy;
  - **discrepancy** (ip-api clean, but the ASN is a known host) →
    *"ip-api didn't flag it, but its ASN/org is a known hosting provider →
    treat as datacenter"* (catches the Microsoft-style misses);
  - both clean → *"not flagged by ip-api or by the ASN/org heuristic — looks
    clean (2 sources; still a heuristic, not proof of residential)."*
  Wording now attributes the source instead of claiming a definitive
  "reputation clean." JSON `xray_egress` adds `asn_hosting`. Output stays
  share-safe (booleans / country / class only — never the IP or the org name).

## [0.5.7] - 2026-06-02

### Changed

- **Probe 26 (detectability) now shows a per-component breakdown.** A bare
  "detectability 0/100 (low) — blends in" gave no insight into *what* was
  evaluated. It now prints each input (cover cert / active-probe / TLS parity)
  with its state and point contribution, plus the band legend — so the score
  is explainable at any value:

  ```
  cover cert (15):   authentic, matches serverName              +0
  active-probe (20): relays unauth probes to the real cover     +0
  TLS parity (24):   version+ALPN+cipher match cover            +0
  bands: 0-14 low · 15-39 moderate · 40-69 high · 70-100 critical
  [OK]  detectability 0/100 (low) — every stealth check passed, blends in
  ```

  Scoring is unchanged; this is display-only (the components are already in
  the JSON under `xray_cover` / `xray_active_probe` / `xray_tls_parity`).

## [0.5.6] - 2026-06-02

### Fixed

- **Probe 16 falls back to HTTPS when the HTTP IP-info lookup gets no data.**
  `ip-api.com`'s free tier is HTTP-only (port 80). Many VPN egresses allow only
  443 outbound, and the free tier is rate-limited (45 req/min per source IP),
  so the lookup intermittently returned nothing and probe 16 hard-failed with
  "egress IP-info lookup returned no data through the tunnel" — even though the
  egress was healthy. It now falls back to an HTTPS source (Cloudflare's
  `cdn-cgi/trace`, port 443, already used elsewhere) for at least the egress
  country and reports `partial` with a clear explanation, instead of failing.
  The datacenter/proxy reputation flags still need the HTTP endpoint (or a paid
  HTTPS one via `XRAY_EGRESS_INFO_URL`). Validated against a config where the
  HTTP lookup was forced to fail → "egress geo via HTTPS fallback: country=…".

## [0.5.5] - 2026-06-02

### Fixed

- **Probe 12 neutralizes device-specific log paths so mobile-exported configs
  boot.** A config exported from an iOS / Android client bakes an app-sandbox
  path into `log.access` (e.g.
  `/private/var/mobile/Containers/Shared/AppGroup/…/Xray/logs/access.log`).
  That directory doesn't exist on the test machine, so xray-core fails to
  initialize its access logger and never starts — probe 12 reported
  `xray-bind-failed` and every tunnel-dependent probe (13/14/16/17/22) silently
  skipped, even though the server itself was perfectly healthy. When patching
  the config probe 12 now also resets `.log` to `{ loglevel: "warning" }`
  (dropping the file paths; xray logs to stderr, which the probe already
  captures), so a config pulled straight off a phone tests end-to-end. New
  test `tests/test_log_path_neutralize.sh`. Suite now 16.

## [0.5.4] - 2026-06-02

### Changed

The two edge-case follow-ups from the v0.5.3 audit:

- **Probe 12 reports "no proxy outbound" instead of a misleading network
  error.** A config with an empty (or freedom-only) `outbounds` array used to
  launch xray, get no route, and report "tunnel did not reach Cloudflare" — as
  if the network were at fault. It now pre-checks (via jq) for at least one
  proxy outbound (`vnext` / `servers`) and fails fast with *"config has no
  proxy outbound — nothing to tunnel through"* (status `no-outbound`).

- **`--diff-baseline` notes a version drift.** A baseline saved by an older
  build is missing the probe blocks added since, so those probes show as
  `none -> X` on the first diff after an upgrade. The diff now prints
  *"baseline is from vX (now vY) — probes added since will appear as changes,
  not regressions"* so that isn't misread as a real regression.

## [0.5.3] - 2026-06-02

### Fixed

- **IPv6-literal endpoints no longer mangled.** Found by edge-case testing: a
  `vless://uuid@[2001:db8::1]:443?…` URL parsed the host as `[2001` (the
  `[^:?#/]+` regex stopped at the first colon), and the `${hostport%%:*}`
  split in the URL→JSON synthesizer had the same bug. Both now use
  bracket-aware `[addr]:port` parsing. A bare IPv6 literal as `VPN_HOST` also
  short-circuits DNS the way an IPv4 literal already did (so it's *probed*
  instead of reported "Domain unresolvable" — `nc`/`openssl` accept v6
  directly), and `_target_https_url` brackets v6 hosts so curl URLs are valid
  (`https://[2001:db8::1]/`). A one-line note flags that full v6-literal
  support is best-effort (some probes still assume v4); pass a hostname or
  `--xray-config-json` if a probe misbehaves.

  New test `tests/test_ipv6_literal.sh` (host/port parsing + DNS
  short-circuit, using RFC 3849 documentation addresses). Suite now 15;
  shellcheck clean.

## [0.5.2] - 2026-06-02

### Fixed

- **Probe 25 no longer reports a misleading latency artifact as throughput.**
  When the cover root served just over the old 50 KB minimum, the direct
  fetch's `speed_download` was dominated by connection-setup latency, not
  bandwidth — producing nonsense like "cover 70 KB/s vs baseline 4685 KB/s,
  not throttled" (a 67× gap that looks contradictory because the 70 KB/s isn't
  a real bandwidth figure). The probe is now **tunnel-primary**: the tunnel
  already presents the cover SNI in bulk, so probe 13/14's throughput is the
  reliable cover-SNI throughput and is used first. The direct cover fetch is
  only a fallback when there's no tunnel, and is trusted only at ≥ 1 MB of
  payload (below which `speed_download` is latency, not bandwidth). Result: a
  real, trustworthy number ("the tunnel carries it at N Mbps") instead of a
  confusing small-transfer artifact.

## [0.5.1] - 2026-06-01

### Changed

- **Probe 25 cross-checks the tunnel instead of bailing to "inconclusive".**
  Many covers (API / asset hosts) serve almost nothing at the root, so the
  direct fetch couldn't measure a throttle and the
  probe gave an unhelpful "not enough cover payload — inconclusive". But the
  tunnel itself presents the cover SNI in bulk, so probe 13/14's throughput
  *is* the cover-SNI throughput. Probe 25 now falls back to it: a healthy
  tunnel (≥ ~2 Mbps) → "cover SNI not throttled at this vantage — the tunnel
  carries it at N Mbps (a volumetric throttle would cap it to tens of KB/s)";
  a collapsed tunnel on clean transport → "may be shaped here". It also now
  notes that a region-throttle only shows where it's enforced (run from the
  affected region, not a clean vantage). Still `inconclusive` only when there's
  neither a measurable cover payload nor any tunnel throughput to cross-check.

## [0.5.0] - 2026-06-01

### Added

Two leaps beyond point-in-time probing — **longitudinal** (what changed) and
**synthesis** (one answer from many signals) — plus a probe that closes a real
production loop. All pure-bash (jq/curl/openssl already required), share-safe.

- **Baseline + diff mode (`--save-baseline FILE` / `--diff-baseline FILE`).**
  Turns the suite into a regression detector. `--save-baseline` writes this
  run's share-safe JSON as a healthy reference; `--diff-baseline` runs and
  reports what changed since — cover went fake, egress geo/reputation flipped,
  capacity regressed, a fleet outbound died, detectability climbed, etc. The
  compared signature is built from statuses / geo / booleans / bucketed
  numbers only (so run-to-run jitter doesn't trip it), and a changed
  server/egress IP is reported as a boolean "changed" — never the value.
  `cron` it to catch the moment a node degrades.

- **Probe 26 — detectability score (stealth synthesis).** A censor sees one
  server, not three findings. Folds probes 15 (cover cert), 20 (active-probe)
  and 24 (TLS parity) into a single 0-100 fingerprintability score + band
  (low / moderate / high / critical) for at-a-glance fleet triage. Weighted
  so a self-signed cover (critical) ranks above a wrong-`dest` server (high)
  above a clean relay (low).

- **Probe 25 — cover-SNI region-throttle.** Automates a real incident: the
  cover domain itself being shaped in-region, which the tunnel silently
  inherits ("fast handshake, slow data"). Compares a direct bulk fetch from
  the genuine cover vs a neutral baseline from this vantage; flags a stark
  slowdown. Best-effort — reports `inconclusive` when the cover serves no
  measurable payload (e.g. an API/asset host). Output: KB/s + ratio, no
  domain.

  JSON adds `probes.xray_cover_throttle`, `probes.xray_detectability`. New
  flags `--save-baseline` / `--diff-baseline`. New test
  `tests/test_score_throttle_baseline.sh`. Suite is now 14; shellcheck clean.

## [0.4.0] - 2026-06-01

### Added

Three more Xray probes — all **pure-bash, no new dependency** (just the
`curl` / `openssl` / `ping` already required), and share-safe (ms, booleans
and generic protocol values only — never an endpoint, cover domain, or IP).

- **Probe 22 — bufferbloat / latency-under-load.** Probes 13/14 measure
  bandwidth; this measures the latency the tunnel *adds while saturated* —
  what makes a fast link feel laggy on calls / gaming. Measures warm RTT
  (keep-alive, so the handshake is paid once and excluded) idle vs under a
  bounded saturating download, and reports the inflation + jitter. Bands:
  `<100ms` low / `<400ms` moderate / `≥400ms` heavy bufferbloat. Runs by
  default when the tunnel is up; `--no-bufferbloat` opts out.

- **Probe 23 — path MTU to the server.** A clamped path MTU fragments the
  Reality ClientHello and causes intermittent handshake failures that mimic
  flaky DPI. A DF-bit `ping` sweep finds the largest unfragmented payload and
  reports the path MTU (or "filtered" when ICMP is blocked). Runs by default
  when a config is given; no tunnel needed.

- **Probe 24 — TLS-negotiation parity.** Stealth depth-3: probe 15 checks the
  cover *cert*, 20 the cover *HTTP behaviour*, and 24 the **TLS negotiation**
  — does the server negotiate the same TLS version / ALPN / cipher as the
  genuine cover site? A real relaying Reality server is byte-identical; a fake
  or wrong-`dest` one diverges (e.g. serves `http/1.1` where the real cover
  offers `h2`). Reports per-attribute parity booleans + the generic negotiated
  values.

  JSON adds `probes.xray_bufferbloat`, `probes.xray_mtu`,
  `probes.xray_tls_parity`. New flag `--no-bufferbloat`, new env
  `XRAY_BUFFERBLOAT`. New test `tests/test_bufferbloat_mtu_tlsparity.sh`.
  Suite is now 13; `shellcheck detect_blocking.sh` clean.

## [0.3.1] - 2026-06-01

### Changed

- **Probes 18 (lint) and 19 (clock skew) now run in numeric position** —
  after 17, before 20 — instead of as a pre-flight block before 11. The
  output reads in straight 11→21 order. They remain static/cheap and their
  findings still surface in the consolidated verdict block, so the
  diagnostic value is unchanged; only the print order moved.

## [0.3.0] - 2026-06-01

### Changed

- **Probe 17 rebuilt around an escalating size ladder.** It used to pulse
  only tiny trace requests on a duration timer and lumped "slow timeout" in
  with "killed", which mislabelled healthy high-RTT tunnels as "unstable"
  (e.g. 0/3). It now pulses a byte ladder (`0 262144 1048576 4194304` by
  default) and classifies each pulse by curl exit code — **ok / slow
  (timeout) / killed (reset)**. A reset that appears only on the larger
  pulses is reported as **volumetric kill-shaping** (the censor allows small
  flows, drops large ones) with the byte size that tripped it — a signature
  trace-only pulses can never reveal. Timeouts with no resets are now
  reported as *slow / degraded*, not "killed". Per-pulse budgets are
  handshake-aware and scale with size. New env `XRAY_STABILITY_SIZES`;
  `XRAY_STABILITY_SECONDS` is now an overall wall-clock cap (default 45),
  `XRAY_STABILITY_INTERVAL` a brief inter-pulse pause. JSON `xray_stability`
  gains `pulses_killed`, `pulses_slow`, `kill_at_bytes`, and a `per_pulse[]`
  ladder (existing fields retained).

### Added

Four more Xray probes, completing the suite across reachability, performance,
stealth, integrity, stability — and a new **correctness** dimension. As with
15-17, all output and JSON are share-safe: verdicts, booleans, counts, status
codes and operator tags only — never a secret value, cover domain, or IP.

- **Probe 18 — config pre-flight lint (static, no network).** Validates the
  parsed URL/JSON for common Reality/VLESS misconfigs before the network
  probes run, so a typo surfaces in milliseconds instead of masquerading as
  DPI three screens down. Checks: `flow=xtls-rprx-vision` requires
  `network=tcp`; `security=reality` requires a `publicKey`; `shortId` must be
  hex ≤16 chars; `serverName` must be a domain not a bare IP; uTLS
  `fingerprint` recommended; vless `encryption=none`. Each finding names the
  protocol knob, never the secret. Runs first (pre-flight) when a config is
  present.

- **Probe 19 — clock skew.** Reality authentication is time-windowed, so a
  client clock off by minutes fails the handshake in a way that looks
  identical to a fingerprint block. Compares local time to a server `Date`
  header (GNU + BSD `date` portable) and warns past ±60s. Runs pre-flight.

- **Probe 20 — active-probe resistance.** Probe 15 checks the cover *cert*;
  this checks the cover *behaviour* the way a censor does — sends a real HTTPS
  request to the server with the cover SNI and compares the response to the
  genuine cover site fetched out-of-band. A real Reality server relays unauth
  clients to dest → matching response; a fake one returns no coherent HTTP or
  a mismatch. Reports relay vs genuine HTTP codes + a match boolean.

- **Probe 21 — per-outbound fleet health matrix (auto on multi-outbound).**
  For balancer / multi-outbound JSON configs, tunnel-tests each outbound (its
  own xray spawn) and prints a health table keyed by the operator-defined tag
  — never the address or port. Distinguishes a single dead endpoint from a
  fleet-wide config problem (all outbounds down → "fix the shared knobs").
  **Auto-enables** when the JSON config has >1 proxy outbound; stays silent
  (no header, no work) for single-outbound or URL-form configs. `--no-fleet`
  disables; `--fleet` forces it inside `--watch`/`--from-file` loops (it
  auto-skips there otherwise, since it's N xray spawns).

  JSON schema adds `probes.xray_lint`, `probes.xray_clock`,
  `probes.xray_active_probe`, `probes.xray_fleet`. New flags: `--no-fleet`,
  `--fleet` (force in loops).
  New test `tests/test_lint_clock_active_fleet.sh` (gating, schema, lint flags
  a bad config + passes a clean one, and asserts no secret leaks into
  findings). Suite is now 12, `shellcheck detect_blocking.sh` clean.

  Default behaviour: 11-20 run by default when a config is given (gated by
  available binaries and whether the tunnel comes up); 21 is opt-in. A full
  run with a live tunnel pulls ~60 MB and takes ~30-60s — trim with
  `--no-speedtest` / `--no-egress-check` / `--no-stability` / `--only` /
  `--skip`; `--watch` and `--from-file` loops auto-skip the heavy probes.

## [0.2.10] - 2026-05-29

### Fixed

- **CI shellcheck job (green again).** Probes 15-17 introduced two unused
  variables — `XRAY_EGRESS_DNS_LEAK` and a stray `elapsed_s` local in probe
  17 — which `shellcheck` flags as `SC2034`. The lint job runs with `-e`, so
  those warnings failed CI on v0.2.8/v0.2.9 even though the script ran
  correctly and the local test suite was green. Removed both (the DNS-leak
  boolean was dropped deliberately: a resolver/egress country-divergence
  heuristic false-positives on legitimate setups like an FR egress using
  8.8.8.8, which clashes with the tool's no-false-positives ethos; the
  resolver region is still reported as informational). `shellcheck
  detect_blocking.sh` is clean.

## [0.2.9] - 2026-05-29

### Fixed

- **Probe 16 timed out on high-RTT tunnels at the default `TIMEOUT`.** The
  egress IP-info and DNS lookups used a flat `--max-time "$TIMEOUT"` (5s by
  default), but each opens a fresh tunnel connection that must first clear
  the Reality handshake (~5-6s on a multi-hop path) — so the lookups died
  mid-handshake and reported "egress IP-info lookup returned no data through
  the tunnel" even though the tunnel was healthy. Both lookups now use the
  same handshake-aware budget (`ceil(probe-12 RTT) + TIMEOUT`) that probes
  13/14/17 already derive. Probe 16 was the only tunnel-using probe still on
  the flat timeout.

## [0.2.8] - 2026-05-29

### Added

Three new Xray probes covering the **stealth / integrity / stability**
dimensions that the reachability (11/12) and performance (13/14) probes
miss. All three are designed to be **safe to share**: output and JSON carry
verdicts + booleans + country code only — never the cover domain, the raw
egress IP, or the provider name.

- **Probe 15 — Reality cover authenticity.** Connects plain-TLS
  (unauthenticated, exactly what a GFW/TSPU active prober does) with the
  configured `serverName` and inspects the presented certificate. A genuine
  Reality server relays such clients to the real cover site → a CA-valid
  cert for that name; a **self-signed or mismatched cert means the cover is
  fake and trivially fingerprinted**. Emits `self-signed`,
  `chain-valid`, `CN-matches-serverName` booleans (never the domain).
  Automates the exact fleet-wide misconfiguration found by hand earlier this
  cycle. Runs by default when a Reality config is present.

- **Probe 16 — egress integrity (geo / reputation / DNS).** Through the
  probe-12 tunnel, looks up the egress geo + datacenter/proxy/mobile flags
  so you know if the exit IP is already on the "this is a VPN" lists that
  streaming / payment / banking services block, plus the DNS-resolver region
  seen through the tunnel. Reports country code + flags only — not the IP or
  ASN org. Runs by default; sends the egress IP to a 3rd-party IP-info
  service (`ip-api.com`, configurable via `XRAY_EGRESS_INFO_URL`) — disable
  with `--no-egress-check`.

- **Probe 17 — held-session stability (delayed-RST detection).** Holds the
  tunnel for a real-elapsed window (default 20s) and pulses small requests,
  catching the censor tactic of letting the handshake through then RST-ing
  the proven tunnel seconds later — invisible to the short bursts in 13/14.
  Runs by default; auto-skips inside `--watch` / `--from-file` loops
  (`--stability` forces it there); `--no-stability` disables. Notes that it
  only catches kills within the hold window — raise `XRAY_STABILITY_SECONDS`
  to probe for slower kill-shaping.

  Tunables: `XRAY_EGRESS_CHECK`, `XRAY_EGRESS_INFO_URL`, `XRAY_EGRESS_DNS_URL`,
  `XRAY_STABILITY`, `XRAY_STABILITY_SECONDS`, `XRAY_STABILITY_INTERVAL`.
  JSON schema adds `probes.xray_cover`, `probes.xray_egress`,
  `probes.xray_stability`.

  New test: `tests/test_cover_egress_stability.sh` (gating + schema +
  an assertion that no domain/IP leaks into the 15/16 JSON). Suite is now 11.

### Fixed

- **Recommendation block no longer prints an empty header.** Recommendations
  are now buffered and the `Recommendation:` heading is emitted only when at
  least one verdict maps to advice. Added mappings for the new
  cover/egress/stability verdicts and for the v0.2.6 timeout/reset wording.

## [0.2.7] - 2026-05-29

### Added

- **Probe 14 — multi-stream / multi-endpoint capacity estimate.** Probe 13
  is a single-stream shaping *floor* detector; on a high-RTT tunnel a single
  TCP stream is window-limited and under-reports real bandwidth by an order
  of magnitude (e.g. ~10 Mbps single-stream where the link actually carries
  100+ Mbps). Probe 14 runs N parallel streams (default 4, like a real
  speedtest) against several public CDN backends (Cloudflare, Hetzner, OVH
  by default) through the probe-12 SOCKS tunnel and reports the **best
  aggregate** as the usable-bandwidth estimate — defeating both single-stream
  BDP limits and one slow path skewing the result.

  Runs **by default** whenever probe 12 brings up a tunnel. Opt out with
  `--no-speedtest` (or `XRAY_SPEEDTEST=0`). Auto-skips inside `--watch` /
  `--from-file` loops (so monitoring doesn't pull tens of MB per iteration);
  `--speedtest` forces it even there.

  Per-stream curl budget is derived from probe 12's measured handshake RTT
  plus a download window, so streams clear the Reality handshake before the
  download window opens — a fixed short timeout would kill every stream
  mid-handshake on a high-RTT tunnel. Total download is bounded
  (`XRAY_SPEEDTEST_MAX_BYTES`, default ~50 MB); with a small budget on a fast
  link the streams finish inside TCP slow-start, so the result is reported as
  a **floor** with a hint to raise the budget for a fuller reading.

  Tunables: `XRAY_SPEEDTEST_STREAMS` (4), `XRAY_SPEEDTEST_MAX_BYTES`
  (52428800), `XRAY_SPEEDTEST_SECONDS` (5, the download window after
  handshake), `XRAY_SPEEDTEST_URLS` (space-separated `name|url|mode` triples;
  `mode=cf` appends `?bytes=N`, `mode=range` caps bytes via an HTTP Range
  header). JSON schema adds `probes.xray_speedtest { status, streams,
  best_endpoint, best_bytes_per_second, best_mbps, per_endpoint[] }`.

  New test: `tests/test_speedtest.sh`. Full suite is now 11 tests.

### Fixed

- **URL-synthesized config no longer creates an orphan tempfile.** The
  synthesizer wrote a `mktemp` base *plus* a `.json` sibling; the synth file
  is only ever read by `jq` (probe 12 writes its own patched `.json` that
  xray-core loads), so the extension was unnecessary. Now a single temp file
  is created and removed — eliminating an intermittent "tempfile leaked"
  flake in `tests/test_xray_url_synth.sh`. The test's leak check is now
  delta-based (ignores unrelated pre-existing files).

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
