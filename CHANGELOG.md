# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.3.1] - 2026-07-07

### Fixed
- **Fleet matrix (probe 21) mislabeled a dialerProxy config.** It counted a `dialerProxy`/`proxySettings` **helper** (e.g. a local ByeDPI socks) as a fleet endpoint, and reported the real proxy as "down" — because isolating it via `--outbound` dropped the dangling dialer — producing a false *"1 of N outbounds pass"* that contradicted probe 12 (which proved the tunnel works). Two-part fix, extended from v1.1.0's dialerProxy awareness to probe 21:
  - **Fleet detection excludes dialerProxy helpers** (`_fleet_tags`, unit-tested) — they're chain plumbing, not endpoints. A single real endpoint + a dialer helper is now correctly *not* a fleet (the matrix stays quiet; probe 12 already tested it).
  - **`--outbound` isolation now keeps the dialer chain** (transitively) — narrowing to a chained outbound includes its `dialerProxy`/`proxySettings` targets, so the standalone test reflects the real chain instead of failing on a dangling reference. No-op for non-chained configs (byte-identical extraction).

## [1.3.0] - 2026-07-07

### Added
- **`--panel-probe [IP]` — audit an origin IP for an exposed x-ui/3x-ui panel.** Host-exposure only `nc`-scans the resolved IP, which on a CDN-fronted config is the CDN edge — so it can't see the origin's panel. `--panel-probe` actively fetches the known panel ports+paths (54321, 2053/`/panel/`, 8080/`/panel/`/`/dashboard/`, 8081, 9000, 2083/2087/8443) on a **backend you name** and classifies each: **x-ui/3x-ui login** (brand marker / login form) vs **CDN edge** (server=cloudflare/akamai/…) vs plain **web** vs **closed**. GETs only, share-safe. Pure `_panel_classify` (unit-tested). JSON: `.probes.panel_probe.{status,panel_found}`.

### Changed
- **Host-exposure no longer false-positives on CDN-fronted configs.** When the resolved IP is a CDN edge (Cloudflare/Akamai/Fastly/…), the "proxy-panel port exposed" finding is **downgraded**: a CDN serves many alt-ports by design (Cloudflare: 8080/2053/2087/8443), so those aren't the origin's panel. The scary takeover verdict is suppressed and replaced with a pointer to `--panel-probe <origin-ip>` to audit the real backend. `_is_cdn_ip` reuses the probe-26 org-keyword detection. JSON: `.probes.host_exposure.cdn_edge`.

## [1.2.1] - 2026-07-07

### Fixed
- **Recommendation engine: two verdict→rec mappings were misfiring.**
  - The **clean-egress** recommendation never fired — its glob matched `"Egress IP is on datacenter/proxy"` but the verdict had been reworded to `"Egress is on datacenter/proxy…"`. A datacenter-egress finding (streaming/banking will block) produced no one-line rec. Glob realigned to the verdict text.
  - The probe-27 **ECH / SNI-privacy** advisory fell through to the generic `*"SNI"*` rec (*"try Reality / domain fronting"*), which is wrong for a config that is **already** CDN-fronted. It now maps to an ECH-specific recommendation (enable client ECH; the chained dialerProxy desync also fragments the ClientHello; "switch to Reality" is a different architecture, not an upgrade).

## [1.2.0] - 2026-07-07

### Added
- **`--stub-dialer` — end-to-end test a ByeDPI/dialerProxy config with zero setup.** When a config dials through a **local** desync `dialerProxy` (ByeDPI / ciadpi / zapret / GoodbyeDPI) that isn't running, this spawns a throwaway **plain SOCKS5** on that port (a minimal, dependency-free perl relay — perl is already a soft-dep) so the tunnel probes (12/13/14/16/17…) can run. Idempotent (reuses an existing listener — real ByeDPI or a prior stub), loopback-only, cleaned up on exit, and self-terminates if orphaned. **It applies no desync**, so it validates the config's **carriage + egress/QoE**, not desync efficacy (that needs an in-region DPI vantage) — the tool says so loudly. No-op with `--no-tunnel`, on a chain-less config, or a non-local dialer.

### Changed
- **Required-value flags now reject a missing value.** `--xray-config-json --stub-dialer <path>` used to swallow the next flag as the "path" and produce a confusing garbage run (`config file not readable: --stub-dialer`). `--xray-config-json` / `--xray-config` now error with the correct order when their value is missing or looks like a flag.

## [1.1.0] - 2026-07-07

### Added
- **dialerProxy / client-side desync chain support (ByeDPI / ciadpi / zapret / GoodbyeDPI).** When an outbound's `sockopt.dialerProxy` points at another outbound, the tool recognizes the chain, and when the target is a **local** socks/http proxy it reports it as a client-side desync layer (probe 18): the whole tunnel TCP+TLS is dialed through it, so it fragments/disorders the ClientHello to defeat SNI/TLS DPI. `tcpKeepAliveInterval` is reported (benign); a broken chain (dialerProxy names a non-existent tag) is a lint error. JSON: `.probes.xray_lint.dialer_proxy` + `desync_chain`.

### Changed
- **Tunnel-failure reading is now chain-aware.** A `dialerProxy → local proxy` config that fails the tunnel test (probe 12 / fleet) no longer misreads as a shared-config fault (`serverName/keys/flow`) — it names the likely cause: the local desync proxy isn't running (start it and re-test). This removes the "0/N outbounds — fleet-wide failure" false alarm on a ByeDPI config.
- **SNI-privacy is chain-aware (probe 27).** With a desync dialerProxy present, the cleartext-SNI advisory notes the chain typically fragments the ClientHello (the split-ClientHello evasion), partially hiding the SNI — with ECH still called out as the unconditional fix.

## [1.0.0] - 2026-07-03

First stable release. detect-blocking has been dogfooded against real infrastructure across 40+ iterations with a 51-test suite; the interface is now considered stable and versioned under [Semantic Versioning](https://semver.org).

### Stability contract
- **Stable** — a breaking change here requires a major (2.0.0) bump:
  - CLI flag names and their argument semantics; process exit codes.
  - The top-level `--json` object shape (`schema_version` / `version` / `timestamp` / `target` / `probes` / `verdicts`), signalled by `schema_version` (now `1`; bumped only on a breaking JSON change).
  - The **share-safety guarantee**: default and `--json` output never carry raw endpoint IPs, cover domains, or secrets — only booleans / country / codes / bucketed numbers. Offending values appear solely under `--reveal`, which is never logged and never emitted.
- **Not a contract** — may change in any minor/patch release:
  - Exact detectability **score** values and bands, and verdict / recommendation wording (heuristics, tuned continuously).
  - Which probes run by default, and probe numbering.
  - **Additive** JSON fields under existing objects — consumers must ignore unknown keys. This is how new signals (e.g. `xray_sni_privacy`, `xray_lint.vless_encryption`) ship without a major bump.
  - Human-readable console formatting.

### Notes
- No functional change from 0.42.0 — this release declares the interface stable and documents the contract. The pre-1.0 flag/knob audit found the surface already consistent (kebab-case; `--sub-*` / `--compare-*` / `--no-*` families; paired toggles) and the JSON already carrying `schema_version`, so nothing was renamed.

## [0.42.0] - 2026-07-03

### Added
- **VLESS Encryption awareness (Xray 2025+ post-quantum layer).** Xray added a native VLESS Encryption layer — `encryption: "mlkem768x25519plus.<method>.<session>[+padding][+delay]"` (ML-KEM-768 + X25519). The tool now recognizes it and reads the **method**: `native`/`xorpub` (structured) vs `random` (full-random, VMess/SS-like). Probe 18 reports the method + whether traffic padding is configured (padding blunts packet-length/timing analysis). New pure classifier `_vless_enc_method` (unit-tested). JSON: `.probes.xray_lint.vless_encryption` + `vless_encryption_padding`.
- **VLESS-without-flow deprecation lint (probe 18).** Xray-core is migrating VLESS-without-flow → VLESS-with-flow (XTLS/Xray-core #5568). Flow-less VLESS now warns with the migration path. JSON: `.probes.xray_lint.vless_flow_deprecated`.

### Changed
- **FET check is now VLESS-Encryption-method-aware (correctness).** The GFW fully-encrypted-traffic check (probe 18) no longer assumes `encryption=none`: on raw TCP with no TLS, `random` is still exposed (kept), while `native`/`xorpub` reshape the wire so a block is **not asserted** (method-dependent — report, don't over-claim).
- **Vision now recognized on non-raw transports when VLESS Encryption is present (correctness).** VLESS Encryption lifts XTLS Vision's raw-TCP restriction ("no transport restrictions"), so the frontier `VLESSENC + XHTTP + xtls-rprx-vision` config is read as vision-protected in probe 26 — not the old "vision N/A on a non-raw transport (tradeoff)". The probe-18 `flow=… requires raw TCP → handshake will fail` lint is likewise suppressed when VLESS Encryption is configured.

### Fixed
- **False-positive lint removed.** Probe 18 used to emit `vless requires encryption=none, got encryption=<x>` — wrong for a modern `encryption=mlkem768x25519plus.*` (valid VLESS Encryption). Now recognized as valid; only a genuinely unrecognized string is flagged as a likely typo.

## [0.41.0] - 2026-07-03

### Added
- **SNI privacy / ECH posture (advisory).** A new stealth axis, orthogonal to the probe-26 detectability score: the score rates the *quality* of the cleartext cover SNI but treats its *visibility* as fixed — this asks whether that SNI can be **hidden at all** (Encrypted ClientHello) and whether the transport allows it. Transport-aware: **Reality** relies on a cleartext cover *by design* (ECH N/A → the cover-quality score is the lever), whereas a **TLS-over-CDN** transport (ws/gRPC/xHTTP behind a front) *can* use ECH — so the probe looks up whether the front publishes an ECH config in DNS (`HTTPS`/SVCB `ech=` param via `dig`, with a DoH-JSON fallback for old resolvers) and classifies the posture `reality` / `ech-available-unused` / `ech-unpublished` / `ech-unknown`. `ech-available-unused` (front offers ECH but the client still leaks the SNI) is the actionable tell — the highest-leverage SNI fix for a CDN-fronted transport. Runs after probe 26 as an **unnumbered advisory** (26 stays the last *scored* probe) and is **never folded into the score** (ECH is a censor-/time-dependent tradeoff, like the uTLS fp). Share-safe; emitted in `--json` under `.probes.xray_sni_privacy`. The pure classifier `_sni_privacy_advisory` is unit-tested (reality/ECH matrix), plus an offline integration check that the advisory doesn't displace probe 26.

## [0.40.1] - 2026-06-26

### Changed
- **`--sub-test all --yt-test` is much faster.** The per-node tunnel pass now also passes `--no-stability --no-bufferbloat` (on top of `--no-speedtest`), dropping the slow data-plane QoE probes (14/17/22) that dominated wall time — one flaky node's held-session stability pulses alone took ~100 s — and that feed nothing into the fleet table (they don't move the detectability score). Detectability stays tunnel-aware via the cover/active-probe/TLS-parity/egress probes. Verified concurrency-safe: each per-node tunnel binds a random ephemeral SOCKS port (`_find_free_port`), so the default batch of 3 doesn't collide.

## [0.40.0] - 2026-06-26

### Added
- **`--sub-test all --yt-test` — per-node YouTube column in the fleet walk.** The default `--sub-test all` stays a fast, no-tunnel fingerprint scan. Adding `--yt-test` switches it to a per-node tunnel pass: each config spins a short-lived xray tunnel (`--xray-only --no-speedtest`, so transport probes 0–10 and the heavy multi-stream pull are skipped) and runs the YouTube fan-out (6 concurrent connections through the tunnel), surfacing a **YouTube** column — `succeeded/requested` + verdict (`ok` / `slow`=throttled / `capped` / `fail`). Because it spawns one xray per node it's much slower than the fingerprint walk, so it's opt-in and the concurrency batch defaults to 3 (vs 8) to avoid xray thrash; override with `--sub-jobs N`. Detectability in this mode is tunnel-aware (includes egress/stability), not just the direct fingerprint. Verified live against a 5-node subscription.

### CI
- **Hardened the DoH-compromise test fixture against a cold-runner startup race** (no tool change). On a slow macOS CI runner `python3`'s `http.server` could take longer to bind than the test's 2 s readiness budget, so the tool queried a not-yet-listening fixture, got an empty DoH answer, and the run failed with `expected canary mismatch line` (flaky — the same commit passed on the other runner). Fixes: the fixture now binds **before** announcing "listening"; the test polls readiness with a generous budget and **skips** (not fails) if the fixture never comes up; and it retries once, keying the answered/not-answered decision on the `canary returned` line (the later `DoH returned no A records` warning is expected success behaviour — the tool discards the poisoned answer). The test now only FAILs on a genuine regression (fixture answered but the MITM wasn't flagged).

## [0.39.2] - 2026-06-26

### Fixed
- **YouTube fan-out progress no longer leaks cursor escapes into non-terminal output.** The live `probing… k/N done (Ns)` counter emitted `\r` + `\033[K` whenever it wasn't under `--json`, so redirecting/piping the run (to a file, `tee`, or a CI log) showed literal `…done (2s) ␛[K [OK]` bytes. The progress loop is now additionally gated on `[ -t 2 ]` (stderr is an interactive terminal); when output isn't a TTY the counter is skipped entirely and the verdict prints clean. The connections + bounded `wait` are unchanged. Verified end-to-end against a live tunnel: 6/6 clean, zero escape/CR artifacts in captured output.

## [0.39.1] - 2026-06-26

### Fixed

- **Root-cause fix for the `--yt-test` / `--conn-test` hang.** Both probes launched
  their curls with `&` and then called a **bare `wait`** — which, in the main shell,
  blocks on *every* background job including the long-lived **xray-core** process that
  probe 12 starts. So whenever the tunnel was up (probe 12 ok), the YouTube probe hung
  **forever** on xray-core (the v0.39.0 maxt cap / single-probe / progress bounded the
  *curls* but not this `wait`). Now each probe collects its curl PIDs and waits only on
  those (`wait $pids`), so it returns as soon as its own connections finish. Verified a
  long-lived background job no longer blocks the wait.

## [0.39.0] - 2026-06-26

### Changed

- **`--yt-test` now runs independently of probe 12's verdict.** It reuses probe 12's
  tunnel **inbound** (the xray process + SOCKS port, which probe 12 leaves running on
  failure) but no longer skips just because probe 12's *Cloudflare* reachability check
  failed. So a Cloudflare-specific block no longer suppresses the YouTube measurement,
  and a **divergence becomes a signal**: YouTube works but Cloudflare doesn't → the
  tunnel is alive, Cloudflare is blocked at the egress (re-check probe 12 before
  declaring the config broken); both fail → the tunnel itself isn't passing traffic
  (Reality auth/handshake — verify UUID/keys/flow). It only skips now if there's
  genuinely no tunnel inbound up.

### Fixed

- **`--yt-test` could hang (and get killed) on a broken/slow tunnel.** Three fixes:
  (1) per-connection budget is **capped at 10s** (it was inheriting probe 12's
  slow-handshake-retry RTT, up to ~20s); (2) when probe 12 has **already failed**, the
  tunnel is suspect, so it now does a **single quick reachability probe (≤6s)** instead
  of a doomed 6-way fan-out — enough to tell "Cloudflare blocked" from "dead tunnel";
  the full fan-out runs only when the tunnel works or `--yt-test` is explicitly passed;
  (3) a **live progress line** (`probing… k/N done (Ns)`, terminal-only) so a slow probe
  shows a ticking counter instead of looking frozen.

## [0.38.0] - 2026-06-26

### Changed

- **`--yt-test` (YouTube fan-out) is now ON BY DEFAULT for tunnel runs** with a light
  **N=6** (was opt-in, N=16). Any deep run where the tunnel comes up (a single
  Reality/VLESS config, or `--sub-test N`) now includes the YouTube reachability check
  automatically. It **auto-skips inside `--watch` / `--from-file` loops** to avoid
  repeated YouTube traffic; explicit `--yt-test [N]` forces a thorough run (default 16,
  runs even in loops); **`--no-yt-test`** disables it. Still a tunnel probe — never the
  `--sub-test all` fleet walk — and skips gracefully with no tunnel. When it skips
  (no tunnel up, or a watch/batch loop) it now prints a **visible** header + reason
  instead of vanishing, so it's clearly "ran but skipped (why)".
- **Bug fix (found while wiring the above):** `--no-yt-test` set `YT_TEST_N=""` but the
  default `${YT_TEST_N:-6}` (applied after arg-parsing) re-enabled it because `:-`
  treats empty as unset. Switched to `${YT_TEST_N-6}` so an explicitly-empty value
  survives.

## [0.37.0] - 2026-06-26

### Added

- **`--yt-test [N]` — YouTube reachability under connection fan-out.** Opt-in
  **tunnel** probe: opens N concurrent connections (default 16) *through the tunnel*
  to real YouTube-infra hosts (`www.youtube.com`, `youtubei.googleapis.com`,
  `i.ytimg.com`, `yt3.ggpht.com`; override with `XRAY_YT_HOSTS`) and reports how many
  complete + the TTFB spread. This is the parallel-origin fan-out real playback
  generates, so it catches the "VPN connects but YouTube buffers / won't load" case a
  single-stream throughput test misses — and **empirically** confirms what probe 16
  only infers (googlevideo throttles datacenter egress IPs). Same
  clean/capped/degraded/all-failed buckets as `--conn-test` (`_classify_conn_limit`).
  Needs the tunnel up (probe 12) → deep-test only (`--sub-test N` / a single config),
  never the fleet walk; skips gracefully with no tunnel. JSON: `probes.youtube_reach`.

## [0.36.0] - 2026-06-26

### Added

- **`--conn-test [N]` — server connection-limit probe.** Opt-in. Opens **N
  simultaneous TLS handshakes** (default 16, capped at 128) to the server and
  reports how many complete plus the handshake-time spread, classifying the result
  as **clean** (handled N concurrent, stable), **capped** (only X/N completed — a
  concurrent-connection cap / rate-limit; clients behind CGNAT or with many devices
  will see failures), **degraded** (all completed but handshake time ballooned under
  load), or **all-failed** (TCP open but every handshake dropped). It's a *server
  robustness / UX* signal, not a censorship one. Direct probe (bounded per-connection
  by `curl --max-time`, since openssl can't be timed out on macOS), so it works
  standalone and inside a `--sub-test N` deep dive; it never auto-runs (not part of
  the fleet walk). JSON: `probes.conn_limit`. Pure classifier `_classify_conn_limit`
  + `tests/test_conn_limit.sh`.

## [0.35.0] - 2026-06-18

### Added

- **`bottom line` synthesis below the fleet grid** — a short, fully computed
  summary (every number derived from the measured signals): **uniformity** (how
  many deployment templates, and the dominant one's coverage — a template fix
  touches most of the fleet at once), **single-probe identifiability** (how many
  nodes serve a self-signed/mismatched cover cert, i.e. one unauthenticated TLS
  connection flags the IP), and **residual exposure after the #1 fix** (the signals
  relaying the cover does *not* clear — `exposed`, `cover-obscure`, `non443`, … —
  so the plan's payoff and limits are explicit). uTLS-rare / mux are excluded from
  the residual (tradeoffs, not scored).

## [0.34.0] - 2026-06-18

### Changed

- **Per-node signals are now a `signal matrix` instead of comma-joined profile
  lines** (which still wrapped, since the signal list is long). The matrix is a
  systematic grid: signals are **fixed columns** (2-char codes), rows are nodes
  **grouped by identical signal-set** (range-compressed indices, most common first),
  cells are `x`/`.`, and a `total` footer row gives the per-signal node count (this
  folds in the old "shared signals" tally). Result: it never wraps, you can scan a
  column to see which profiles share a signal, and any node that differs (e.g. a
  `cover-mismatch` instead of `self-signed`, or an extra `non443`) stands out as its
  own row. Backed by a new pure helper `_signal_matrix` + `tests/test_signal_matrix.sh`.

## [0.33.0] - 2026-06-18

### Changed

- **Fleet table no longer wraps — per-node `tells` moved out of the table into a
  deduplicated `node profiles` section.** The `tells` column was a ~100-char string
  that was *identical across same-template nodes* and overran the line (the table
  wrapped and repeated the same signals 20+ times). The per-row table is now a
  compact fixed-width line (`# · remarks · server:port · cover · detect · fp`) that
  fits any reasonable terminal, and the signals are shown **once per distinct
  profile** — nodes are grouped by identical *fingerprint + band + signals*, listed
  with range-compressed node indices, most common first. No information lost; a
  uniform fleet collapses to a few lines and any node that differs stands out. The
  old "deployment templates" count section is folded into this (profiles already
  show the fingerprint per group).

## [0.32.3] - 2026-06-18

### Added

- **Scheduled run-log cleanup** (`.github/workflows/cleanup-runs.yml`): deletes
  `sub-run` workflow runs older than 24h (configurable via `max_age_hours` /
  `workflow`, `ALL` to prune everything), every 6h + on demand. Keeps dispatch-input
  metadata from lingering in the public Actions history. Needs Actions write
  permission (Settings → Actions → General → Workflow permissions). Note: this
  limits lingering exposure but is **not** leak prevention — a public run is visible
  the instant it starts, so a pasted tokened URL must still be rotated.

### Reverted

- The v0.32.2 guard that blocked paste-in inputs on a public repo is removed (the
  paste-in convenience is kept); the redacted output + the input warnings remain,
  and the new cleanup workflow handles stale runs instead.

## [0.32.2] - 2026-06-18

### Changed (security)

- **`sub-run.yml` now refuses paste-in inputs on a public repo.** `workflow_dispatch`
  input values are recorded in the run's metadata and are world-readable, so a
  `sub_url` / `sub_json` pasted into the form on a public repo leaks (a tokened URL
  ends up public). The workflow now aborts with a clear error when the repo is public
  and either input is non-empty, forcing the masked `SUB_URL` secret with a blank
  form. Private repos/forks are unaffected (they can still paste + use `redact:false`).

## [0.32.1] - 2026-06-18

### Fixed

- **Fleet walk no longer prints a stray `NNN.row: No such file or directory`.** A
  concurrent `_walk_one` job could try to write its row file when the temp dir was
  momentarily unavailable (e.g. an orphaned background job from an earlier
  interrupted run, whose `_cleanup` had already removed that run's dir, flushing its
  stderr into a later run). The write now `mkdir -p`s the dir first (idempotent,
  cheap) and silences the redirect, so the row write always succeeds and never emits
  the noisy error. No data was lost before — the affected row still rendered — but
  the message was alarming.

## [0.32.0] - 2026-06-18

### Added

- **Run a subscription on GitHub Actions, on-demand** (`.github/workflows/sub-run.yml`):
  a manual `workflow_dispatch` that takes a pasted `sub_url` / `sub_json` (or a stored
  `SUB_URL` secret) and runs `--subscription … --sub-test all`, printing a **redacted**
  summary (counts + remediation plan — never hostnames/covers/fingerprints) by default.
  Documented public-repo caveats: inputs/logs are world-readable, so tokened URLs go in
  the secret and `redact: false` is private-repo-only.
- **Hermetic subscription CI** — `tests/test_subscription_http.sh` + a local stdlib
  fake panel (`tests/fixtures/fake_sub_server.py`) that UA-gates and runs a 302 cookie
  challenge, exercising the whole `--subscription … --sub-test all` fetch→decode→walk
  path with safe placeholders and no real infra. Wired into the macOS/Ubuntu CI matrix
  alongside the fleet helper tests.

### Changed (security)

- **secret-scan no longer stores the banned values in the repo** — those strings *are*
  the secrets, so a banned list living in a public file defeats the purpose. The list
  now loads from the `SECRET_SCAN_BANNED` env/secret or a **gitignored** `scripts/.banned`
  (template: `scripts/.banned.example`); the committed script holds only the loader. The
  always-on generic-credential layer is unchanged, and layer 1 still trips locally via
  the pre-commit hook. The no-arg scan now also covers untracked files and ignores
  `__pycache__`. (Pre-existing entries remain in git history — rotate those secrets.)

## [0.31.1] - 2026-06-18

### Fixed

- **Fleet table fully aligned — the `server:port` column no longer overruns.** After
  v0.30.0 fixed multibyte `remarks`, a hostname longer than the column (e.g.
  `…:10443` at 40 chars) still pushed `cover`/`detect`/`fp`/`tells` rightward for
  that row. The column is now capped via a new `_ep_fit` helper that truncates the
  **host** (ASCII `~` marker) while keeping the **port** intact, so the column is a
  fixed width and the rest of the table lines up across every row. Covered by
  `tests/test_wpad.sh`.

## [0.31.0] - 2026-06-18

### Added

- **Fleet remediation plan** — the single "fleet root cause" line is replaced by a
  ranked, deduplicated fix list. Many of the per-node tells are *symptoms of one
  root fix* (self-signed / chain-invalid / cn!=sni / no-relay / tls-parity / sni!=ip
  all clear when the cover is relayed), so the plan collapses signals into a handful
  of actionable fixes, annotates each with **how many nodes it clears and which**
  (range-compressed, e.g. `0-10,12,14,16-27`), and ranks them by impact (ties broken
  by how fundamental the fix is). A node can appear under several fixes — it needs
  each. New `_compress_ranges` helper + `tests/test_fleet_plan.sh`.

### Fixed

- The plan's symptom→fix grouping uses `|` as the signal/fix delimiter, not `=` —
  signal tokens themselves contain `=` (`cn!=sni`, `sni!=ip`), which an `=` split
  would corrupt.

## [0.30.0] - 2026-06-18

### Fixed

- **Fleet table is now aligned when remarks contain Cyrillic / CJK / emoji.** The
  `remarks` column was padded with `printf '%-Ns'`, which counts **bytes** — so a
  flag emoji (8 bytes) or Cyrillic name (2 bytes/char) made every row's
  byte-vs-display delta different and shifted every column after it. A new
  multibyte-aware `_wpad` helper pads/truncates by **display width** (`perl -CS`,
  exact for Latin/Cyrillic/flags, ~1 col off per wide pictograph; falls back to the
  old byte-pad if perl is absent), so `server:port` / `cover` / `detect` / `fp`
  now line up across all rows. Over-long remarks truncate with an ellipsis.
  Covered by `tests/test_wpad.sh`.

## [0.29.0] - 2026-06-18

### Changed

- **The `--sub-test all` fleet walk now probes servers concurrently** (in batches
  of `--sub-jobs`, default 8) instead of one at a time. A fleet of N servers —
  each several TLS handshakes — drops from minutes to seconds. Each node writes
  its own row file (no shared state, no interleaved output); the table is rendered
  in index order after the batch completes, so the output is byte-identical to the
  old serial walk. `--sub-jobs 1` forces the old serial behaviour. New
  `tests/test_subscription.sh` assertion locks parallel == serial.

## [0.28.0] - 2026-06-18

### Added

- **Fleet root-cause synthesis.** After the table, `--sub-test all` now tallies
  the fired signals across all scored nodes (*"shared signals across N nodes:
  27× self-signed · 27× no-relay · …"*) and names the single highest-**leverage**
  fix — the one that, applied to the shared template, clears the most nodes at
  once. Priority is by how fundamental a signal is (a broken cover relay outranks
  an exposed port), not raw count, so a uniform fleet gets one actionable verdict:
  *"fleet root cause (27/27 nodes): Reality cover is not relayed — point dest +
  serverNames at the real cover host:443."*
- **`no-relay` now carries the prober-facing result**, and curl's `000` (no HTTP
  response at all — reset/TLS-fail/silence) renders as the readable **`no-relay:noresp`**
  instead of a cryptic code; real codes stay numeric (`no-relay:403`).
- **`utls-rare` names the fingerprint** (e.g. **`utls-rare:qq`**) so you can tell
  a deliberate signature-evading fp (qq/360) from an accidental outlier. The uTLS
  fp string is now also emitted in JSON (`xray_detectability.utls_fp`).

## [0.27.0] - 2026-06-18

### Added

- **Fleet-walk `tells` now carry their values — actionable, not just labels.**
  `no-relay` → **`no-relay:403`** (the HTTP code the active prober actually got
  instead of a relay), `tls-parity` → **`tls-parity:cipher+ext`** (which TLS
  dimensions diverged from the cover), `exposed:1` → **`exposed:22+8080`** (the
  real open ports, collapsing to `+Nmore` past two).
- **Six new tells**, all from direct probes already running under `--no-tunnel`:
  `chain-invalid` (cover cert chain), `cn!=sni` (cert CN ≠ serverName), `fet`
  (flow/`fragment` exposure, lint 18), `mux` (multiplexing on — a Reality
  detectability risk), `id-nonuuid` (non-UUID VLESS id), `utls-rare` (uncommon
  uTLS fingerprint), and `clock:Ns` (client clock skew ≥ 5s, probe 19).

### Fixed

- **Fleet table no longer truncates the port off a long hostname.** A
  `host:port` longer than the 36-char column was byte-cut (`…kkk.com:4` — the
  port silently lost, real data loss). The server column is now pad-only: a long
  hostname makes that row slightly ragged but the port is always intact.

## [0.26.0] - 2026-06-18

### Added

- **Fleet walk (`--sub-test all`) now explains *why*, not just *how bad*.** Each
  row gains a **`tells`** column — the compact set of detectability signals that
  drove that server's score (`self-signed`, `no-relay`, `cover-obscure`,
  `sni!=ip`, `sni-nxdomain`, `tls-parity`, `non443`, `sni-kw`, `vision-off`,
  `exposed:N`, `throttle?`, or `clean`) — so you can see at a glance how the
  lower-scoring outliers differ from the critical mass without deep-testing each.
  All signals come from the DIRECT probes that already run under `--no-tunnel`
  (15 cover-cert, 20 active-probe, 24 TLS-parity, host-exposure, 26
  detectability); the walk just stops throwing them away. No extra network — the
  same one self-invoke per server, one `jq` pass instead of two.
- **Deployment-template fingerprint column + cluster summary.** A short **`fp`**
  column groups servers built from the same template, and a new
  *"deployment templates (count × fingerprint, band)"* summary at the bottom
  collapses a uniform fleet to one line — so any node that breaks the mold (a
  different `fp`, or the same `fp` scoring a different band) stands out
  immediately. Answers "are these all the same build?" cryptographically.
- A one-line **legend** above the table documents the `tells` / `fp` columns, and
  the no-Reality (Hysteria) and unreachable rows now carry an explanatory note in
  the `tells` column instead of a bare status.
- Tells/fp/score-band extraction is factored into a pure, unit-tested helper
  (`_fleet_row_fields`) with a new `tests/test_fleet_tells.sh` covering the
  signal matrix, the fingerprint prefix, the `clean` case, and safe degradation
  on a garbage payload.

## [0.25.2] - 2026-06-18

### Fixed

- **Fleet-walk table no longer mangles non-ASCII remarks or truncates ports.** The
  `--sub-test all` table used `printf` byte-precision (`%-24.24s`) on the remarks
  column, which cut multibyte emoji/Cyrillic names mid-character (garbled output),
  and the server column was too narrow so long `host:port`s lost the port. Remarks
  are now printed without byte-truncation (no mangling; ragged but correct) and the
  server/cover columns are widened so the port and cover domain are fully shown.


## [0.25.1] - 2026-06-18

### Fixed

- **Fleet walk (`--sub-test all`) is now fast and robust.** Two issues with the
  v0.25.0 walk: (1) each per-server self-invoke also ran the **transport probes
  (0-10)** — now it passes `--only xray,xrayjson` so only the fingerprint probes
  run; (2) a dead/unreachable server's `openssl` connect hangs the OS connect
  timeout (~75 s), not `TIMEOUT` — the walk now does a **bounded TCP precheck**
  (`nc -G/-w $TIMEOUT`) per server and marks unreachable ones without attempting
  the handshake (reported in the summary as `… unreachable`). A 28-server fleet,
  including down nodes, now scans in seconds instead of stalling.


## [0.25.0] - 2026-06-18

### Added

- **`--subscription … --sub-test all` — score the whole fleet at once.** v0.24.0
  inventoried every config but deep-tested only one; now `--sub-test all` walks
  **every** config and prints a fleet **detectability table** (idx · remarks ·
  server:port · cover · score/band) plus a summary (N critical/high/moderate/low).
  It uses the new `--no-tunnel` mode per server, so a 28-server fleet is just TLS
  handshakes — no `xray` spawn, no throughput/stability pulls — and won't hammer
  prod. Hysteria/no-proxy entries are marked skipped. Deep-test any row with
  `--sub-test N`.
- **`--no-tunnel`** — run only the **direct fingerprint** probes (cover-cert,
  active-probe, TLS-parity, detectability, lint, clock, MTU, host-exposure),
  skipping every probe that spawns `xray-core` or moves data (11/12/13/14/16/17/
  21/routing/22/25/volume). A fast detectability read for any single config too.


## [0.24.0] - 2026-06-18

### Added

- **`--subscription URL` — fetch, decode, inventory, and test a subscription.**
  Sub panels commonly 302-to-self with a `Set-Cookie` challenge and gate on the
  client User-Agent, so the fetch uses a **cookie jar + a Happ-like UA**
  (`--sub-ua` to override). The response is decoded as a **JSON array of full Xray
  configs** (the "advanced" Happ sub format), a single config object, or a base64
  blob wrapping either. It prints a **fleet inventory** (one line per config:
  remarks + the first proxy outbound's protocol/security/server/cover, marking the
  one under test) and runs the **full suite on a selected config** (`--sub-test N`,
  default 0) by reusing the normal pipeline. Extracted configs hold live creds, so
  they're written `0600` into a `0700` temp dir and EXIT-cleaned; inventory values
  go through the v0.23.1 `_safe` sanitizer (a sub is untrusted input). New
  `tests/test_subscription.sh` (offline, via a `file://` fixture). A base64
  `vless://` *list* and a per-server "score the whole fleet" walk are the next step.


## [0.23.1] - 2026-06-16

### Security

- **Control-char / ANSI-escape sanitization of config-derived values (`_safe`).**
  Attacker-influenced fields (host, cover SNI) were printed and logged raw — a
  crafted config with terminal escape sequences could execute them when the output
  or `--log-file` was viewed (terminal-escape injection). Values are now stripped
  of control chars (incl. `ESC`) before printing — at the source for `VPN_HOST` and
  the cover SNI (`_xray_cover_sni`), and in `reveal()`. No-op on legitimate
  hosts/SNIs.
- **HTTPS-first IP reputation (MITM resistance).** The geo/ASN/datacenter lookups
  used plain-HTTP `ip-api`, which the very on-path adversary being profiled can
  spoof to skew the verdict. `_asn_of` and the cover-popularity check now query an
  HTTPS source (`ipinfo.io`) first and fall back to `ip-api` (HTTP) only if it
  fails; the egress probe prints a caveat when geo/flags came over plain HTTP and
  notes the HTTPS cross-checks (`ipwho.is` / `ipapi.is`). `XRAY_EGRESS_INFO_URL`
  can be pointed at an HTTPS endpoint to harden further.

## [0.23.0] - 2026-06-16

### Security

- **Automated secret scanner + CI gate (`scripts/secret-scan.sh`).** A SecOps
  pass found that test fixtures had hardcoded *real* values — a live VLESS id and
  the production Reality cover — and that the pre-commit discipline was a manual,
  known-strings `grep` that a *new* real credential would slip past. The scanner
  closes that class: it checks (1) an explicit banned-string list (known fleet
  infra) **and** (2) generic credential patterns in config context — real UUIDs,
  43-char Reality public keys, and public server IPs in `"address"`/`@host`
  position — with obvious placeholders (all-zero UUID, all-`A`/`TEST` keys,
  RFC1918 / TEST-NET / loopback / DNS-baseline IPs) allowlisted. Wired as a **CI
  job** (blocks merge) and an opt-in **pre-commit hook** (`scripts/install-hooks.sh`).
- **Scrubbed the live values from the working tree** — the real VLESS id and the
  production cover SNI in `tests/test_fet.sh` / `tests/test_routing.sh` (and a
  CHANGELOG example) are now generic placeholders. (History still contains them;
  the real remediation for that is server-side credential rotation — a leaked
  id/cover in a public repo can't be un-published.)

## [0.22.0] - 2026-06-15

### Added

- **Probe 6 now actually tests UDP/443 + QUIC reachability** instead of skipping
  when curl lacks HTTP/3 (the common case on macOS). A dependency-free **QUIC
  Version-Negotiation probe** (perl UDP — the same soft-dep the IKEv2 probe uses)
  sends a long-header packet with an unsupported version; an RFC-9000 server must
  reply with a VN packet, so a reply proves UDP/443 + QUIC are reachable with no
  crypto. It baselines a **known QUIC host** (`cloudflare-quic.com`, override
  `XRAY_QUIC_BASELINE`) — so silence means *this network blocks UDP/443*, not "the
  host has no QUIC" (most sites run QUIC now, so an arbitrary host can't be a
  no-QUIC control). For a **Hysteria2** config it also probes the server's own UDP
  port. Verdicts: `net-blocked` (UDP/443 blocked here → Hysteria2 / QUIC covers /
  `xtls-rprx-vision-udp443` passthrough won't work), `net-ok`, `target-quic`,
  `net-ok-target-silent` (UDP/443 fine but the target gave no QUIC reply —
  expected for an obfs'd Hysteria2 or a TCP server). Hedged + single-vantage-aware.
  curl `--http3` is kept as a fallback baseline where present. JSON:
  `probes.udp.{quic_baseline, quic_target, quic_verdict}`. The verdict logic is a
  pure function (`_classify_udp_quic`), unit-tested offline
  (`tests/test_udp_quic.sh`).

## [0.21.1] - 2026-06-15

### Fixed

- **Probe 20 (active-probe) now probes the server's actual port, not 443.** The
  unauthenticated relay probe hardcoded the port in its `curl --resolve`
  (`"$sni:443:$VPN_HOST"` + `https://$sni/`), so for a Reality server on a
  non-standard port (e.g. `:56443`) it connected to `:443` — where the server
  isn't listening — and read `relay-code=000` → a false "+25, not relaying to the
  cover," which also inflated the detectability score. It now uses
  `VPN_PORT_TCP` for both the `--resolve` mapping and the URL, matching probes
  15/24 (which already connected on the configured port). The genuine-cover
  baseline still uses the cover's real `:443`. (Reported by an operator running
  Reality on `:56443`.) Regression guard: `tests/test_active_probe_port.sh`.
- **Probe 26 now recognises `xtls-rprx-vision-udp443` as a vision flow.** The
  TLS-in-TLS check matched the flow by exact string (`= "xtls-rprx-vision"`), so
  the valid `-udp443` variant (same vision splicing, additionally passes UDP/443)
  read as "no vision" and was wrongly scored `+15 (TLS-in-TLS exposure)`. It now
  matches the whole vision family. (Same operator's config used the `-udp443`
  flow, so it was hit by both this and the probe-20 port bug.)

## [0.21.0] - 2026-06-12

### Added

- **Cross-probe temporal synthesis — a volume-triggered-throttling hint.** A new
  advisory folds the *ordering* of the tunnel probes: if the tunnel carried data
  early (probe 12 up + a successful data-plane pull in 13/14) but then degraded on
  **every** later sustained use (16 egress / 17 stability / 22 bufferbloat), that
  early-pass/late-fail shape is the in-region signature of **cumulative-volume
  throttling** — and it's the one such effect a single run can hint at, because
  the tool itself generates the load (probe 14 pulls up to ~50 MB), creating a
  natural before/after-load boundary. Requires **≥2** independent late
  degradations (one alone is too FP-prone). It is **advisory only — never folded
  into the detectability score** — and explicitly hedged: equally consistent with
  transient congestion, so it points at the disambiguating re-run
  (`XRAY_SPEEDTEST_MAX_BYTES=<small>` / `--no-speedtest`) rather than asserting a
  block. JSON: `probes.xray_detectability.volume_throttle_suspected`. The decision
  is a pure function (`_volume_throttle_suspected`), unit-tested across the firing
  pattern and the healthy / dead-tunnel / single-failure / skipped cases
  (`tests/test_volume_synthesis.sh`).
- **`--full` / `--thorough` — a comprehensive-run umbrella.** Turns on the two
  opt-in scanners (`--scan-covers` + `--censor-sweep`) in one flag; everything
  else already runs by default for a config. It's an **explicit** opt-in by
  design, not a silent default — `--censor-sweep` actively fetches known-censored
  sites from the operator's own machine (a risk in a censored region), so that
  stays the operator's deliberate call. Doesn't clobber an explicit
  `--scan-covers=LIST` / `--censor-sweep=LIST`, and prints a one-line note that
  the censored-site sweep is running. `tests/test_full_flag.sh`.

## [0.20.1] - 2026-06-12

### Fixed

- **Probe 26 no longer scores an unreachable cover as "authentic" (false-clean).**
  When the Reality cover is unreachable (probe 15 gets no cert), the detectability
  synthesis used to fall through to `cover cert (15): authentic, matches
  serverName +0` — asserting a clean cover it never actually saw. It now scores
  **UNVERIFIED (+5)**, mirroring the existing unverified path for probes 20/24.
- **Probe 26 no longer counts "no coherent HTTP" as a confirmed +25 tell when the
  server is unreachable.** If the active-probe sees silence (`relay-code=000`)
  *and* the cover was unreachable, that silence is the blackhole, not a relay
  refusal — you can't tell "won't relay" from "can't reach". It's now scored
  **UNVERIFIED (+5)** instead of `exposed (+25)`. (Both surfaced by a real run
  against a blackholed in-region node, where the old logic reported a confident
  50/100 built partly on artifacts of unreachability.)
- The cover-cert and active-probe scoring are now pure functions
  (`_score_cover_cert`, `_score_active`), unit-tested across reachable and
  unreachable cases without a live server (`tests/test_detect_scoring.sh`).

## [0.20.0] - 2026-06-11

### Added

- **`--outbound TAG` — target one server in a multi-outbound config.** An Xray
  JSON config can hold several proxy outbounds (split-tunnel routing, balancer
  fleets); the full-config probe (12) runs them all with routing intact, but the
  single-server fingerprint probes (host, cover cert, active-probe, TLS-parity,
  detectability) need one. `--outbound TAG` narrows the config to that outbound
  (the chosen outbound + a `freedom` direct, with `routing`/`balancers` dropped)
  and tests that server **standalone**. Without the flag, behaviour is unchanged —
  the full config is tested, the first proxy outbound feeds the single-server
  probes, and a note reports how many proxy outbounds there are and their tags so
  you know there's more to target. Narrowing is implemented by reordering the
  chosen outbound to index 0, so every existing read path targets it with no
  per-field changes. A `--outbound` tag that isn't a proxy outbound, or doesn't
  exist, exits with the list of valid tags. Chained configs (`dialerProxy`) warn
  that a standalone test won't reflect the chain (use the full config instead).
  New `tests/test_outbound_select.sh`.

## [0.19.0] - 2026-06-11

### Added

- **Happ deep-link input adapter.** [Happ](https://happ.su) `happ://` links are
  now accepted via `--xray-config`, in three forms:
  - **`happ://import/<scheme://…>`** — unwraps the inner config URL
    (vless/vmess/trojan/ss/hy2/…) and runs it through the normal pipeline (a
    `hy2://` inner flows into the Hysteria2 analyzer for free). Tolerates a plain,
    percent-encoded, or base64-wrapped inner URL.
  - **`happ://routing/add/<base64-json>`** — recognised as a **routing profile**
    (no server to tunnel-test). It's decoded, summarised (name, `DomainStrategy`,
    `RouteOrder`, `GlobalProxy`, `FakeDns`, remote DNS), and **linted** with the
    tool's existing reasoning: the `IPOnDemand`/`IPIfNonMatch` DNS-leak vector
    (noting `FakeDns: true` as the mitigation), and a remote DoH resolver whose
    own domain is region-blocked (e.g. `cloudflare-dns.com` in RU).
  - **`happ://crypt…`** — detected as an **RSA-encrypted** link that can't be
    opened without the operator's key; says so instead of choking.
  An unrecognised `happ://` variant exits with a clear message. New
  `tests/test_happ.sh`.

## [0.18.2] - 2026-06-10

### Changed

- **Probe 17 (held-session stability) now auto-confirms a reset instead of
  punting.** Each killed pulse is retried once inline — only a reset that
  *reproduces* is counted as a kill, so a single stray RST / server hiccup no
  longer trips a block verdict. A pulse that resets then passes on retry is
  reported as a recovered transient blip (`pulses_retried_recovered` in JSON) and
  not counted. The `transient` verdict (non-monotonic ladder) consequently means
  a *retry-confirmed* reset that a larger pulse still cleared — a size/path
  anomaly, stated as such rather than "re-run to confirm".
- The kill-ladder classification is now a pure function
  (`_classify_stability_ladder`) split out from the probe, unit-tested across
  none/ok/slow/transient/volumetric/reset without needing a live tunnel
  (`tests/test_stability_classifier.sh`).

### Fixed

- **Probe 1 (DNS) no longer emits a spurious "DoH returned no A records"
  warning for an IP-literal target.** A bare IP has no name to DoH-resolve; the
  probe now detects an IPv4/IPv6 literal (`_is_ip_literal`), skips the DoH lookup
  and the poisoning/leak comparison, and notes the checks are N/A instead of
  warning.

## [0.18.1] - 2026-06-10

### Fixed

- **Probe 17 (held-session stability) no longer over-claims "volumetric
  kill-shaping" on a transient reset.** The verdict required only `some kill +
  some ok + first kill wasn't tiny` — it never checked that *no larger pulse
  survived*. A real run showed the 1 MB pulse reset but the **4 MB pulse then
  succeeded** (non-monotonic), yet it was reported as a volumetric byte-threshold
  block. Now the hard "volumetric kill-shaping" FAIL fires only when the ladder
  is **monotonic** (every pulse at/above the reset also failed); a larger pulse
  succeeding after a smaller reset downgrades to a `transient` status with a
  "re-run to confirm" note instead of a false block verdict.
- **Probe 19 (clock skew) now parses the HTTP `Date` header under any locale.**
  `_epoch_from_httpdate` parsed the (always-English) RFC-7231 date with `date`
  without forcing the locale, so on a non-English machine (e.g. `ru_RU`) `%a`/`%b`
  were matched against localized month/day names and failed — surfacing as
  "could not parse reference time" and a blind clock-skew probe. Now forces
  `LC_ALL=C` on the parse.

## [0.18.0] - 2026-06-10

### Added

- **Hysteria2 config analysis (`probe_hysteria`).** Hysteria2 is QUIC over
  UDP/443 — a different stack from Xray/Reality (no cover relay, no TLS-in-TLS),
  so the Xray probes don't apply and a TCP/TLS probe against it would falsely
  read "unreachable". The tool now **auto-detects a Hysteria2 client config** —
  YAML or JSON via `--xray-config-json`, or a `hysteria2://` URI via
  `--xray-config` — and runs a static analyzer that applies the same detection
  principles to what the client config exposes:
  - **Cleartext SNI tell (the #1 risk).** QUIC carries the SNI in the Initial
    packet, which the GFW decrypts and reads (since 2024). A protocol /
    circumvention keyword in `tls.sni` (or in the server hostname, when no
    explicit `tls.sni` is set and the SNI defaults to it) is one-glance
    identification — flagged with a fix (set an innocuous, popular SNI).
  - **obfs (salamander)** present? Without it the QUIC handshake is
    fingerprintable.
  - **`tls.insecure`** — cert verification disabled (MITM + can't validate the
    masquerade cert).
  - **UDP/443 single-point + QUIC-SNI advisory** — no TCP fallback; wholesale
    UDP/443 blocking takes it down (port-hopping / fallback suggested).
  - Says plainly that what dominates detectability — the **server's** masquerade
    target, cert, and enforced obfs — isn't visible in a client config.
  JSON: `probes.hysteria.{status, sni_keyword, sni_explicit, obfs, insecure}`
  (booleans only — share-safe; the raw SNI prints only under `--reveal`).

## [0.17.0] - 2026-06-09

### Added

- **Probe 24 → JA3S-grade.** TLS-parity now compares the **ServerHello extension
  set** (via `openssl -tlsextdebug`) — the discriminating part of a JA3S/JA4S
  fingerprint that version/ALPN/cipher alone miss — and emits a comparable
  **fingerprint hash** for the server vs the genuine cover. A correctly-relaying
  Reality server is byte-identical to the cover; a broken/own-TLS one diverges at
  the extension level even when version/cipher align. The pass/fail decision still
  rests on version+ALPN+cipher (reliable, feeds probe 26), but an extension-only
  divergence is surfaced as a finer tell. JSON `xray_tls_parity.{ext_match,
  server_fingerprint, cover_fingerprint}`. (Server-side fingerprinting is fully
  observable from our own connection — no `tshark` needed, unlike the *client*
  fingerprint.)
- **Host-exposure probe (whole-host disguise).** Checks the server for giveaway
  ports beyond 443 (SSH/RDP, and proxy-**panel** ports like x-ui/3x-ui). A real
  CDN edge answers only 443; an open panel is both a takeover risk and a loud tell
  to any scanner profiling the IP. Auto (with a config); short per-port timeout so
  a firewalled host can't stall it. JSON `probes.host_exposure`.

## [0.16.0] - 2026-06-08

### Added

- **Censored-URL sweep (`--censor-sweep[=LIST]`).** OONI-`web_connectivity`-style
  reachability: fetches a list of commonly-censored hosts **direct** and (when the
  tunnel is up) **through it**, classifying each — *reachable (both)* /
  *blocked direct → tunnel carries it* (the tunnel is doing its job) /
  *direct only → tunnel doesn't carry it* (routing/proxy fault) / *blocked both*.
  Summarises how many the tunnel unblocks vs. drops. Reuses `_url_reachable` and
  the SOCKS-through-tunnel path (no new deps); direct-only when there's no tunnel.
  Opt-in. JSON `probes.censor_sweep`.
- **Cover scanner: popularity/throughput guidance.** The scan now explains that
  it checks *protocol suitability + region-risk only* — it can't measure a site's
  traffic rank — and that a good cover must also be **high-traffic/popular** (for
  collateral + volume-blending), while the **cover's own speed doesn't gate the
  tunnel** (that's the proxy backend + egress, probes 13/14).

### Fixed

- **Cover-scan JSON.** `candidates[]` was space-split, but verdicts contain spaces
  (`good cover [region-risk: …]`), so the JSON mis-parsed multi-word verdicts
  (the test only exercised the one-word `unreachable`). Now newline-separated.

## [0.15.0] - 2026-06-05

### Added

- **Cover-SNI scanner (`--scan-covers[=LIST]`).** Ranks candidate Reality
  `dest`/`serverName` covers by the properties that matter — **TLSv1.3 + HTTP/2 +
  CA-valid cert + non-redirect (HTTP 200)** — and names the best. The diagnostic
  counterpart to the "self-owned/obscure cover" finding: instead of only telling
  you a cover is weak, it helps you pick a good one (the niche
  [Hiddify-Reality-Scanner](https://github.com/hiddify/Hiddify-Reality-Scanner)
  fills). `LIST` is comma-separated, or omit for a built-in set of neutral,
  globally-popular CDN/cloud sites. Standalone (no config/tunnel needed); curl
  bounds reachability so a dead candidate can't stall the scan. JSON
  `probes.cover_scan` (`status`, `best`, `candidates[]`). Caveat surfaced in the
  output: checked from the client, and a global-CDN cover still mismatches the
  server's IP (prefer one on the server's own network, or self-steal). Scores are
  **vantage-local**, so candidates commonly blocked/throttled in a censored region
  (Cloudflare in RU, Google in CN, …) are flagged **`[region-risk]`** and
  de-prioritised in the pick — a cover censored in-region is a dead cover there no
  matter how it scores here. It stays **opt-in** (the only probe that reaches
  third-party sites), but the cover-weak recommendations (self-signed / self-owned
  cover / SNI↔IP mismatch) now **point to `--scan-covers`** so it's discoverable
  exactly when it's useful.

### Changed

- **DNS-resolver line (probe 16) clarified.** It now states plainly that the
  edns check confirms proxied lookups exit *through the tunnel* (resolved at the
  egress), and that a client-side DNS leak shows up as the routing
  `domainStrategy` finding instead — not here.

## [0.14.1] - 2026-06-05

### Changed

- **TLS-in-TLS / vision scoring is now correct on non-raw transports.** REALITY
  over gRPC/ws/xhttp **can't** use `xtls-rprx-vision` (it needs raw TCP), so that
  case is no longer scored `+15` "exposure" — it's a **censor-dependent tradeoff,
  not a misconfig** (HTTP/2-framed transports are often *less* targeted than
  raw+vision against current censors; no consensus —
  [XTLS #2593](https://github.com/XTLS/Xray-core/discussions/2593)). The `+15`
  now applies **only** to raw-TCP-without-vision (a real, available mitigation
  left unused); the non-raw case emits a note and `xray_detectability.tls_in_tls_protected: null`.
- **uTLS-fp note mentions JA4.** [JA4](https://github.com/FoxIO-LLC/ja4) (the JA3
  successor) **sorts** the cipher/extension lists, so extension-shuffling no
  longer hides a rare fp; and a proxy that tweaks the ClientHello or normalizes
  HTTP headers breaks JA4 **parity** ([XTLS #4900](https://github.com/XTLS/Xray-core/issues/4900)).

### Added

- **QUIC-SNI advisory.** Flags QUIC-based configs (Hysteria2 / TUIC, or
  `network: quic`) for the GFW's QUIC-SNI censorship — it decrypts the QUIC
  Initial, reads the SNI, and blocks a residual list since 2024
  ([gfw.report USENIX'25](https://gfw.report/publications/usenixsecurity25/en/)).
  Mitigation: SNI-slicing across QUIC CRYPTO frames (default in `quic-go ≥ 0.52.0`,
  inherited by Hysteria2/TUIC). Covers both Xray-form and sing-box configs.

## [0.14.0] - 2026-06-05

### Added

- **`--xray-only` flag.** Runs only the Xray-protocol probes (11–26 + routing /
  egress) and skips the transport probes (0–10) — a convenience alias for
  `--only xray,xrayjson` for quickly re-checking a config's tunnel/stealth/routing
  without the network-layer probes. Warns if no `--xray-config` /
  `--xray-config-json` was given (nothing to probe).

## [0.13.1] - 2026-06-05

### Added

- **Parser-vs-destination fix-class one-liner** in the recommendation block — the
  "ByeDPI vs Xray" decision in one line, chosen from what actually fired:
  **PARSER** (a fragmentation bypass was confirmed → a client-side desync like
  ByeDPI/zapret beats the block with no server, on your own IP) vs
  **DESTINATION/PROBE** (IP block / active probing / detectable protocol → you
  need a destination-hiding tunnel like Reality/Xray). Parser wins when a
  fragmentation bypass is present (a server is then optional); it does not fire on
  a routine moderate-detectability run.

## [0.13.0] - 2026-06-05

### Added

- **GFW fully-encrypted-traffic (FET) exposure check (probe 18).** Implements the
  detection from *"How the Great Firewall of China Detects and Blocks Fully
  Encrypted Traffic"* (gfw.report, USENIX Security '23). Since 2021 the GFW
  *exempts* traffic that looks like a known protocol — a TLS record header, an
  HTTP verb, or mostly-printable bytes — and **blocks the rest** by an entropy
  test (set bits/byte ≈3.4–4.6 = looks random). A proxy with **no TLS/HTTP
  framing** — Shadowsocks, or VMess/VLESS over **raw TCP with `security: none`** —
  is random from byte 0, matches no exemption, and is blocked. The check is
  purely static (protocol + security + transport): TLS/REALITY match the TLS
  exemption, `ws`/`grpc`/`xhttp` carry plaintext HTTP framing, and UDP transports
  (mKCP/QUIC) aren't covered by this TCP classifier. Flags exposure with a verdict
  and a fix (wrap in TLS/REALITY, use an HTTP-framed transport, or add an
  obfs/prefix+padding for Shadowsocks). JSON `xray_lint.fet_exposed`.
- **Self-steal as a second SNI↔IP fix.** The CDN-fronting suggestion now also
  names the `self-steal` REALITY pattern (server fronts its own site via
  `realitySettings.target` + its own `serverNames`, so the cover resolves to the
  server itself — no mismatch).



### Added

- **TLS-in-TLS exposure check (probe 26, scored +15).** Flags VLESS-REALITY
  configs that lack `flow: "xtls-rprx-vision"` — the inner TLS records of a
  proxied HTTPS site carry a length/timing signature visible inside the outer
  REALITY TLS, which the most advanced censors detect passively (REALITY with a
  non-XTLS flow is officially discouraged for this reason). Detected statically
  from the flow/transport (the *mitigation*, not the packet signature — no
  `tshark`). Unlike the uTLS-fp tradeoff, vision is near-universally correct, so
  it scores. JSON `xray_detectability.tls_in_tls_protected`.
- **CDN-fronting suggestion.** When the SNI↔IP mismatch / entry-egress
  co-location tells fire, the recommendation now names CDN-fronting as the
  structural fix: front the entry behind a CDN so the cover SNI resolves to the
  CDN's own IPs and the connection terminates there, eliminating both tells.
- **Traffic-shape advice (folded into the vision finding).** Suggests XHTTP +
  padding where vision can't apply (CDN-frontable transports), and surfaces
  `mux.cool` as a soft note (it adds a correlation/shape surface and is generally
  unnecessary with vision). JSON `xray_detectability.mux_enabled`.
- **Server-side VLESS `fallbacks` detection** (active-probe defense, info-only),
  and the DNS recommendation now points to the canonical `geosite:cn`/`geoip:cn`
  → direct + `fakedns` recipe.
- **DNS split-horizon detection (routing probe).** A `dns` block with per-domain
  servers (a tunneled foreign resolver + a local domestic one) is recognized as
  the leak-free way to keep geoip routing. JSON `xray_routing.dns_split_horizon`.

### Changed

- **Sharper DNS-leak messaging.** The `domainStrategy` finding now explains the
  *direction* of the leak: local resolution of a proxied domain is leak-only, not
  blending (the local censor never sees the proxied destination — it connects
  from the exit IP), while direct traffic already resolves locally at the
  `freedom` outbound. Recommends a split-horizon `dns` block, and notes a tunneled
  resolver's local blockability is irrelevant once routed through the proxy.
- **Probe 18 lint** accepts `network: "raw"` (the current name for `tcp`) for
  `flow=xtls-rprx-vision`, instead of flagging it as a misconfig.

### Fixed

- **False-positive "rotate endpoint" verdicts.** Probe 5's *"firewall blackhole /
  full IP block"* is now suppressed when the tunnel actually works
  (`XRAY_JSON_STATUS=ok`), and probe 13's *"data plane unusable"* is suppressed
  when multi-stream capacity (probe 14) or held-session stability (probe 17) are
  healthy — both replaced with one transient note. A single early/single-stream
  stall no longer contradicts a working tunnel pushing full throughput (same
  vantage-aware cross-reference as probe 2).

## [0.11.0] - 2026-06-05

### Added

- **Egress-vs-routing-intent cross-check (routing probe ↔ probe 16).** New
  cross-probe synthesis: if the proxy-routed set contains **streaming or payment
  domains** AND the egress is on **datacenter/proxy reputation lists**, those
  exact services will geo/proxy-block through the node. The tool already had both
  facts (the routing map and the egress reputation flags) but never connected
  them; now it warns, raises a verdict, and recommends a residential/clean-IP
  egress for those flows (or dropping them from the proxy set). JSON
  `xray_routing.proxy_sensitive_categories`.

### Changed

- **Per-strategy `domainStrategy` precision.** The DNS-leak check no longer
  treats `IPOnDemand` and `IPIfNonMatch` identically. `IPOnDemand` only resolves
  to evaluate an `ip`/`geoip` rule, so with **no `ip` rules it never resolves**
  and is no longer flagged (a no-op, not a leak). `IPIfNonMatch` resolves
  **every** unmatched destination regardless of `ip` rules, so it's flagged
  whenever there's no `dns` block. The advice also reads the inbound
  **sniffing** state: with sniffing on, domain rules match leak-free and the fix
  is `domainStrategy: "AsIs"`; with sniffing off, it tells you to enable sniffing
  first. JSON `xray_routing.sniffing`.

## [0.10.0] - 2026-06-05

### Added

- **Routing `domainStrategy` / DNS-leak check.** The routing probe now reads
  `routing.domainStrategy` and flags **`IPOnDemand`/`IPIfNonMatch` with no `dns`
  block** as a DNS-leak + latency risk: those strategies resolve destination
  domains to IP (to evaluate `ip`/`geoip` rules) via the **system/ISP resolver**,
  so the resolver sees the proxied and direct domains even though traffic is
  tunneled. With sniffing on, domain rules match without resolution, so the fix
  is `domainStrategy: "AsIs"` (+ a `dns` block routed through the proxy). JSON
  `xray_routing.domain_strategy` and `dns_leak_risk`.
- **Self-owned / obscure cover detector (probe 26).** A good Reality cover is a
  popular site on a major CDN (blocking it costs the censor collateral). A cover
  that **resolves to a hosting/VPS network** rather than a CDN is self-owned or
  obscure — low collateral to block, and often a brand/operator domain (a
  provider tell). Detected via the **datacenter flag** (ip-api `hosting`, then
  ipapi.is `is_datacenter`/ASN-type) — not just the org name, so it catches small
  hosts an org-keyword list misses. Scored `+10` and named; a CDN-hosted cover
  (e.g. `www.microsoft.com`) is not flagged. JSON `xray_detectability.cover_obscure`.

## [0.9.3] - 2026-06-04

### Added

- **Entry↔egress co-location signal (probe 16).** Most providers egress on a
  *different* network than the Reality entry; a deployment that exits from the
  **same /24** (or same ASN) as its entry runs ingress+egress on one block — a
  distinctive, low-FP topology signature (e.g. an entry `.6` exiting via `.2` in
  the same /24). The probe now compares the egress IP against the entry IP and
  reports `same-/24` / `same-ASN` / `different`. Operator-visible only (a censor
  doesn't see the egress), so it's reported for identification, not scored;
  booleans only (IPs stay behind `--reveal`). JSON `xray_egress.egress_colocated`.
  `query` was added to the ip-api field set to obtain the egress IP.

## [0.9.2] - 2026-06-04

### Changed

- **The uTLS fingerprint is a tradeoff, no longer a scored penalty.** v0.9.0
  scored an uncommon uTLS fp (`qq`/`360`) as `+10` detectability — but that
  modeled only *anomaly/allow-list* censors (rare = outlier). Against a
  *signature/deny-list* censor like **TSPU**, which blocklists the near-universal
  `chrome`-uTLS-Reality JA3, a rare fp is exactly what **evades** — so `chrome`
  can be *more* detectable, not less. The score now adds **0 points** for fp
  distinctiveness and presents it as a two-sided tradeoff (signature-evasion vs
  anomaly-visibility), letting the operator's empirical result against the target
  censor decide. The fp is still reported and still folded into the **deployment
  fingerprint** (so it continues to *identify* a deployment), just not penalized.
  Net: an `fp=qq` Reality node returns from 40/100 (high) to its structural
  30/100 (moderate). Test updated to assert fp does not move the score.

## [0.9.1] - 2026-06-04

### Added

- **Probe 16 egress reputation: a fallback source so flags aren't "n/a" when
  ip-api is rate-limited.** When ip-api's flag endpoint returns nothing (rate
  limited → no `countryCode`, so `hosting`/`proxy`/`mobile` came back `n/a`),
  the probe used to fall to *"reputation only partially checked"*. It now queries
  a third source (`XRAY_EGRESS_DC_URL`, default `ipapi.is`) through the tunnel
  for an **explicit datacenter / proxy / ASN-type flag** — which the existing
  ASN pool (ipinfo / ipwho.is / ifconfig) doesn't provide and the org-keyword
  heuristic misses for providers off its list. So a rate-limited run now still
  determines the egress is (or isn't) a datacenter instead of leaving it
  incomplete. JSON `xray_egress.datacenter_fallback`. New test
  `tests/test_egress_fallback.sh`.

## [0.9.0] - 2026-06-04

### Added

- **uTLS-fingerprint distinctiveness as a detectability signal (probe 26).**
  Reality mimics a browser's ClientHello via uTLS. A globally-common browser
  (`chrome`/`firefox`/`safari`/`edge`/`ios`/`android`) blends in; a regional or
  uncommon one — `qq` / `360` (China-specific browsers, rare elsewhere) — yields
  a **stable, distinctive JA3** a fingerprinter can match (`random`/`randomized`
  give no fixed JA3, so they aren't penalized). The score now folds this in
  (`+10`) and names it, and it's a per-deployment constant — so e.g. an `fp=qq`
  config moves from 30/100 (moderate) to 40/100 (high). JSON
  `xray_detectability.utls_fp_uncommon`.
- **Deployment fingerprint — recognize the same provider/template across nodes.**
  A short, stable, **share-safe** SHA-256 hash over the config's *identifying
  shape* — protocol / security / network / flow / uTLS-fp / shortId-length /
  port / a routing-recipe signature — and **nothing sensitive** (never the IP,
  UUID, keys, or cover domain). Two configs from the same provider hash
  identically (only per-node IP/keys/SNI differ), so you can match a known
  deployment's fingerprint to answer "is this the same provider?". JSON
  `xray_detectability.deployment_fingerprint`. New test
  `tests/test_utls_fingerprint.sh`.

## [0.8.2] - 2026-06-04

### Fixed

- **Routing default-route detection no longer mistakes a `protocol:`/`port:`-only
  rule for the catch-all.** A full-tunnel-with-bypass config (e.g.
  `protocol:bittorrent → direct`, a domain bypass list → direct, and everything
  else → the proxy via Xray's first-outbound default) was read **backwards** as
  *"default → direct, selective routing"*. A true catch-all matches everything —
  no `domain`/`ip`/`port`/`protocol` narrowing — so protocol- and port-scoped
  rules are now excluded, and the default correctly falls back to the first
  outbound. Such a config now reads *"default → proxy, ALL traffic tunnels"*.
  Regression test added to `tests/test_routing.sh`.

## [0.8.1] - 2026-06-04

### Changed

- **Routing live test no longer counts a non-fetchable apex as a split-tunnel
  failure.** Tier 2 marked any failed fetch "unreachable", so a routed domain
  whose **apex doesn't resolve** (e.g. `cdninstagram.com` — a suffix-match entry
  for `*.cdninstagram.com`, not a host) or a CDN host with no root page looked
  like a proxy fault. Each sampled domain is now classified against a **direct
  baseline**: `carried` (proxy reached it), `proxy-failed` (reachable directly
  but **not** through the proxy — the only real routing fault), or `n-a`
  (unreachable both ways → ignored). "Reached" also counts a completed
  TLS-to-target handshake, not just an HTTP status, so asset hosts that serve no
  root page still register. JSON `live_results[].http_code` → `.result`.

## [0.8.0] - 2026-06-04

### Added

- **Routing-coverage probe (split-tunnel) — the tool now understands the
  `routing` table it used to strip.** A "selected sites via the proxy, rest
  direct" config expresses its intent in `routing.rules`, which every other
  probe discards (`del(.routing)`). The new probe has two tiers:
  - **Tier 1 — static map + lint** (always, pure-jq): maps each rule per
    outbound (domain / geosite / geoip / ip counts), resolves the **default
    route** (catch-all rule, else the first outbound), classifies proxy vs
    direct outbounds, and lints the footguns — an `outboundTag` **referenced but
    not defined** (matched traffic silently dropped → verdict), and the
    **default-route direction** (all-proxy vs selective).
  - **Tier 2 — live split-tunnel test** (when the tunnel is up): launches
    xray-core with the **full config (routing intact)** and fetches a sample of
    proxy-routed sites through it, so you can see the split actually carries them
    — catching a dead proxy path that the generic tunnel test (probe 12) can miss
    when its own target happens to route direct.

  JSON gains `probes.xray_routing` (`status`, `default_outbound`,
  `proxy_outbounds`, `undefined_outbound_tags`, `live_test`, `live_results`).
  New test `tests/test_routing.sh`.

## [0.7.5] - 2026-06-03

### Changed

- **"IP route blocked" no longer overclaims censorship for a host that's just
  down.** When the target's TCP 80+443 both fail, probe 2 used to assert *"IP
  route blocked entirely"* and recommend *"rotate to a fresh IP"* — wrong for a
  server that's simply offline, and useless advice (rotating *your* IP can't fix
  a downed server). It's now **vantage-aware**:
  - an **ICMP liveness** check splits "up but TCP-filtered" (host pings) from
    "unreachable" (no TCP, no ICMP), each with its own verdict;
  - the recommendation cross-references the **control sites** (probe 8): on a
    **clean vantage** (all control sites reachable → not broad censorship) an
    unreachable host reads as *"most likely DOWN / null-routed — verify it's up;
    rotating your own IP won't help"*; only on a **filtered vantage** is an
    IP-level block suggested.

  JSON `probes.tcp` gains `target_icmp_ok`. New test
  `tests/test_ip_route_vantage.sh`.

## [0.7.4] - 2026-06-03

### Added

- **Detect a non-Xray JSON config (e.g. sing-box) and say so plainly.** Passing
  a sing-box config to `--xray-config-json` used to silently mis-parse (its
  outbounds use `type`/`server`/`route`, not Xray's
  `protocol`/`settings.vnext`/`streamSettings`). The tool now detects this up
  front (no outbound has a `protocol` field, plus sing-box markers) and reports
  *"this is not an Xray-core config (looks like sing-box) — Xray-protocol probes
  skipped"* with a verdict, instead of producing confusing output. It still
  derives the server from the sing-box shape (`server`/`server_port`) so the
  transport probes (0-10) run against it; only the Xray-protocol/stealth probes
  (11-26) are skipped. New test `tests/test_nonxray_config.sh`.

## [0.7.3] - 2026-06-03

### Added

- **`--xray-config-json` now accepts inline JSON and stdin, not just a file.**
  The value may be a file path (unchanged), **inline JSON** (`'{…}'`), or **`-`**
  (read from stdin). JSON is full of shell-hostile symbols (`{ } " :` spaces), so
  the robust ways to pass it are to single-quote inline JSON, or — cleanest — a
  quoted heredoc over stdin: `--xray-config-json - <<'EOF' … EOF` (the quoted
  delimiter stops the shell touching `$`/backticks/quotes inside). Inline/stdin
  JSON is written to a `0600` temp file that the EXIT trap removes (it holds live
  credentials), so every downstream reader still sees a normal path. Invalid JSON
  or empty stdin fail fast (exit 1) with a quoting hint. New test
  `tests/test_inline_json.sh`.

## [0.7.2] - 2026-06-02

### Added

- **`--reveal` — opt-in operator detail.** By default every line the tool prints
  is share-safe (booleans / country / codes only — never the cover domain,
  serverName, egress IP, or org), so output can be pasted into a ticket. But the
  operator running it on their *own* config often needs the specifics ("*which*
  SNI is the problem?"). `--reveal` prints them to the **terminal**: the cover
  `serverName` (probe 15/26), the flagged cleartext SNI (probe 26), and the
  egress IP / org / country (probe 16). It is deliberately **terminal-only** —
  never written to the log file, never in `--json` (suppressed under
  `--quiet`/`--json`), and obviously never committed. Its output is **not** safe
  to paste or share. New test `tests/test_reveal.sh` locks all three invariants
  (shown with the flag, absent without it, absent from JSON).

## [0.7.1] - 2026-06-02

### Changed

- **An unverifiable stealth dimension now counts as risk, not a clean pass.**
  When probe 20 (active-probe resistance) or 24 (TLS parity) can't baseline
  against the genuine cover, probe 26 used to score it `+0` — i.e. treat
  "couldn't check" as "verified clean," which understates risk. It now adds a
  modest **UNVERIFIED +5** each, because an unconfirmed stealth property is an
  open risk. Guards against false inflation: it's weighted well below a
  *confirmed* tell (25/15 — absence of evidence ≠ evidence of bad), and applies
  **only** to a cover/server-side baseline failure (`no-baseline` / `unreachable`)
  — a missing local tool (openssl/curl) stays `+0`, since that's the tool's
  limitation, not the server's risk. So a Reality server with an NXDOMAIN cover
  reads ~30/100 (cover quality + the two unverified dimensions) instead of a
  misleading low score.

## [0.7.0] - 2026-06-02

Four fixes surfaced by testing a real VLESS-Reality + XHTTP share-link, where
the tool both over-alarmed (phantom DPI) and under-alarmed (missed the real
risk) on a perfectly healthy config.

### Fixed

- **Probes 3-5 no longer cry "TLS DPI / RST injection / HTTPS cut" against a
  Reality server.** They probed the wrong SNI — the bare-IP `VPN_HOST` (or
  no-SNI / an innocent SNI) — never the configured Reality serverName. A Reality
  server is *designed* to drop handshakes whose SNI isn't a configured
  serverName, so those drops were misread as a censor block (and propagated to
  the verdict + recommendation). New `_effective_tls_sni` helper: probes 3-5 now
  present the Reality serverName, and probe 3 judges the block on *that*
  handshake and skips the generic DPI verdicts for Reality configs. Behaviour is
  unchanged for non-Reality targets.
- **Probe 15 matches the cert's SAN, not just its CN.** A cover cert with
  `CN=example.com` and SAN `*.example.com` legitimately covers a subdomain
  serverName, but the CN-only check called that a mismatch and escalated to a
  false "authentication fails fleet-wide" verdict. It now parses the leaf cert's
  Subject Alternative Names (with one-level wildcard logic) before deciding.

### Added

- **Probe 26 scores cover-SNI quality** — two tells a valid cert cannot mask,
  because the serverName is sent in cleartext in every ClientHello:
  - the cover SNI **carries a circumvention/antagonistic keyword** (vpn, proxy,
    xray, reality, … or a censor's name) → a passive SNI-blocklist DPI (the
    cheap, default method) matches and blocks it on sight, no lookup needed
    (+10). This is the **severe** one.
  - the cover SNI is **NXDOMAIN** (doesn't publicly resolve) → not a real site
    you blend into (+10). A **soft** tell: it only bites a censor that *actively*
    resolves SNIs, not the passive default. It's *also* why the active-probe (20)
    and TLS-parity (24) baselines report "not evaluated" — there's no genuine
    cover to compare against, which the breakdown now says explicitly instead of
    leaving a silent gap. Only a DNS-**confirmed** NXDOMAIN flags it — a transient
    SERVFAIL / timeout / geo-DNS miss from the run vantage does **not** (no FP).

  Both get a dedicated named verdict. JSON `xray_detectability` gains
  `sni_resolves` and `sni_keyword`. New test `tests/test_sni_quality.sh`.
- **XHTTP transport in the URL→JSON synthesis.** `type=xhttp` (and the legacy
  `splithttp`) now emit `xhttpSettings` (`path` / `host` / `mode`), so probe 12
  can probe XHTTP share-links end-to-end instead of failing while xray-knife
  (probe 11) succeeds.

## [0.6.3] - 2026-06-02

### Added

- **`allowInsecure` / `insecure=true` handling for skip-verify WS/TLS configs.**
  Some VLESS configs (e.g. sing-box `"tls": { "insecure": true }`, exported as
  a `vless://…&allowInsecure=1` share-link) tell the client to accept *any*
  server cert. Two changes:
  - the URL→JSON synthesis now **carries `allowInsecure` into `tlsSettings`**
    (both `allowInsecure=` and `insecure=` spellings), so such a config can be
    probed end-to-end instead of failing the handshake on its invalid cert;
  - the config lint (probe 18, static — so it **fires even against an
    unreachable node**) now **flags `allowInsecure=true` as a detectability
    tell**: the client is masking a cert that won't validate for the SNI (a
    strong active-probe fingerprint) and the path is MITM-able. The fix is a
    real valid-cert domain, or Reality (which needs no client-side cert).

  New test `tests/test_allow_insecure.sh`. Suite now 18.

## [0.6.2] - 2026-06-02

### Added

- **Probe 26 now recognizes the passive Reality *conjunction* — and names it.**
  A perfectly active-cloaked Reality server (authentic cover cert, relays
  unauth probes, TLS parity — 0/100 on every active probe) was still scored
  only by its two independent passive tells (non-443 port +10, SNI↔IP mismatch
  +10 = 20/100), each of which is FP-prone alone. But their **conjunction** —
  presenting an SNI for a domain that lives on a *different network* **and**
  serving it on a *non-standard port* — is a recognized VLESS-Reality
  structural signature a passive censor can match with low FP. Probe 26 now
  detects the conjunction (+10), and emits a dedicated, named verdict:
  *"Passive Reality/Xray fingerprint detected …"*. So such a server reads as a
  **30/100 named Reality fingerprint** instead of a misleading low score.
  JSON `xray_detectability` gains `passive_fingerprint_strong`.

### Changed

- **Hardened the SNI↔IP network check against ASN-lookup rate limits.** It now
  decides on-network by **DNS membership first** (does the cover domain actually
  resolve to this server IP? — needs no external API), falling back to the ASN
  cross-check only for the large-CDN case (exact edge IP differs, same network).
  When neither can be established it stays silent rather than guessing — so the
  tell survives ip-api rate limiting and large CDNs don't false-positive.

### Fixed

- **Recommendations are de-duplicated, and detectability findings get the right
  fix.** Distinct verdicts that map to the same recommendation no longer print
  it twice. The broad `*SNI*` recommendation rule was also catching the new
  detectability verdicts (they mention "SNI"), wrongly advising an
  already-Reality server to "try Reality"; detectability/fingerprint findings
  now map to the correct fix — serve the cover on 443 and pick a cover on the
  server's own network or a large shared CDN.

## [0.6.1] - 2026-06-02

### Changed

- **Sharpened the TLS-fragmentation bypass recommendation to name current
  DPI-desync tools.** When probe 3 finds a block that's defeated by ClientHello
  fragmentation, the recommendation now points at concrete, current tools —
  **ByeDPI/ciadpi** (desktop SOCKS desync proxy), **ByeDPIAndroid** (Android),
  and **zapret / GoodbyeDPI** — and maps the escalation: start with TLS-record
  split (`--tlsrec`/`--split`, the method this probe confirms), and if a
  stricter DPI needs more, move to fake-packet + TTL (`--fake --ttl`) or
  `--disorder`. (No new probe / dependency — probe 3 already tests the
  fragmentation method; this just makes the fix actionable with today's tools.)

## [0.6.0] - 2026-06-02

### Changed

- **Probe 26 is now the single, final, comprehensive detectability score —
  active + passive.** Previously it synthesized only the active-probe signals
  (15 cover cert / 20 active-probe / 24 TLS parity); a server could score
  0/100 yet still be trivially fingerprintable by **passive** structure. Probe
  26 now also folds in two passive tells and always runs last:
  - the cover SNI served on a **non-standard port** (real cover sites use 443) → +10;
  - the server IP **not on the cover domain's network** (SNI↔IP ASN mismatch,
    via a direct ASN cross-check) → +10.

  Passive tells weigh less than active ones because they're false-positive-prone
  for a censor at scale (legit CDN / domain-fronting traffic mismatches too) —
  but they're real, and a targeted check catches them. The breakdown labels
  each signal `active ·` / `passive ·` with its points. So a perfectly
  active-cloaked server on a non-443 port whose IP isn't on the cover's network
  now reads **20/100 (moderate)** with the specific tells, instead of a
  misleading 0/100. JSON `xray_detectability` gains `port_standard` and
  `sni_ip_asn_match`. New test `tests/test_detectability.sh`. Suite now 17.

## [0.5.9] - 2026-06-02

### Fixed

- **Probe 14: replaced the dead Hetzner speed endpoint.** `speed.hetzner.de`
  no longer resolves (DNS NXDOMAIN), so the Hetzner stream reported "no data"
  on every run — pure noise (the best-of-N result was unaffected, but it
  looked like a failure). Swapped it for DataPacket
  (`lon.download.datapacket.com/100mb.bin`, HTTPS + Range, a provider-diverse
  CDN). The default pool is now Cloudflare / DataPacket / OVH, all verified
  reachable with Range support. Override anytime with `XRAY_SPEEDTEST_URLS`.

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
