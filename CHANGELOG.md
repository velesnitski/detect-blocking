# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
  (e.g. `example.net`) is not flagged. JSON `xray_detectability.cover_obscure`.

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
