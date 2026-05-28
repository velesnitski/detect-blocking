# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Configuration precedence: CLI arg > env var > `detect_blocking.conf`
  > built-in default.
- Optional logging to file with timestamps, ANSI-stripping, and 10MB
  rotation; `--quiet` flag for cron use.
- `--version`, `--help` flags.
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
