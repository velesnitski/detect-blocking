# Contributing

Thanks for your interest. This project keeps the surface small on purpose —
single-file Bash script, no runtime dependencies beyond what ships with
macOS / a default Linux. Contributions should preserve that.

## Branch workflow

- **`main`** — stable, release-tagged. Always fast-forward-merged from `dev`.
- **`dev`** — active development. **All work lands here first.**
- **Topic branches** (`feature/...`, `fix/...`) — branch off `dev`, PR back
  into `dev`. Maintainers merge `dev` → `main` on each release.

Direct pushes to `main` are not used outside the merge step.

## Setting up

```sh
git clone https://github.com/velesnitski/detect-blocking.git
cd detect-blocking
git checkout dev
chmod +x detect_blocking.sh
bash tests/run.sh   # verify your environment works
```

## Style

- **Bash 3.2 compatible.** macOS still ships 3.2 by default — `mapfile`,
  associative arrays, `${var^^}`, etc. are off-limits.
- **`set -u` clean.** All state variables initialised before first read.
- **shellcheck clean** at `-S warning`. If a warning is intentional,
  add `# shellcheck disable=SCxxxx` with a one-line reason.
- **Portable POSIX where possible.** macOS BSD `nc` differs from Linux
  netcat — use the `_nc_tcp_probe` helper for any new TCP probe.
- **No external services** at runtime aside from those explicitly
  configured (DoH endpoint, control sites). Don't add telemetry.
- **No new mandatory deps.** Add to the optional list (jq / dig / perl /
  xxd) with a graceful fallback or skip.

## Tests

Every change must keep these green:

```sh
shellcheck -S warning detect_blocking.sh
bash -n detect_blocking.sh
bash tests/run.sh
```

CI runs the same on macOS and Ubuntu.

When you add a new probe or verdict, add a corresponding test in `tests/`.
Pattern:

- Smoke / happy-path tests assert against the IANA demo target
  (`www.example.com`).
- Negative scenarios use the `tests/fake_doh.py` fixture (or extend it) to
  simulate a hostile network locally — no external dependencies.

## Reporting bugs

Open an issue with:

1. OS and version (`sw_vers` on macOS, `lsb_release -a` on Linux).
2. Bash version (`bash --version`).
3. `openssl version` and `curl --version`.
4. Exact command and full `--log-file` output (or copy-paste of the
   failing section).

## Reporting security issues

See [SECURITY.md](SECURITY.md) — do not file public issues for security
problems.

## Commit messages

Prefer Conventional Commits:

```
fix(probe-dns): treat IPv4-mapped IPv6 as non-special
feat(openvpn): support TCP-only OpenVPN servers
docs(readme): clarify JA3 limitation
test(doh): add canary timeout regression
```

Not enforced, but appreciated.
