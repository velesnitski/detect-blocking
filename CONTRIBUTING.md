# Contributing

Thanks for your interest. This project keeps the surface small on purpose —
single-file Bash script, no runtime dependencies beyond what ships with
macOS / a default Linux. Contributions should preserve that.

## Branch workflow

- **`main`** — stable, release-tagged. Always fast-forward-merged from `dev`.
- **`dev`** — active development. **All work lands here first.**
- **Topic branches** (`feature/…`, `fix/…`) — branch off `dev`, PR back
  into `dev`. Maintainers merge `dev` → `main` on each release.

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

## Implementation gotchas

### Binary packets and null bytes

Shell variables are C-strings — they truncate at the first `\x00`.
The IKE and OpenVPN probes build binary packets with `perl`. **Never**
store the output in a shell variable; pipe `perl` directly into `nc`:

```bash
# WRONG — packet is silently truncated at the first \x00
pkt=$(perl -e 'print "\x00\x01\x02"')
echo "$pkt" | nc …

# CORRECT — pipe directly
perl -e 'print "\x00\x01\x02"' | nc …
```

### Fractional-second timing

`date +%s` is integer-only (1 s resolution). RST injection events are
typically < 200 ms and would be invisible. Use:

```bash
{ time -p openssl s_client … </dev/null >"$tmp_out" 2>&1; rc=$?; } 2>"$tmp_time"
elapsed=$(awk '/^real/{print $2}' "$tmp_time")
```

Float comparison without `bc`:

```bash
awk "BEGIN{exit !($elapsed < 1.0)}"
```

### nc connect-timeout flag

macOS BSD `nc` uses `-G <seconds>` for connect timeout; Linux `nc` uses
`-w <seconds>`. Always go through `_nc_tcp_probe` — it branches on
`$OSTYPE` — rather than calling `nc` directly in a new probe.

### nslookup output

`nslookup` prints the resolver's own IP under `Address:` before the
target's answer. Use:

```bash
nslookup "$host" 2>/dev/null \
  | awk '/^Name:/{found=1} found && /^Address:/{print $2; exit}'
```

### mktemp portability

Always use exactly 6 trailing `X` characters — Linux requires it:

```bash
tmp=$(mktemp "${TMPDIR:-/tmp}/prefix.XXXXXX")
```

### stat portability

```bash
# GNU (Linux)
size=$(stat -c%s "$file" 2>/dev/null) \
  || size=$(stat -f%z "$file" 2>/dev/null)   # BSD (macOS)
```

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
