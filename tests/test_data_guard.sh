#!/usr/bin/env bash
#
# tests/test_data_guard.sh — this repo is PUBLIC; prose and fixtures must not carry
# one operator's run.
#
# Three structural layers that are ALWAYS on, plus the existing configurable deny-list
# in scripts/secret-scan.sh:
#
#   1. ADDRESSES — every routable address in a tracked file must come from the
#      private / documentation ranges, or be a baseline resolver the tool itself
#      declares. A bright line beats a judgement call: "is this address real?"
#      invites an argument, "is it from RFC 5737?" does not.
#   2. MAGNITUDES — scale is described qualitatively. Prose written while working
#      against a running fleet absorbs that run's numbers ("28 node(s)", "27/27"),
#      and those are one execution's output, not facts about this codebase. They
#      date immediately, a reader cannot verify them, and the argument reads the
#      same without them. Worse here than in most repos: a node count plus a
#      finding is a statement about how exposed a specific fleet is.
#   3. COUNTRY FOOTPRINT — two or more ISO-2 codes in sequence is a run's output.
#      A lone code is fine; it appears as a parameter throughout.
#
# Deliberately scoped to OBSERVED magnitudes. Configured thresholds and caps
# ("probes 0-27", "capped at 8 parallel") are design facts and must keep passing.
#
# This file is exempt from its own rules and must be: it carries deliberately
# invalid samples, which is how each rule proves it is not vacuous. Scanning them
# would make the guard fail on its own evidence.
set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$SCRIPT_DIR/detect_blocking.sh"
SELF="$(basename -- "${BASH_SOURCE[0]}")"
fail() { printf 'FAIL: %s\n' "$1" >&2; exit 1; }

cd "$SCRIPT_DIR" || fail "cannot enter repo root"

# ---------------------------------------------------------------------------
# Layer 1 — addresses
# ---------------------------------------------------------------------------
# The allowed set is: non-global space, plus addresses this tool DECLARES as
# baselines. The declared ones are parsed out of detect_blocking.sh rather than
# retyped here, so the guard cannot drift from what the tool actually queries.
declared_resolvers() {
  # BASELINE_IPS / DOH_URL defaults, plus the one.one.one.one canary answers the
  # DoH-integrity check compares against (1.1.1.1 / 1.0.0.1) and Google's
  # secondary. Anything else must justify itself as documentation space.
  sed -n 's/.*BASELINE_IPS="\${BASELINE_IPS:-\${BASELINE_IP:-\([^}]*\)} \([^"]*\)}".*/\1 \2/p' "$SCRIPT"
  printf '1.0.0.1 8.8.4.4\n'
}

# A tiny, explicit set kept small on purpose so the exemption cannot quietly grow:
#   1.2.3.4 / 5.6.7.8 — the conventional invented pair, used as opaque tokens.
#   8.0.0.0, 8.47.69.0, 8.6.112.0 — the sinkhole answers tests/fake_doh.py serves.
#     8.0.0.0/8 sinkholing is published DPI behaviour, not fleet data; the fixture
#     needs a *recognisable* sinkhole shape for the "DoH path is compromised"
#     verdict to be exercised at all.
DOC_PLACEHOLDERS='1.2.3.4 5.6.7.8 8.0.0.0 8.47.69.0 8.6.112.0'

python3 - "$SELF" "$DOC_PLACEHOLDERS" "$(declared_resolvers | tr '\n' ' ')" <<'PY' || exit 1
import ipaddress, re, subprocess, sys, pathlib

self_name, placeholders, declared = sys.argv[1], set(sys.argv[2].split()), set(sys.argv[3].split())
ALLOWED = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "0.0.0.0/8", "192.0.2.0/24", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
)]
IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

def non_global(tok):
    try:
        return any(ipaddress.ip_address(tok) in n for n in ALLOWED)
    except ValueError:
        return True          # a version string like 1.2.3.4.5 fragment, not an address

if not declared:
    print("FAIL: could not parse any declared baseline resolver from detect_blocking.sh "
          "— the guard would silently allow nothing and pass", file=sys.stderr)
    sys.exit(1)

violations = []
for rel in subprocess.run(["git", "ls-files"], capture_output=True, text=True).stdout.split():
    p = pathlib.Path(rel)
    if not p.is_file() or p.name == self_name:
        continue
    try:
        text = p.read_text()
    except (UnicodeDecodeError, OSError):
        continue
    for n, line in enumerate(text.splitlines(), 1):
        for tok in IP.findall(line):
            if non_global(tok) or tok in declared or tok in placeholders:
                continue
            violations.append(
                f"  {rel}:{n} — {tok!r} is routable and is neither documentation "
                f"space nor a resolver this tool declares")
if violations:
    print("FAIL: real-looking addresses in tracked files:", file=sys.stderr)
    print("\n".join(violations), file=sys.stderr)
    print("  Use 192.0.2.x / 198.51.100.x / 203.0.113.x (RFC 5737).", file=sys.stderr)
    sys.exit(1)

# --- not vacuous: the rule must reject something just outside each range ---
assert non_global("192.0.2.7") and non_global("10.1.2.3") and non_global("127.0.0.1")
assert not non_global("172.15.0.1"), "just outside RFC 1918 must fail"
assert not non_global("203.0.114.9"), "just outside TEST-NET-3 must fail"
assert not non_global("203.0.113.6"), "an arbitrary routable address must fail"
PY

# ---------------------------------------------------------------------------
# Layer 2 — magnitudes
# ---------------------------------------------------------------------------
# Scoped to docs, tests and the script's own comments: every magnitude leak found
# in this repo's audit sat in one of the three.
SELF="$SELF" python3 - <<'PY' || exit 1
import os, re, subprocess, sys, pathlib

SELF = os.environ["SELF"]
# Each pattern is an observed count of *fleet units*. Probe indices, ports and
# parallelism caps are design facts and deliberately do not match.
PATTERNS = [
    (re.compile(r"\d+[ -]node\(s\)", re.I),                      "an observed node count"),
    (re.compile(r"\b\d+[ -]nodes?\b", re.I),                     "an observed node count"),
    (re.compile(r"fleet of \d+", re.I),                          "a real fleet size"),
    (re.compile(r"\b\d+/\d+ (nodes|hosts|servers)\b", re.I),     "an observed fleet ratio"),
    (re.compile(r"\b\d{2,} (hosts|servers|nodes)\b", re.I),      "a fleet-scale count"),
]

# A README must be able to SHOW the tool's output, and that output contains counts
# by its very nature. So one narrow exemption: a fenced block preceded by the marker
# below is treated as illustrative. It buys nothing on its own — the numbers inside
# still have to be invented — it only stops the guard from firing on a sample.
MARKER = "<!-- data-guard: illustrative sample -->"

def scan(path):
    """Yield (lineno, why, text) for every observed magnitude outside a marked block."""
    exempt_fence = False
    armed = False
    for n, line in enumerate(path.read_text().splitlines(), 1):
        stripped = line.strip()
        if stripped == MARKER:
            armed = True
            continue
        if stripped.startswith("```"):
            if armed:                      # opening fence of a marked block
                exempt_fence, armed = True, False
            elif exempt_fence:             # its closing fence
                exempt_fence = False
            continue
        if exempt_fence:
            continue
        for rx, why in PATTERNS:
            m = rx.search(line)
            if m:
                yield n, why, m.group(0)
                break

TARGETS = ["README.md", "CHANGELOG.md", "SECURITY.md", "CONTRIBUTING.md",
           "tests/*", "detect_blocking.sh", "scripts/*"]
listed = subprocess.run(["git", "ls-files", *TARGETS],
                        capture_output=True, text=True).stdout.split()

violations = []
scanned = 0
for rel in listed:
    p = pathlib.Path(rel)
    if p.name == SELF or not p.is_file():
        continue
    try:
        found = list(scan(p))
    except (UnicodeDecodeError, OSError):
        continue
    scanned += 1
    for n, why, tok in found:
        violations.append(f"  {rel}:{n} — {tok!r} is {why}")

# A guard that scans nothing reads green. This one refuses to.
if scanned < 20:
    print(f"FAIL: magnitude guard only scanned {scanned} file(s) — the target list "
          "is broken, so a pass here would mean nothing", file=sys.stderr)
    sys.exit(1)

if violations:
    print("FAIL: observed fleet magnitudes — describe scale qualitatively instead:",
          file=sys.stderr)
    print("\n".join(violations), file=sys.stderr)
    sys.exit(1)

# --- not vacuous: every banned shape must fire ---
for shape in ("27 node(s): 0-6,8-27", "a live 16-node CDN-fronted fleet",
              "fleet of 40 servers", "fleet root cause (27/27 nodes)",
              "scanned 140 hosts", "a 5-node subscription"):
    assert any(rx.search(shape) for rx, _ in PATTERNS), f"would not catch: {shape}"
# --- ...and design facts must not ---
for ok in ("probes 0-27 run by default", "capped at 8 parallel workers",
           "exit code 2 means blocked", "TLS 1.3 cipher parity",
           "batch defaults to 3"):
    assert not any(rx.search(ok) for rx, _ in PATTERNS), f"false-positive on: {ok}"

# --- the marker must exempt ONLY the block it introduces ---
import tempfile
with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as fh:
    fh.write(f"{MARKER}\n```\n7 node(s) inside a marked block\n```\n"
             "9 node(s) after it, unmarked\n")
    probe = pathlib.Path(fh.name)
found = [n for n, _, _ in scan(probe)]
probe.unlink()
assert found == [5], f"marker must exempt only its own fence, got lines {found}"
PY

# ---------------------------------------------------------------------------
# Layer 3 — country footprint (docs only, as upstream)
# ---------------------------------------------------------------------------
ISO2='AD AE AF AG AL AM AO AR AT AU AZ BA BD BE BG BH BR BY CA CH CL CN CO CR CY CZ DE DK DO DZ EC EE EG ES ET FI FR GB GE GH GR HK HR HU ID IE IL IN IQ IR IS IT JM JO JP KE KG KH KR KW KZ LB LK LT LU LV MA MD ME MK MN MT MX MY NG NL NO NP NZ OM PA PE PH PK PL PT PY QA RO RS RU SA SE SG SI SK TH TJ TM TN TR TW UA US UY UZ VE VN ZA'

python3 - "$ISO2" <<'PY' || exit 1
import re, subprocess, sys, pathlib
iso2 = set(sys.argv[1].split())
seq = re.compile(r"\b([A-Z]{2})\b\s*[/,]\s*\b([A-Z]{2})\b")
docs = subprocess.run(["git", "ls-files", "README.md", "CHANGELOG.md", "SECURITY.md",
                       "CONTRIBUTING.md"], capture_output=True, text=True).stdout.split()
violations = []
for rel in docs:
    p = pathlib.Path(rel)
    if not p.is_file():
        continue
    for n, line in enumerate(p.read_text().splitlines(), 1):
        for m in seq.finditer(line):
            if m.group(1) in iso2 and m.group(2) in iso2:
                violations.append(f"  {rel}:{n} — {m.group(0)!r} discloses a country footprint")
if violations:
    print("FAIL: country-footprint disclosure:", file=sys.stderr)
    print("\n".join(violations), file=sys.stderr)
    sys.exit(1)
# not vacuous
assert seq.search("nodes spanning RU / IR"), "country rule must fire on a real pair"
PY

echo "PASS: data guard — addresses from documentation ranges only, scale described qualitatively, no country footprint"
