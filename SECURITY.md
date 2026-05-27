# Security Policy

## Reporting a vulnerability

**Do not open a public issue for security problems.**

Use GitHub's [private security advisory](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
feature on this repository, or email the maintainers at the contact in the
repository's profile.

When reporting include:

- The version of `detect-blocking` (`./detect_blocking.sh --version`).
- A minimal reproducer (config / env vars / target conditions).
- The observed vs. expected behaviour.
- Why you believe this is a security issue rather than a bug.

You should expect an acknowledgement within 7 days. Disclosure timing is
coordinated with the reporter; the default window is 90 days.

## Scope

This tool is a **locally-run, passive** network diagnostic. It does not
exploit, scan, or actively probe systems beyond the **single target** the
user configures plus a small fixed set of public reference endpoints
(Cloudflare DoH, baseline IP reachability, declared control sites).

Examples of what we consider in-scope:

- A probe sending unexpected payloads to the target (beyond IKE / OpenVPN
  protocol headers that the script documents).
- A way for a malicious config file or env var to achieve arbitrary
  command execution.
- A way for a hostile DoH response or DNS answer to escape the parsers
  (`_parse_doh_ips`, `_ipv4_lines`).
- Sensitive data accidentally written to log files at any log level.

Out of scope:

- The fact that the script reveals censorship state to anyone who can read
  its output. That's the point.
- Reports that the script "could be misused" — the tool runs only against
  what the operator configures. See "Intended use" in the README.

## Responsible use

Probes target one VPN endpoint that the user explicitly configures plus a
small set of public reference endpoints. Run it only against infrastructure
you operate or have explicit authorization to test.
