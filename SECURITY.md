# Security Policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x     | :white_check_mark: |
| 1.x     | :x: (v1 wire format retired in 2.0.0; upgrade) |

## Reporting a vulnerability

**Do not open a public issue.** Use one of these private channels:

1. GitHub → **Security** tab → **Report a vulnerability** (private
   vulnerability reporting), or
2. Email the maintainer: `jeroperez2011@gmail.com`
   (address also listed in `library.json`).

Include: affected version/commit, what you did, what you observed, and
whether you believe credential keys, nonces, or wrapped keys are
exposed. Redact real secrets from everything you send.

Expect an acknowledgement within a week; fixes ship as a new release
with notes describing the impact (without disclosing exploit details
before users can upgrade).

## Scope

The threat model, key handling rules, replay requirements, RNG policy,
and known limitations (relay attacks, server trust root, MIFARE UID
assurance) are defined in [`docs/SECURITY.md`](docs/SECURITY.md) — read
it before auditing or changing authentication code. Host-side unit tests
pin behavior; they are not a security certification.
