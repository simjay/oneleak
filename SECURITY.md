# Security Policy

oneleak handles sensitive data (secrets and PII) by design, so security issues in it are taken seriously.

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.** A public issue discloses the problem before a fix is available.

Instead, report it privately via [GitHub Security Advisories](https://github.com/simjay/oneleak/security/advisories/new) for this repository. Include:

- A description of the issue and its impact (e.g. "a crafted rule file can execute code," "sanitize() can leak a raw value in output X")
- Steps to reproduce
- Affected version(s)

You should receive an acknowledgment within a few days.

## What counts as a security issue here

Given oneleak's purpose, these are treated as security issues even if they'd be "just bugs" elsewhere:

- Any way for `scan()` output (findings, JSON, previews, logs, errors) to leak a raw sensitive value it detected
- Any way for a declarative YAML/JSON rule file to execute arbitrary code
- Any way for `.oneleak.yaml` to trigger code execution or network access
- Any way for a mapping file / fingerprint to be reversed to a raw value without the caller's key
- ReDoS (regular-expression denial of service) in any built-in rule pattern

## Supported versions

Only the latest released version is supported with security fixes while oneleak is pre-1.0.
