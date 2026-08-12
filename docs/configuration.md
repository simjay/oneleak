# Configuration

oneleaks reads an optional `.oneleaks.yaml` in your project root. The **Python API never auto-loads it** (`scan(config=...)` must be passed explicitly). Only the CLI auto-discovers it, so library calls stay side-effect-free.

Unknown top-level fields are a hard error, not silently ignored.

```yaml
version: 1

exclude:
  - "node_modules/**"
  - "vendor/**"

pii:
  email: true
  phone: true
  ssn: true
  credit_card: true
  ipv4: false   # not every user considers IP addresses sensitive
  ipv6: false
  iban: true

rule_paths:
  - ".oneleaks/rules/company-rules.yaml"

allow:
  paths:
    - "tests/fixtures/**"

disabled_rules:
  - datadog-api-key

severity_overrides:
  datadog-api-key: low
```

## Fields

| Field | Type | Description |
|---|---|---|
| `version` | int | Config schema version. Currently `1`. |
| `exclude` | list of glob patterns | Files matching these patterns are never read/scanned during directory scans. `.git/`, `node_modules/`, `.venv/`, `venv/`, `__pycache__/`, `dist/`, `build/` are always excluded regardless of this list. |
| `pii` | mapping of detector name to bool | Enable/disable individual PII detectors: `email`, `phone`, `ssn`, `credit_card`, `ipv4`, `ipv6`, `iban`. Unknown keys are rejected. |
| `rule_paths` | list of paths | Additional YAML/JSON rule files to load alongside the built-ins. |
| `allow.paths` | list of glob patterns | Files are still scanned, but findings under matching paths are dropped from the result. Useful for intentional test fixtures you don't want failing CI. |
| `disabled_rules` | list of rule IDs | Rule IDs to skip entirely (built-in or custom), e.g. `openai-api-key`, `datadog-api-key`. |
| `severity_overrides` | mapping of rule ID to severity | Override a rule's default severity, e.g. downgrade a noisy rule from `high` to `low` instead of disabling it outright. Values must be one of `low`, `medium`, `high`, `critical`. |

## Path-scoping in custom rules

There is no per-rule `include_paths`/`exclude_paths`. Path scoping is config-level only, via the top-level `exclude` / `allow.paths` fields above.

## Adopting oneleaks on an existing codebase

A baseline is the primary tool for this: snapshot today's findings, then fail the build only on *new* ones. See [Baselines](#baselines) below. The other options still apply and compose well with a baseline:

- `--fail-on high`: let low/medium findings report without breaking the build, and tighten the threshold over time.
- `allow.paths`: exempt directories of known-intentional content (test fixtures, docs with example keys).
- `disabled_rules` / `severity_overrides`: silence or downgrade a specific noisy rule rather than a whole path.
- `# oneleaks: allow <rule-id>`: a targeted, reviewable, line-level exemption. See [Custom Rules](rules.md#inline-suppression).

## Baselines

A baseline file records `(rule_id, path, fingerprint)` for findings a team has already seen and decided not to block on yet. Turn oneleaks on for a repo that already has findings without a blocking flag-day: snapshot what's there today, then only new findings fail the build going forward. Baselines never contain raw values, only rule IDs, paths, and HMAC fingerprints, so they're safe to commit, and must be committed for the whole team (and CI) to see the same accepted findings.

Create or refresh a baseline:

```bash
oneleaks scan . --baseline .oneleaks-baseline.json --update-baseline
```

This overwrites the file with a full snapshot of the current run's findings (not a merge): a finding that's no longer present because the secret was fixed simply drops out on the next update, so accepted debt shrinks as it's paid down instead of accumulating forever.

Check against it on later runs (CI, pre-commit) by omitting `--update-baseline`:

```bash
oneleaks scan . --baseline .oneleaks-baseline.json --fail-on high
```

Only findings *not* in the baseline are reported and count toward the exit code.

### The stable-key requirement

Baseline matching relies on `Finding.fingerprint`, which is an HMAC keyed off a random value generated fresh **per process** unless `ONELEAKS_FINGERPRINT_KEY` is set. Without a stable key, fingerprints computed today would never match fingerprints computed tomorrow (or in CI, or on a teammate's machine), so the baseline would silently never match anything. `oneleaks scan --baseline` refuses to run at all until `ONELEAKS_FINGERPRINT_KEY` is set, rather than fail that way silently.

The same key value must be used everywhere the baseline is read or written: every developer's machine and CI. Treat it like any other shared secret, a password manager entry or a CI secret store, **never committed to the repo alongside the baseline it protects** (a leaked key makes every fingerprint in the baseline reversible by brute force for low-entropy values like SSNs, see [How Scanning & Sanitization Work](architecture.md#fingerprinting)).

### Baselines are a CLI concept

`--baseline` is a CLI flag, not a `.oneleaks.yaml` field or a `Config` option available from the Python API. This is deliberate: a baselined finding is still a real secret sitting in the code, just one already triaged and accepted as debt, and it should never stop `sanitize()` from redacting it. Config-level filters like `allow.paths` apply uniformly to `scan()`, git scanning, *and* `sanitize()` by design (an allowlisted path is treated as genuinely not sensitive), so routing baselines through that same shared pipeline would have silently let a "known" secret leak into sanitized output. Keeping `--baseline` CLI-only avoids that trap.
