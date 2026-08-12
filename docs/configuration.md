# Configuration

oneleaks reads an optional `.oneleaks.yaml` from your project root.

!!! note "Only the CLI auto-discovers it"

    The Python API never loads config on its own. You pass it explicitly with `scan(config=...)`, so library calls stay side-effect-free.

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
  ipv4: false   # not everyone considers IP addresses sensitive
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
| `exclude` | globs | Files never read during directory scans. |
| `pii` | name → bool | Turn individual PII detectors on or off. Unknown keys are rejected. |
| `rule_paths` | paths | Extra YAML/JSON rule files to load alongside the built-ins. |
| `allow.paths` | globs | Files are still scanned, but findings under these paths are dropped. |
| `disabled_rules` | rule IDs | Rules to skip entirely, built-in or custom. |
| `severity_overrides` | rule ID → severity | Change a rule's severity. One of `low`, `medium`, `high`, `critical`. |

Some directories are **always** excluded regardless of your `exclude` list:

```text
.git/  node_modules/  .venv/  venv/  __pycache__/  dist/  build/
.pytest_cache/  .mypy_cache/  .ruff_cache/  .hypothesis/
```

Available `pii` keys: `email`, `phone`, `ssn`, `credit_card`, `ipv4`, `ipv6`, `iban`, `imei`, `mac_address`, `bank_routing_number`.

!!! tip "`exclude` and `allow.paths` are not the same"

    `exclude` skips reading the file at all. `allow.paths` scans it, then discards the findings.

    Use `exclude` for noise you never want touched. Use `allow.paths` for intentional content like test fixtures.

    One caveat: `exclude` only applies to directory scans. Git-based scans (`--changed`, `--staged`, `--history`) consult `allow.paths` only.

## Path scoping

There's no per-rule `include_paths` or `exclude_paths`. Path scoping is config-level only, through `exclude` and `allow.paths`.

## Adopting oneleaks on an existing codebase

A [baseline](#baselines) is the primary tool: snapshot today's findings, then fail only on new ones.

These compose well alongside it:

- **`--fail-on high`**: let low and medium findings report without breaking the build, then tighten over time.
- **`allow.paths`**: exempt directories of known-intentional content.
- **`disabled_rules` / `severity_overrides`**: silence or downgrade one noisy rule instead of a whole path.
- **`# oneleaks: allow <rule-id>`**: a targeted, reviewable, line-level exemption. See [Custom Rules](rules.md#inline-suppression).

## Baselines

A baseline records `(rule_id, path, fingerprint)` for findings your team has seen and decided not to block on yet.

It lets you turn oneleaks on for a repo that already has findings, with no flag-day: snapshot what exists today, and only new findings fail the build.

Baselines store **no raw values**, only rule IDs, paths, and HMAC fingerprints. They're safe to commit, and *should* be committed so the whole team and CI agree on what's accepted.

**Create or refresh:**

```bash
oneleaks scan . --baseline .oneleaks-baseline.json --update-baseline
```

This writes a full snapshot, not a merge. A finding that's gone because someone fixed the secret simply drops out on the next update, so accepted debt shrinks as it's paid down.

**Check against it** by omitting `--update-baseline`:

```bash
oneleaks scan . --baseline .oneleaks-baseline.json --fail-on high
```

Only findings *not* in the baseline are reported or affect the exit code.

### The stable-key requirement

Baseline matching uses `Finding.fingerprint`, an HMAC keyed off a random value generated **fresh per process**, unless `ONELEAKS_FINGERPRINT_KEY` is set.

Without a stable key, today's fingerprints would never match tomorrow's, or CI's, or a teammate's. The baseline would silently match nothing.

So `--baseline` refuses to run until the variable is set, rather than failing quietly.

!!! danger "Never commit the key next to the baseline"

    Use the same key everywhere the baseline is read or written, and store it like any other shared secret: a password manager, or a CI secret store.

    A leaked key makes every fingerprint in the baseline brute-forceable for low-entropy values like SSNs. See [Fingerprinting](architecture.md#fingerprinting).

### Baselines are a CLI concept

`--baseline` is a CLI flag only. It is not a `.oneleaks.yaml` field or a `Config` option.

That's deliberate. A baselined finding is **still a real secret** sitting in the code. Triaged, but not safe.

Config filters like `allow.paths` apply uniformly to `scan()`, git scanning, *and* `sanitize()`, because an allowlisted path is treated as genuinely not sensitive. Routing baselines through that same pipeline would have let a known secret leak into sanitized output.

Keeping `--baseline` CLI-only avoids that trap.
