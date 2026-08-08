# Configuration

oneleak reads an optional `.oneleak.yaml` in your project root. The **Python API never auto-loads it** (`scan(config=...)` must be passed explicitly) — only the CLI auto-discovers it, so library calls stay side-effect-free.

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
  - ".oneleak/rules/company-rules.yaml"

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
| `allow.paths` | list of glob patterns | Files are still scanned, but findings under matching paths are dropped from the result — useful for intentional test fixtures you don't want failing CI. |
| `disabled_rules` | list of rule IDs | Rule IDs to skip entirely (built-in or custom), e.g. `openai-api-key`, `datadog-api-key`. |
| `severity_overrides` | mapping of rule ID to severity | Override a rule's default severity, e.g. downgrade a noisy rule from `high` to `low` instead of disabling it outright. Values must be one of `low`, `medium`, `high`, `critical`. |

## Path-scoping in custom rules

There is no per-rule `include_paths`/`exclude_paths` — path scoping is config-level only, via the top-level `exclude` / `allow.paths` fields above.

## Adopting oneleak on an existing codebase

Baseline files (snapshot today's findings, then fail only on *new* ones) are **not implemented yet**. Until they are, the practical ways to introduce oneleak to a repo that already has findings are:

- `--fail-on high` — let low/medium findings report without breaking the build, and tighten the threshold over time.
- `allow.paths` — exempt directories of known-intentional content (test fixtures, docs with example keys).
- `disabled_rules` / `severity_overrides` — silence or downgrade a specific noisy rule rather than a whole path.
- `# oneleak: allow <rule-id>` — a targeted, reviewable, line-level exemption. See [Custom Rules](rules.md#inline-suppression).
