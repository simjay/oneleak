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

sanitize:
  mode: typed
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
| `sanitize` | mapping | Sanitization options (currently just `mode: typed`, the only supported mode). |

## Path-scoping in custom rules

Individual rules accept `include_paths` / `exclude_paths` fields in their YAML/JSON definition, but as of v0.1 these are parsed and stored, not yet enforced during scanning — tracked in `.plan/v1-roadmap.md`. Use the top-level `exclude` / `allow.paths` config fields above for path scoping today.
