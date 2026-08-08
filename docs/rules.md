# Custom Rules

Three rule sources compose into one registry: built-in rules, declarative YAML/JSON rules, and Python rules. Rule IDs must be unique across all three — a duplicate ID (including colliding with a built-in) raises a `ConfigError` at load time.

## YAML rules

```yaml
rules:
  - id: company-api-key
    category: secret        # secret | pii | sensitive
    type: company_api_key
    severity: high           # low | medium | high | critical
    pattern: '\bCOMPANY_[A-Za-z0-9]{32}\b'
    keywords:
      - token
      - api_key
    priority: 100
```

```python
result = oneleak.scan(text, rules=["company-rules.yaml"])
```

| Field | Required | Description |
|---|---|---|
| `id` | yes | Unique rule identifier. |
| `category` | yes | `secret`, `pii`, or `sensitive`. |
| `type` | yes | Finding type, e.g. `company_api_key`. Drives the sanitized placeholder name (`<COMPANY_API_KEY_1>`). |
| `severity` | yes | `low`, `medium`, `high`, or `critical`. |
| `pattern` | one of pattern/keywords | Regex. Use a named group `value` to have the finding span only that group (e.g. matching just the password portion of a connection string) instead of the whole match. |
| `keywords` | optional | If present, a match must also have one of these keywords nearby (same line, ~60 chars back) to count — reduces false positives on generic patterns. |
| `validator` | optional | Name of a built-in validator to confirm the match: `luhn`, `iban`, `ssn`, `ipv4`, `ipv6`, `jwt`. |
| `priority` | optional | Overlap-resolution tier — higher wins when two rules match the same span. Defaults to 80 if a pattern is present, 60 if keyword-only. Built-in provider/structural rules use 90–110; the built-in generic-assignment and entropy detectors use 50 and 10 respectively. |
| `include_paths` / `exclude_paths` | optional | Parsed, but **not yet enforced** as of v0.1 — see `.plan/v1-roadmap.md`. |

Declarative YAML/JSON rules can never execute arbitrary code — this is a hard security boundary, not just a convention.

## JSON rules

Same shape, JSON-encoded:

```json
{
  "rules": [
    {
      "id": "company-token",
      "category": "secret",
      "type": "company_token",
      "severity": "high",
      "pattern": "\\bCTOK_[A-Za-z0-9]{8}\\b"
    }
  ]
}
```

## Python rules

For detection logic that can't be expressed as a regex (a proprietary checksum, an internal ID format):

```python
from oneleak import PythonRule
from oneleak.models import RuleMatch

class EmployeeIdRule(PythonRule):
    id = "employee-id"
    category = "pii"
    type = "employee_id"
    severity = "medium"

    def detect(self, text):
        idx = text.find("EMP-")
        if idx == -1:
            return []
        return [RuleMatch(start=idx, end=idx + 10)]
        # a plain (start, end) tuple works too

result = oneleak.scan(text, rules=[EmployeeIdRule()])
```

Python rules are **never** auto-loaded from repository config — only from an explicit `rules=[...]` argument in your own code. A rule this powerful being silently pulled in from a file anyone could add to a repo would be a real remote-code-execution vector; requiring explicit registration is a hard security boundary, matching the constraint on YAML/JSON rules above.

## Inline suppression

```python
TOKEN = "fake-secret"  # oneleak: allow
TOKEN = "fake-secret"  # oneleak: allow generic-secret   (scoped to one rule ID)
```

See [Configuration](configuration.md) for path/rule-level exclusions and allowlisting.
