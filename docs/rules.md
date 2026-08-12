# Custom Rules

Three rule sources compose into one registry:

| Source | Written as | Auto-loadable? |
|---|---|---|
| Built-in | YAML shipped with oneleaks | Always on |
| YAML / JSON | Data | Yes, via `rule_paths` or `rules=[...]` |
| Python | Code | **No**, explicit registration only |

Rule IDs must be unique across all three. A duplicate, including one colliding with a built-in, raises `ConfigError` at load time.

## YAML rules

```yaml
rules:
  - id: company-api-key
    category: secret        # secret | pii | sensitive
    type: company_api_key
    severity: high          # low | medium | high | critical
    pattern: '\bCOMPANY_[A-Za-z0-9]{32}\b'
    keywords:
      - token
      - api_key
    priority: 100
```

```python
result = oneleaks.scan(text, rules=["company-rules.yaml"])
```

### Fields

| Field | Required | Description |
|---|---|---|
| `id` | yes | Unique identifier. |
| `category` | yes | `secret`, `pii`, or `sensitive`. |
| `type` | yes | Finding type. Drives the placeholder name: `company_api_key` → `<COMPANY_API_KEY_1>`. |
| `severity` | yes | `low`, `medium`, `high`, or `critical`. |
| `pattern` | one of these two | Regex. See the named-group tip below. |
| `keywords` | one of these two | Words that must appear nearby for a match to count. |
| `validator` | optional | `luhn`, `iban`, `ssn`, `ipv4`, `ipv6`, `jwt`, or `aba_routing`. |
| `priority` | optional | Overlap-resolution tier. Higher wins a contested span. |

!!! tip "Capture just part of a match with a `value` group"

    Name a group `value` and the finding spans only that group, not the whole match.

    That's how `connection-string-credential` flags only the password inside a URL, rather than the entire connection string.

**Priority defaults:** 80 with a pattern, 60 for keyword-only. For context, built-in rules use 90–110, generic assignment uses 50, and entropy uses 10. See [overlap resolution](architecture.md#4-overlap-resolution).

**Keywords** must appear within roughly 60 characters before the match, on the same line. They reduce false positives on generic patterns. They do not make matching faster.

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

For logic a regex cannot express, such as a proprietary checksum or an internal ID format:

```python
import oneleaks
from oneleaks import PythonRule, RuleMatch

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

result = oneleaks.scan(text, rules=[EmployeeIdRule()])
```

!!! danger "Python rules are never auto-loaded"

    They come only from an explicit `rules=[...]` argument in your own code, never from repository config.

    Silently loading executable rules from a file anyone could commit would be a remote-code-execution vector in your CI.

    Declarative YAML and JSON rules can never execute code. That's a hard security boundary, not a convention.

## Inline suppression

```python
TOKEN = "fake-secret"  # oneleaks: allow
TOKEN = "fake-secret"  # oneleaks: allow generic-secret
```

Bare `allow` suppresses every rule on that line. Adding a rule ID scopes it to just that rule, so anything else on the line still reports.

For path- and rule-level exemptions, see [Configuration](configuration.md).

## Path scoping

There is no per-rule `include_paths` or `exclude_paths`. Scoping is config-level only, through `exclude` and `allow.paths` in [Configuration](configuration.md#fields).
