# Contributing to oneleak

## Setup

```bash
uv sync --all-extras
uv run pre-commit install
```

## Workflow

```bash
make lint        # ruff check
make format       # ruff format + ruff check --fix
make typecheck    # mypy
make test         # pytest
make ci           # all of the above
```

`make ci` must pass before opening a PR. `pre-commit` runs a subset of the same checks automatically on `git commit`, including `oneleak scan --staged` on the repo's own changes.

## Adding a built-in rule

Built-in secret rules live in `oneleak/builtin_rules/secrets.yaml`, PII rules in `oneleak/builtin_rules/pii.yaml`. See [Custom Rules](docs/rules.md) for the schema.

Every new rule needs:

- A **positive** test (a realistic-shaped match is detected)
- A **negative** test (an adjacent, non-matching string is not)
- A **boundary** test (off-by-one length, wrong prefix, etc.)

Add tests to `tests/test_scanner.py` (or a focused new test file for a large batch of rules).

**Never use real credentials in test fixtures** — even expired or revoked ones. Use clearly-fake values (`"a" * 20`, `sk-proj-` + filler, etc.), matching the existing test style.

## Priority tiers for overlap resolution

If two rules can match the same span, the higher `priority` wins (see `.plan/concepts.md` Section 8). Roughly:

```text
structural anchor (PEM/JWT/connection-string): 110
provider-specific pattern / PII:                100
keyword-anchored generic pattern:                70
generic credential assignment:                   50
entropy-only:                                    10
```

If your new rule is provider-specific (a fixed, identifiable prefix like `AKIA...`), use `100`. If it needs a keyword to disambiguate a generic-looking pattern, use `70`.

## Reporting a false positive / false negative

Add a regression test reproducing it (see "Adding a built-in rule" above) — false-positive regressions become permanent test cases, not just bug reports.

## Security issues

Do not open a public issue for a security vulnerability — see [SECURITY.md](SECURITY.md).
