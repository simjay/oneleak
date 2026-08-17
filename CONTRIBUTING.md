# Contributing to oneleaks

## Setup

```bash
uv sync --all-extras
uv run pre-commit install
```

## Workflow

```bash
make format   # ruff format + ruff check --fix (mutating)
make lint     # ruff check + ruff format --check + mypy (verify only)
make test     # pytest, with coverage
make ci       # lint + test + docs-build (what CI runs)
```

`make ci` must pass before opening a PR. `pre-commit` runs a subset of the same checks automatically on `git commit`, including `oneleaks scan --staged` on the repo's own changes.

## Adding a built-in rule

Built-in secret rules live in `oneleaks/builtin_rules/secrets.yaml`, PII rules in `oneleaks/builtin_rules/pii.yaml`. See [Custom Rules](docs/guides/rules.md) for the schema.

Every new rule needs:

- A **positive** test (a realistic-shaped match is detected)
- A **negative** test (an adjacent, non-matching string is not)
- A **boundary** test (off-by-one length, wrong prefix, etc.)

Add the tests to `tests/integration/secrets/test_secret_rules.py` or `tests/integration/pii/test_pii_rules.py`, whichever the rule belongs to. See "Where tests go" below.

**Never use real credentials in test fixtures**, even expired or revoked ones. Use clearly-fake values (`"a" * 20`, `sk-proj-` + filler, etc.), matching the existing test style.

## When two rules match the same text

The rule with the higher `priority` wins (see [docs/advanced/architecture.md](docs/advanced/architecture.md#4-overlap-resolution)). Roughly:

```text
recognised by its own layout (PEM/JWT/URL):    110
recognised by a known prefix / personal data:  100
recognised by a nearby word:                   70
looks like a password being set:               50
just looks random:                             10
```

If your rule looks for a fixed prefix like `AKIA...`, use `100`. If it needs a nearby word to tell it apart from ordinary text, use `70`.

## Where tests go

There are two kinds of test, and they are kept in different places.

**Tests that a secret IS found** go next to the rules they test:
`tests/integration/secrets/test_secret_rules.py` for keys and tokens,
`tests/integration/pii/test_pii_rules.py` for personal data. Each of those files has two halves: the rule list loads, and the
rules find what they are meant to find. They build the fake secret in code
(`"sk-proj-" + "a" * 24`) instead of writing it out in full.

That is not a style preference. A file containing realistic-looking keys makes
GitHub refuse the push, so writing the key out in full can block your commit. Some existing tests have a comment saying exactly this. Please do not
"tidy" them into single strings.

**Tests that something is NOT flagged** go in
`tests/integration/false_positives/clean_files/`. Each file
in that folder is safe content that oneleaks used to report by mistake, copied
from a real project and cut down to the smallest version that still shows the
problem. The test beside it scans every file in that folder and checks nothing is
reported.

`tests/integration/scanning/` is for the machinery itself: reading files, text
encodings, which rules get switched off in which kinds of file, and so on. It
is not for testing individual rules.

`tests/README.md` lists every folder and what belongs in it.

To add a file to `tests/integration/false_positives/clean_files/`:

1. Cut the file down to the smallest version that still triggers the wrong report.
2. Put a note at the top starting `What this catches:`, saying in plain words
   what mistake the file guards against. JSON files use a `"_why"` key instead,
   since JSON has no comments. A test checks the note is there, because that
   note is what explains a future failure to whoever hits it.
3. Check that `pytest tests/integration/false_positives` fails before your fix
   and passes after.

Two things to know:

- These files are skipped by the linter. They are copies of real files, and some
  of them contain code that does not lint.
- This repo's own `.oneleaks.yaml` allows everything under `tests/`, so running
  `oneleaks scan .` will not notice a mistake in one of these files. The pytest
  run is the only thing checking them.

## Reporting a wrong result

Add a test for it. If oneleaks reported something that was not a secret, add a
file to `tests/integration/false_positives/clean_files/`. If it missed a real
secret, add a test next to the
rule's existing ones. Either way it becomes a permanent test, not just a bug
report.

## Security issues

Do not open a public issue for a security vulnerability. See [SECURITY.md](SECURITY.md).
