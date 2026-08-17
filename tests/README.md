# Tests

The top level says **how** a test runs. Inside that, folders say **what** it covers.

| Folder | What runs |
|---|---|
| `unit/` | One function at a time. Never calls `scan()`. |
| `integration/` | The whole scan, in one process. |
| `e2e/` | The real `oneleaks` program, started as a separate process. |
| `test_properties.py` | Thousands of generated inputs, across several areas at once. |

## unit/

| File | Covers |
|---|---|
| `secrets/test_detectors.py` | Spotting a value because it looks random, or sits next to a word like "password" |
| `pii/test_validators.py` | The maths checks: card numbers, IBAN, social security, IP addresses |
| `test_config.py` | Reading `.oneleaks.yaml` |
| `test_models.py` | The data classes |
| `test_baseline.py` | Saving and reading a list of findings you have already reviewed |

`test_validators.py` sits under `pii/` because seven of its ten checks only
ever apply to personal data. Three of its tests cover `jwt`, which is a secret.
Splitting three tests into their own file to make the folders match exactly
would break up a file that reads well as one piece.

`test_config.py`, `test_models.py` and `test_baseline.py` are not about secrets
or personal data, so they sit directly in `unit/` rather than being forced into
one side or the other.

## integration/

| File | Covers |
|---|---|
| `secrets/test_secret_rules.py` | Does each key and token format get found |
| `pii/test_pii_rules.py` | Does each kind of personal data get found |
| `scanning/test_scanner.py` | Files, folders, text encodings, rules switched off per file type |
| `scanning/test_git.py` | Changed, staged and committed content |
| `output/test_sanitizer.py` | Blanking values out and putting them back |
| `output/test_sarif.py` | The SARIF report GitHub reads |
| `commands/test_cli.py` | The command line, called from inside Python |
| `commands/test_mcp_server.py` | The MCP tools, called directly |
| `false_positives/` | Safe content stays unreported |
| `test_custom_rules.py` | Loading your own rules from YAML, JSON or Python |

## e2e/

| File | Covers |
|---|---|
| `test_cli_subprocess.py` | Runs the real command in a real folder and checks exit codes and output |
| `test_mcp_stdio.py` | Starts the MCP server and talks to it the way a real client would |

These two have longer names than their `integration/` counterparts because
pytest needs every test file to have a different name.

## The two kinds of test case

**"We found the secret."** These build the fake key in code
(`"ghp_" + "a" * 36`) rather than writing it out, because a realistic-looking
key sitting in a file makes GitHub refuse the push.

**"We left the safe thing alone."** These live in
`integration/false_positives/`. The `clean_files/` folder holds real files that
oneleaks used to report by mistake, each with a note at the top saying what it
is for. The test scans them all and fails if anything is reported.

## Running them

```bash
make test                          # everything, with coverage
uv run pytest tests/unit           # one group
uv run pytest tests/integration/pii
```
