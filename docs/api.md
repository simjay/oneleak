# API Reference

The public surface is intentionally small. Everything below is importable directly from `oneleak` (e.g. `oneleak.Config`, `oneleak.RuleMatch`), except the `git` functions, which live under `oneleak.git`:

```python
import oneleak

oneleak.scan(...)
oneleak.sanitize(...)
oneleak.desanitize(...)
oneleak.git.scan_changed(...)
oneleak.git.scan_staged(...)
oneleak.git.scan_history(...)
```

## Scanning and sanitizing

::: oneleak.scanner.scan

::: oneleak.sanitizer.sanitize

::: oneleak.sanitizer.desanitize

## Git

::: oneleak.git.scan_changed

::: oneleak.git.scan_staged

::: oneleak.git.scan_history

## Configuration

`Config` mirrors `.oneleak.yaml` for callers who want to build one directly instead of loading a file. See [Configuration](configuration.md) for the YAML shape and field descriptions.

::: oneleak.config.Config

## Models

::: oneleak.models.Finding

::: oneleak.models.ScanResult

::: oneleak.models.SanitizedResult

::: oneleak.models.MappingEntry

::: oneleak.models.Rule

::: oneleak.models.RuleMatch

::: oneleak.models.PythonRule

::: oneleak.models.Category

::: oneleak.models.Severity

## Errors

Every error oneleak raises deliberately is an `OneleakError`. Catch that if you don't need to distinguish the subclass, or catch the specific one for finer-grained handling.

::: oneleak.errors.OneleakError

::: oneleak.errors.ConfigError

::: oneleak.errors.ScanError
