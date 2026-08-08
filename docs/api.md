# API Reference

The public surface is intentionally small:

```python
import oneleak

oneleak.scan(...)
oneleak.sanitize(...)
oneleak.desanitize(...)
oneleak.git.scan_changed(...)
oneleak.git.scan_staged(...)
```

::: oneleak.scanner.scan

::: oneleak.sanitizer.sanitize

::: oneleak.sanitizer.desanitize

::: oneleak.git.scan_changed

::: oneleak.git.scan_staged

## Models

::: oneleak.models.Finding

::: oneleak.models.ScanResult

::: oneleak.models.SanitizedResult

::: oneleak.models.MappingEntry

::: oneleak.models.Rule

::: oneleak.models.PythonRule
