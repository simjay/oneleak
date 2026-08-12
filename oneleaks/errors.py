"""Exception hierarchy, plus helpers for turning low-level failures into clean
oneleaks errors.

Error messages must never dump raw sensitive content, and, just as
importantly for anyone running oneleaks in CI, they must never surface a raw
Python exception type. `cli.py::main()` renders any `OneleaksError` as a plain
`error: <message>`. Anything else falls through to a generic handler that
prints the exception class name. So raising the right type here *is* the
user-facing error-message fix.
"""

from __future__ import annotations

from pathlib import Path

import yaml


class OneleaksError(Exception):
    """Base class for every error oneleaks raises deliberately. Catch this to
    handle any oneleaks failure without needing to know which subclass it is.
    """


class ConfigError(OneleaksError):
    """Bad rule/config definitions: duplicate IDs, invalid regex, unknown fields."""


class ScanError(OneleaksError):
    """Runtime scanning failures (unreadable path, etc.)."""


def read_text_file(path: str | Path, *, what: str) -> str:
    """Read a UTF-8 text file, raising ConfigError instead of OSError.

    `what` names the kind of file for the message, e.g. "config file".
    """
    try:
        return Path(path).read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ConfigError(f"{what} not found: {path}") from exc
    except OSError as exc:
        raise ConfigError(f"cannot read {what} {path}: {exc.strerror}") from exc
    except UnicodeDecodeError as exc:
        raise ConfigError(f"{what} {path} is not valid UTF-8") from exc


def yaml_error_detail(exc: yaml.YAMLError) -> str:
    """Condense a PyYAML error into one line.

    Raw `str(a YAMLError)` is a multi-line dump with a caret diagram, which is
    fine in a traceback and terrible in a CLI error line.
    """
    problem = getattr(exc, "problem", None)
    mark = getattr(exc, "problem_mark", None)
    if problem and mark is not None:
        return f"{problem} (line {mark.line + 1}, column {mark.column + 1})"
    return " ".join(str(exc).split())
