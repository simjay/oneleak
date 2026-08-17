"""Turning bytes on disk into scannable text.

Deciding whether a file is text at all, working out its encoding, and reading
a single file or a string of input. Walking a folder lives in scanner.py,
beside the scanning it feeds.
"""

from __future__ import annotations

import codecs
import fnmatch
from pathlib import Path

from oneleaks.errors import ScanError


def _is_probably_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


# Encodings identified by a leading byte-order mark. Ordered longest-BOM
# first: UTF-32 LE begins with the UTF-16 LE BOM, so testing the shorter
# prefix first would decode it as the wrong encoding.
_BOM_ENCODINGS: tuple[tuple[bytes, str], ...] = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF8, "utf-8-sig"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)


def _decode_text(data: bytes) -> str | None:
    """Decode scanned bytes to text, or None if they aren't readable text.

    The BOM check comes before the binary heuristic, not after: UTF-16 text is
    close to half null bytes, so `_is_probably_binary` would call it binary and
    skip it.

    Only BOM-carrying UTF-16 is recovered. Without a BOM there is nothing to
    distinguish it from binary, so it still falls to the null-byte heuristic
    and is still skipped.
    """
    for bom, encoding in _BOM_ENCODINGS:
        if data.startswith(bom):
            try:
                return data.decode(encoding)
            except UnicodeDecodeError:
                return None
    if _is_probably_binary(data):
        return None
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _matches_any(relative_posix: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(relative_posix, pattern) for pattern in patterns)


def resolve_text_input(content, *, skip_unreadable: bool = False) -> tuple[str | None, str | None]:
    """Resolve str/bytes/single-file-Path input to (text, path). Directories
    are not supported here, use scan_path() directly for those.

    With skip_unreadable=True (used by scan(), to match directory-scan's
    "skip binary files safely" default), a binary/undecodable file yields
    (None, path) instead of raising. sanitize() uses skip_unreadable=False:
    asking to sanitize a specific unreadable file is a real user-facing error.
    """
    if isinstance(content, Path):
        if content.is_dir():
            raise ScanError("this operation does not support directory input; pass a file or text")
        data = content.read_bytes()
        text = _decode_text(data)
        if text is None:
            if skip_unreadable:
                return None, str(content)
            raise ScanError(f"cannot process binary file: {content}")
        return text, str(content)
    if isinstance(content, bytes):
        text = _decode_text(content)
        if text is None:
            if skip_unreadable:
                return None, None
            raise ScanError("input looks binary, not text")
        return text, None
    if isinstance(content, str):
        return content, None
    raise ScanError(f"unsupported input type: {type(content).__name__}")
