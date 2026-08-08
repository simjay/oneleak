#!/usr/bin/env python3
"""Prints rough timing numbers for the scenarios in .plan/v1-roadmap.md's
"Performance benchmarks" item: 1KB/1MB text, a config-file-sized input, a
small/large synthetic repo, and git.scan_changed().

Not a pass/fail gate (perf varies too much across machines/CI runners to
hard-assert on) -- just run `make bench` and eyeball the numbers, or diff
two runs before/after a detector change.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import oneleak
from oneleak import git

_LOREM = (
    "def process_request(user_id, payload):\n"
    "    # handle incoming request and validate payload shape\n"
    "    result = {'status': 'ok', 'user_id': user_id}\n"
    "    for key, value in payload.items():\n"
    "        result[key] = normalize(value)\n"
    "    return result\n\n"
)

_SECRET_LINE = "OPENAI_API_KEY=sk-proj-" + "a" * 40 + "\nemail=alice@example.com\n"


def _repeat_to_size(unit: str, target_bytes: int) -> str:
    reps = max(1, target_bytes // len(unit.encode("utf-8")))
    return unit * reps


def _time(label: str, fn) -> float:
    start = time.perf_counter()
    fn()
    elapsed = time.perf_counter() - start
    print(f"  {label:<32} {elapsed * 1000:8.2f} ms")
    return elapsed


def bench_text_sizes() -> None:
    print("\n== Text scanning ==")
    for label, size in [("1 KB text", 1024), ("1 MB text", 1024 * 1024)]:
        text = _repeat_to_size(_LOREM, size) + _SECRET_LINE
        elapsed = _time(label, lambda t=text: oneleak.scan(t))
        mb = len(text.encode("utf-8")) / (1024 * 1024)
        print(f"    -> {mb / elapsed:.1f} MB/s" if elapsed > 0 else "    -> instant")

    config_text = (
        "version: 1\nexclude:\n  - node_modules/**\npii:\n  email: true\n"
        f"# fake config comment\napi_key: sk-proj-{'a' * 30}\n"
    )
    _time("config-file-sized input", lambda: oneleak.scan(config_text))


def _make_synthetic_repo(base: Path, n_files: int) -> None:
    for i in range(n_files):
        content = _repeat_to_size(_LOREM, 2000)
        if i % 10 == 0:
            content += _SECRET_LINE
        (base / f"module_{i}.py").write_text(content)


def bench_directory_scans() -> None:
    print("\n== Directory scanning ==")
    for label, n_files in [("small repo (~20 files)", 20), ("large repo (~500 files)", 500)]:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            _make_synthetic_repo(base, n_files)
            elapsed = _time(label, lambda b=base: oneleak.scan(b))
            print(f"    -> {n_files / elapsed:.1f} files/s" if elapsed > 0 else "    -> instant")


def bench_git_changed() -> None:
    print("\n== git.scan_changed() ==")
    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        subprocess.run(["git", "init", "-q"], cwd=base, check=True)
        subprocess.run(["git", "config", "user.email", "bench@bench.com"], cwd=base, check=True)
        subprocess.run(["git", "config", "user.name", "bench"], cwd=base, check=True)
        _make_synthetic_repo(base, 10)
        subprocess.run(["git", "add", "-A"], cwd=base, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=base, check=True)
        # A few staged changes, like a real pre-commit invocation would see.
        for i in range(3):
            (base / f"module_{i}.py").write_text(_LOREM + _SECRET_LINE)
        subprocess.run(["git", "add", "-A"], cwd=base, check=True)

        _time("3 staged files", lambda: git.scan_staged(cwd=str(base)))
        _time("3 changed files", lambda: git.scan_changed(cwd=str(base)))


def main() -> None:
    print("oneleak benchmark -- not a CI gate, just eyeball for regressions")
    bench_text_sizes()
    bench_directory_scans()
    bench_git_changed()
    print()


if __name__ == "__main__":
    if shutil.which("git") is None:
        raise SystemExit("git not found on PATH; required for the git.scan_changed() benchmark")
    main()
