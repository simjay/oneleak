"""Tests for the scanning machinery itself, not for any particular rule.

Reading files and folders, text encodings, which rules get turned off in which
kinds of file, what happens when two rules match the same text, and how config
file patterns are adjusted when a scan starts in a subfolder.

Tests for whether a given rule detects a given key format live in
`test_secret_rules.py` and `test_pii_rules.py`.
"""

import codecs
from pathlib import Path

import pytest
from helpers import rule_ids

import oneleaks
from oneleaks.config import Config, _shorten_pattern, discover_config
from oneleaks.scanner import _disabled_rule_ids, build_registry


class TestOverlapResolution:
    def test_provider_pattern_wins_over_entropy(self):
        # A real OpenAI-shaped key is also high-entropy. Only one finding
        # (the provider-specific one) should survive for that span.
        text = "sk-proj-abcdEFGH1234ijklMNOP5678"
        result = oneleaks.scan(text)
        spans_for_text = [f for f in result.findings if text[f.start : f.end] in text]
        rule_ids_here = {f.rule_id for f in spans_for_text}
        assert "openai-api-key" in rule_ids_here
        assert "high-entropy-string" not in rule_ids_here


class TestInlineSuppression:
    def test_suppressed_line_produces_no_finding(self):
        text = 'TOKEN = "fake-secret-value"  # oneleaks: allow\n'
        result = oneleaks.scan(text)
        assert result.safe

    def test_rule_scoped_suppression(self):
        text = 'TOKEN = "fake-secret-value"  # oneleaks: allow generic-secret\n'
        result = oneleaks.scan(text)
        assert result.safe

    def test_rule_scoped_suppression_does_not_suppress_other_rules(self):
        text = "OPENAI_API_KEY=sk-proj-" + "a" * 20 + "  # oneleaks: allow generic-secret\n"
        result = oneleaks.scan(text)
        assert "openai-api-key" in rule_ids(result)

    def test_scoped_suppression_of_the_overlap_winner_lets_the_loser_surface(self):
        # Regression test: suppression must run before overlap resolution.
        # aws-access-key-id (priority 100) wins the overlap against
        # generic-secret (priority 50) for this span. Scoping the allow
        # comment to aws-access-key-id specifically must not silently drop
        # the whole span. generic-secret should still fire in its place.
        text = 'api_key = "AKIAABCDEFGHIJKLMNOP"  # oneleaks: allow aws-access-key-id\n'
        result = oneleaks.scan(text)
        assert rule_ids(result) == ["generic-secret"]


class TestBytesInput:
    def test_non_utf8_bytes_skipped_not_raised(self):
        # Regression test: scan(bytes) used to unconditionally raise on
        # undecodable input, unlike an equivalent binary file on disk (which
        # is silently skipped). The two input forms must behave the same.
        result = oneleaks.scan(b"\xff\xfe not utf8 \x00\x00\x00")
        assert result.safe

    def test_sanitize_bytes_still_raises(self):
        from oneleaks.errors import ScanError
        from oneleaks.sanitizer import sanitize

        with pytest.raises(ScanError):
            sanitize(b"\xff\xfe not utf8 \x00\x00\x00")


class TestFileAndDirectoryScanning:
    def test_scan_single_file(self, tmp_path: Path):
        f = tmp_path / "config.py"
        f.write_text("OPENAI_API_KEY = 'sk-proj-" + "a" * 20 + "'\n")
        result = oneleaks.scan(f)
        assert not result.safe
        assert result.findings[0].path == str(f)

    def test_scan_directory_aggregates_and_excludes_git(self, tmp_path: Path):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config").write_text("sk-proj-" + "a" * 20)
        (tmp_path / "app.py").write_text("OPENAI_API_KEY = 'sk-proj-" + "a" * 20 + "'\n")
        result = oneleaks.scan(tmp_path)
        paths = {f.path for f in result.findings}
        assert paths == {"app.py"}

    def test_scan_directory_excludes_local_tool_caches(self, tmp_path: Path):
        # .pytest_cache/.mypy_cache/.ruff_cache/.hypothesis are all gitignored,
        # never committed, but a directory scan walks the real filesystem
        # regardless of git status, so they need their own exclusion.
        for cache_dir in (".pytest_cache", ".mypy_cache", ".ruff_cache", ".hypothesis"):
            d = tmp_path / cache_dir
            d.mkdir()
            (d / "artifact.txt").write_text("sk-proj-" + "a" * 20)
        (tmp_path / "app.py").write_text("x = 1\n")
        result = oneleaks.scan(tmp_path)
        assert result.safe

    def test_binary_file_skipped(self, tmp_path: Path):
        f = tmp_path / "binary.dat"
        f.write_bytes(b"\x00\x01\x02sk-proj-" + b"a" * 20)
        result = oneleaks.scan(f)
        assert result.safe

    def test_oversized_file_skipped(self, tmp_path: Path):
        f = tmp_path / "big.txt"
        f.write_text("sk-proj-" + "a" * 20)
        result = oneleaks.scan(tmp_path / "big.txt")
        # sanity: normally detected
        assert not result.safe
        # now confirm size limit actually filters via directory scan path
        from oneleaks.rules import RuleRegistry

        registry = RuleRegistry()
        registry.load_builtin()
        findings = __import__("oneleaks.scanner", fromlist=["_scan_file"])._scan_file(
            f,
            registry,
            base=tmp_path,
            max_file_size=1,
            fingerprint_key=None,
            disabled_rules=frozenset(),
        )
        assert findings == []


class TestConfig:
    def test_disabled_rule_is_skipped(self):
        cfg = Config(disabled_rules=["openai-api-key"])
        result = oneleaks.scan("sk-proj-" + "a" * 20, config=cfg)
        assert "openai-api-key" not in rule_ids(result)

    def test_pii_detector_disabled(self):
        cfg = Config(pii={"email": False})
        result = oneleaks.scan("contact me at alice@example.com", config=cfg)
        assert "email" not in rule_ids(result)

    def test_every_known_pii_type_actually_disables_its_rule(self):
        # Regression: pii: {} used to validate against a hand-maintained set
        # in config.py while scanner.py separately hand-maintained the
        # type->rule_id map it disables by. If the two ever drifted, a type
        # would pass validation and then silently no-op instead of disabling
        # anything. Both are now derived from pii_rules.py's one source of
        # truth, so this can't happen -- proven here for every known type,
        # not just one.
        from oneleaks import pii_rules

        for pii_type in pii_rules.known_types():
            cfg = Config(pii={pii_type: False})
            registry = build_registry(None, cfg)
            disabled = _disabled_rule_ids(cfg)
            rule_id = pii_rules.type_to_rule_id()[pii_type]
            assert rule_id in disabled, f"{pii_type} did not disable {rule_id}"
            assert any(r.id == rule_id for r in registry.rules), f"{rule_id} not a real rule"

    def test_allow_paths_drops_findings_from_matched_path(self, tmp_path: Path):
        fixtures = tmp_path / "tests" / "fixtures"
        fixtures.mkdir(parents=True)
        (fixtures / "example.py").write_text("sk-proj-" + "a" * 20)
        cfg = Config(allow_paths=["tests/fixtures/*"])
        result = oneleaks.scan(tmp_path, config=cfg)
        assert result.safe

    def test_unknown_top_level_field_rejected(self):
        import pytest

        from oneleaks.config import parse_config
        from oneleaks.errors import ConfigError

        with pytest.raises(ConfigError):
            parse_config("not_a_real_field: true\n")


class TestLockfileSuppression:
    """Lockfiles are mostly base64 integrity hashes, which entropy cannot tell
    from a credential. Only the low-precision detectors are skipped on them,
    so a real credential in a lockfile is still reported.
    """

    GO_SUM_LINE = (
        "cloud.google.com/go v0.26.0/go.mod h1:aQUYkXzVsufM+DwF1aE+0xfcU+56JwCaLick0ClmMTw=\n"
    )

    def test_entropy_suppressed_in_lockfile(self, tmp_path):
        (tmp_path / "go.sum").write_text(self.GO_SUM_LINE)
        assert oneleaks.scan(tmp_path).findings == []

    def test_same_content_still_flagged_outside_a_lockfile(self, tmp_path):
        (tmp_path / "notes.txt").write_text(self.GO_SUM_LINE)
        assert "high-entropy-string" in rule_ids(oneleaks.scan(tmp_path))

    def test_provider_rules_still_run_in_lockfiles(self, tmp_path):
        # A private-registry URL carrying credentials is a real lockfile leak,
        # so suppressing the whole file would be wrong.
        (tmp_path / "package-lock.json").write_text(
            '{"resolved": "https://registry.example.com/x", "key": "sk-proj-' + "a" * 24 + '"}'
        )
        assert "openai-api-key" in rule_ids(oneleaks.scan(tmp_path))

    def test_applies_to_single_file_scans_too(self, tmp_path):
        path = tmp_path / "go.sum"
        path.write_text(self.GO_SUM_LINE)
        assert oneleaks.scan(path).findings == []


class TestTextEncodings:
    SECRET = 'key = "sk-proj-' + "a" * 24 + '"\n'

    def test_utf16_with_bom_is_decoded(self, tmp_path):
        # UTF-16 is close to half null bytes, so the binary heuristic used to
        # skip it silently: a secret in a PowerShell script looked like a
        # clean scan. This is what Out-File and .NET write.
        path = tmp_path / "script.ps1"
        path.write_bytes(self.SECRET.encode("utf-16"))
        assert "openai-api-key" in rule_ids(oneleaks.scan(path))

    def test_utf16_big_endian_with_bom_is_decoded(self, tmp_path):
        path = tmp_path / "script.ps1"
        path.write_bytes(codecs.BOM_UTF16_BE + self.SECRET.encode("utf-16-be"))
        assert "openai-api-key" in rule_ids(oneleaks.scan(path))

    def test_utf8_bom_is_decoded(self, tmp_path):
        path = tmp_path / "config.txt"
        path.write_bytes(self.SECRET.encode("utf-8-sig"))
        assert "openai-api-key" in rule_ids(oneleaks.scan(path))

    def test_utf16_without_bom_is_still_skipped(self, tmp_path):
        # Documented limitation: with no BOM there is nothing to tell UTF-16
        # from binary, so it still falls to the null-byte heuristic.
        path = tmp_path / "script.ps1"
        path.write_bytes(self.SECRET.encode("utf-16-le"))
        assert oneleaks.scan(path).findings == []

    def test_binary_is_still_skipped(self, tmp_path):
        path = tmp_path / "blob.bin"
        path.write_bytes(b"\x00\x01\x02\x03" * 64)
        assert oneleaks.scan(path).findings == []


class TestPatternsAdjustForWhereTheScanStarts:
    """Path patterns in a config file are written relative to that file, but
    the scan may start in a folder further down. Unless the patterns are
    adjusted, they get compared against paths that begin somewhere else and
    quietly never match.
    """

    @staticmethod
    def _project(tmp_path, config_body):
        (tmp_path / ".oneleaks.yaml").write_text(config_body)
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "leak.txt").write_text("key=sk-proj-" + "a" * 24)
        return tmp_path

    def test_exclude_applies_when_scanning_from_below_the_config(self, tmp_path):
        root = self._project(tmp_path, 'exclude:\n  - "sub/**"\n')
        cfg = discover_config(root / "sub")
        assert oneleaks.scan(root / "sub", config=cfg).findings == []

    def test_exclude_still_applies_when_scanning_from_the_config_root(self, tmp_path):
        root = self._project(tmp_path, 'exclude:\n  - "sub/**"\n')
        cfg = discover_config(root)
        assert oneleaks.scan(root, config=cfg).findings == []

    def test_allow_paths_applies_from_below_the_config(self, tmp_path):
        root = self._project(tmp_path, 'allow:\n  paths:\n    - "sub/**"\n')
        cfg = discover_config(root / "sub")
        assert oneleaks.scan(root / "sub", config=cfg).findings == []

    def test_pattern_for_a_sibling_tree_does_not_leak_across(self, tmp_path):
        # `other/**` cannot match anything under sub/, so it must be dropped
        # rather than trimmed into something that matches by accident.
        root = self._project(tmp_path, 'exclude:\n  - "other/**"\n')
        cfg = discover_config(root / "sub")
        assert "openai-api-key" in rule_ids(oneleaks.scan(root / "sub", config=cfg))

    def test_hand_constructed_config_is_left_alone(self, tmp_path):
        # No config file, so nothing is adjusted: `sub/**` is read as relative to
        # the scan root and must not match `leak.txt` from inside sub/.
        root = self._project(tmp_path, "exclude: []\n")
        cfg = Config(exclude=["sub/**"])
        assert cfg.root is None
        assert "openai-api-key" in rule_ids(oneleaks.scan(root / "sub", config=cfg))

    def test_pattern_naming_the_scan_root_itself_covers_everything_under_it(self, tmp_path):
        # `sub` consumes down to nothing. Dropping it would silently discard
        # the exclusion; it has to become `**`.
        root = self._project(tmp_path, 'exclude:\n  - "sub"\n')
        cfg = discover_config(root / "sub")
        assert oneleaks.scan(root / "sub", config=cfg).findings == []

    def test_file_target_agrees_with_directory_target(self, tmp_path, monkeypatch):
        # A file target reports the path as given, framed by the working
        # directory. `scan .` and `scan leak.txt` must reach the same verdict.
        root = self._project(tmp_path, 'allow:\n  paths:\n    - "sub/**"\n')
        monkeypatch.chdir(root / "sub")
        cfg = discover_config()
        assert oneleaks.scan(Path("leak.txt"), config=cfg).findings == []
        assert oneleaks.scan(Path("."), config=cfg).findings == []


class TestShorteningAPattern:
    def test_cuts_off_a_folder_name_that_matches(self):
        assert _shorten_pattern("sub/a/**", ("sub",)) == "a/**"

    def test_cuts_off_several_folder_names(self):
        assert _shorten_pattern("src/vendor/**", ("src", "vendor")) == "**"

    def test_a_pattern_naming_this_folder_becomes_match_everything(self):
        assert _shorten_pattern("sub", ("sub",)) == "**"

    def test_a_pattern_for_another_folder_is_dropped(self):
        assert _shorten_pattern("other/**", ("sub",)) is None

    def test_stops_cutting_at_the_first_star(self):
        # A `*` can stand for any number of folders, so guessing how much to
        # cut would be wrong. Leave the rest of the pattern as written.
        assert _shorten_pattern("**/x", ("sub",)) == "**/x"
        assert _shorten_pattern("*.txt", ("sub",)) == "*.txt"

    def test_nothing_to_cut_leaves_the_pattern_alone(self):
        assert _shorten_pattern("sub/**", ()) == "sub/**"


class TestGeneratedContentSuppression:
    CERT_BODY = "MIIDXTCCAkWgAwIBAgIJAKL0UG+mRkSPMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV"
    KEY_BODY = "MIIEowIBAAKCAQEAx7Xy9kZfKQvPjWnLmT4bH8sVcRdYuIoPaSdFgHjKlZxCvBnM"

    def _pem(self, label, body):
        return f"-----BEGIN {label}-----\n" + "\n".join([body] * 4) + f"\n-----END {label}-----\n"

    def test_certificate_body_is_not_entropy(self):
        # A certificate is meant to be shared, but its text looks exactly
        # like a secret. One repo's test fixtures produced 118 of these.
        assert oneleaks.scan(self._pem("CERTIFICATE", self.CERT_BODY)).findings == []

    def test_public_key_block_is_not_entropy(self):
        assert oneleaks.scan(self._pem("PUBLIC KEY", self.CERT_BODY)).findings == []

    def test_private_key_block_is_still_reported(self):
        result = oneleaks.scan(self._pem("RSA PRIVATE KEY", self.KEY_BODY))
        assert "pem-private-key" in rule_ids(result)

    def test_a_real_secret_beside_a_certificate_is_still_found(self):
        text = self._pem("CERTIFICATE", self.CERT_BODY) + "\nkey=sk-proj-" + "a" * 24 + "\n"
        assert "openai-api-key" in rule_ids(oneleaks.scan(text))

    def test_svg_path_coordinates_are_not_ip_addresses(self, tmp_path):
        # SVG path data is a stream of coordinates, and four dot-separated
        # numbers in a row parse as an address.
        path = tmp_path / "logo.svg"
        path.write_text('<svg><path d="M13.28.85.45c.13-1.59,10.33.93.12,1.87.2"/></svg>')
        assert "ipv4" not in rule_ids(oneleaks.scan(path))

    def test_public_addresses_outside_an_svg_are_unaffected(self, tmp_path):
        path = tmp_path / "hosts.txt"
        path.write_text("resolver = 8.8.8.8")
        assert "ipv4" in rule_ids(oneleaks.scan(path))
