from pathlib import Path

import oneleak
from oneleak.config import Config


def rule_ids(result):
    return [f.rule_id for f in result.findings]


class TestProviderRules:
    def test_aws_access_key(self):
        result = oneleak.scan("key = AKIAABCDEFGHIJKLMNOP")
        assert "aws-access-key-id" in rule_ids(result)

    def test_aws_access_key_negative(self):
        result = oneleak.scan("key = AKIAABCDEFGHIJKLMNO")  # one char short
        assert "aws-access-key-id" not in rule_ids(result)

    def test_github_pat(self):
        result = oneleak.scan("ghp_" + "a" * 36)
        assert "github-pat" in rule_ids(result)

    def test_github_pat_boundary_too_short(self):
        result = oneleak.scan("ghp_" + "a" * 35)
        assert "github-pat" not in rule_ids(result)

    def test_openai_key(self):
        result = oneleak.scan("sk-proj-" + "a" * 20)
        assert "openai-api-key" in rule_ids(result)

    def test_anthropic_key(self):
        result = oneleak.scan("sk-ant-" + "a" * 20)
        assert "anthropic-api-key" in rule_ids(result)

    def test_stripe_secret_key(self):
        result = oneleak.scan("sk_live_" + "a" * 24)
        assert "stripe-secret-key" in rule_ids(result)

    def test_npm_token(self):
        result = oneleak.scan("npm_" + "a" * 36)
        assert "npm-token" in rule_ids(result)

    def test_ordinary_code_has_no_findings(self):
        result = oneleak.scan("def add(a, b):\n    return a + b\n")
        assert result.safe


class TestPEMPrivateKey:
    def test_detects_pem_block(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----"
        result = oneleak.scan(pem)
        findings = [f for f in result.findings if f.rule_id == "pem-private-key"]
        assert len(findings) == 1
        assert findings[0].preview == "<PRIVATE_KEY>"


class TestConnectionString:
    def test_matches_only_credential_portion(self):
        text = "postgres://user:hunter2@db.example.com/mydb"
        result = oneleak.scan(text)
        findings = [f for f in result.findings if f.rule_id == "connection-string-credential"]
        assert len(findings) == 1
        f = findings[0]
        assert text[f.start : f.end] == "hunter2"


class TestOverlapResolution:
    def test_provider_pattern_wins_over_entropy(self):
        # A real OpenAI-shaped key is also high-entropy; only one finding
        # (the provider-specific one) should survive for that span.
        text = "sk-proj-abcdEFGH1234ijklMNOP5678"
        result = oneleak.scan(text)
        spans_for_text = [f for f in result.findings if text[f.start : f.end] in text]
        rule_ids_here = {f.rule_id for f in spans_for_text}
        assert "openai-api-key" in rule_ids_here
        assert "high-entropy-string" not in rule_ids_here


class TestInlineSuppression:
    def test_suppressed_line_produces_no_finding(self):
        text = 'TOKEN = "fake-secret-value"  # oneleak: allow\n'
        result = oneleak.scan(text)
        assert result.safe

    def test_rule_scoped_suppression(self):
        text = 'TOKEN = "fake-secret-value"  # oneleak: allow generic-secret\n'
        result = oneleak.scan(text)
        assert result.safe

    def test_rule_scoped_suppression_does_not_suppress_other_rules(self):
        text = "OPENAI_API_KEY=sk-proj-" + "a" * 20 + "  # oneleak: allow generic-secret\n"
        result = oneleak.scan(text)
        assert "openai-api-key" in rule_ids(result)


class TestFileAndDirectoryScanning:
    def test_scan_single_file(self, tmp_path: Path):
        f = tmp_path / "config.py"
        f.write_text("OPENAI_API_KEY = 'sk-proj-" + "a" * 20 + "'\n")
        result = oneleak.scan(f)
        assert not result.safe
        assert result.findings[0].path == str(f)

    def test_scan_directory_aggregates_and_excludes_git(self, tmp_path: Path):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config").write_text("sk-proj-" + "a" * 20)
        (tmp_path / "app.py").write_text("OPENAI_API_KEY = 'sk-proj-" + "a" * 20 + "'\n")
        result = oneleak.scan(tmp_path)
        paths = {f.path for f in result.findings}
        assert paths == {"app.py"}

    def test_binary_file_skipped(self, tmp_path: Path):
        f = tmp_path / "binary.dat"
        f.write_bytes(b"\x00\x01\x02sk-proj-" + b"a" * 20)
        result = oneleak.scan(f)
        assert result.safe

    def test_oversized_file_skipped(self, tmp_path: Path):
        f = tmp_path / "big.txt"
        f.write_text("sk-proj-" + "a" * 20)
        result = oneleak.scan(tmp_path / "big.txt")
        # sanity: normally detected
        assert not result.safe
        # now confirm size limit actually filters via directory scan path
        from oneleak.rules import RuleRegistry

        registry = RuleRegistry()
        registry.load_builtin()
        findings = __import__("oneleak.scanner", fromlist=["_scan_file"])._scan_file(
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
        result = oneleak.scan("sk-proj-" + "a" * 20, config=cfg)
        assert "openai-api-key" not in rule_ids(result)

    def test_pii_detector_disabled(self):
        cfg = Config(pii={"email": False})
        result = oneleak.scan("contact me at alice@example.com", config=cfg)
        assert "email" not in rule_ids(result)

    def test_allow_paths_drops_findings_from_matched_path(self, tmp_path: Path):
        fixtures = tmp_path / "tests" / "fixtures"
        fixtures.mkdir(parents=True)
        (fixtures / "example.py").write_text("sk-proj-" + "a" * 20)
        cfg = Config(allow_paths=["tests/fixtures/*"])
        result = oneleak.scan(tmp_path, config=cfg)
        assert result.safe

    def test_unknown_top_level_field_rejected(self):
        import pytest

        from oneleak.config import parse_config
        from oneleak.errors import ConfigError

        with pytest.raises(ConfigError):
            parse_config("not_a_real_field: true\n")
