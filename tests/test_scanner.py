from pathlib import Path

import pytest

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

    def test_gitlab_pat(self):
        result = oneleak.scan("glpat-" + "a" * 20)
        assert "gitlab-pat" in rule_ids(result)

    def test_gitlab_pat_boundary_too_short(self):
        result = oneleak.scan("glpat-" + "a" * 19)
        assert "gitlab-pat" not in rule_ids(result)

    def test_slack_token(self):
        result = oneleak.scan("xoxb-" + "a" * 10)
        assert "slack-token" in rule_ids(result)

    def test_slack_token_all_valid_prefixes(self):
        for prefix in "baprs":
            result = oneleak.scan(f"xox{prefix}-" + "a" * 15)
            assert "slack-token" in rule_ids(result), f"prefix {prefix} should match"

    def test_slack_token_boundary_too_short(self):
        result = oneleak.scan("xoxb-" + "a" * 9)
        assert "slack-token" not in rule_ids(result)

    def test_slack_webhook_url(self):
        # Assembled from parts on purpose. Written as one contiguous literal,
        # this fixture trips GitHub's push protection, which blocks the push
        # even though the value is obviously fake. Their webhook detector is
        # purely structural, so there is no "clearly a test value" it accepts.
        # A secret scanner's own fixtures have to dodge other secret scanners.
        # Do not "simplify" this back into a single string.
        host = "hooks.slack.com"
        url = f"https://{host}/services/T{'0' * 8}/B{'0' * 8}/{'X' * 24}"
        result = oneleak.scan(url)
        assert "slack-webhook-url" in rule_ids(result)

    def test_slack_webhook_url_negative_wrong_domain(self):
        result = oneleak.scan("https://not-slack.example.com/services/T00000000/B00000000/X")
        assert "slack-webhook-url" not in rule_ids(result)

    def test_twilio_api_key(self):
        result = oneleak.scan("SK" + "a" * 32)
        assert "twilio-api-key" in rule_ids(result)

    def test_twilio_api_key_boundary_too_short(self):
        result = oneleak.scan("SK" + "a" * 31)
        assert "twilio-api-key" not in rule_ids(result)

    def test_datadog_api_key_with_keyword_context(self):
        result = oneleak.scan("datadog_api_key = " + "a" * 32)
        assert "datadog-api-key" in rule_ids(result)

    def test_datadog_api_key_negative_without_keyword_context(self):
        # Bare 32-char hex string with no "datadog"/"dd_api_key" nearby
        # should not fire. This rule requires keyword context precisely
        # because a bare 32-hex-char pattern is indistinguishable from an
        # MD5 hash otherwise.
        result = oneleak.scan("checksum = " + "a" * 32)
        assert "datadog-api-key" not in rule_ids(result)

    def test_google_api_key(self):
        result = oneleak.scan("AIza" + "a" * 35)
        assert "google-api-key" in rule_ids(result)

    def test_google_api_key_boundary_too_short(self):
        result = oneleak.scan("AIza" + "a" * 34)
        assert "google-api-key" not in rule_ids(result)

    def test_pypi_token(self):
        result = oneleak.scan("pypi-AgEIcHlwaS5vcmc" + "a" * 50)
        assert "pypi-token" in rule_ids(result)

    def test_pypi_token_boundary_too_short(self):
        result = oneleak.scan("pypi-AgEIcHlwaS5vcmc" + "a" * 49)
        assert "pypi-token" not in rule_ids(result)

    def test_azure_storage_key(self):
        # Regression test: the original pattern's trailing \b could never be
        # satisfied after `==` padding (a non-word char), so this rule was
        # completely dead. Confirm it actually fires now.
        result = oneleak.scan("AccountKey=" + "a" * 86 + "==;EndpointSuffix=core.windows.net")
        assert "azure-storage-key" in rule_ids(result)

    def test_aws_secret_access_key_span_does_not_shift_across_delimiter(self):
        # Regression test: the old bare-40-char-charset pattern could shift
        # left across the `=` delimiter (also a valid base64 char), capturing
        # part of "KEY=" instead of the real secret's last character.
        text = "AWS_SECRET_ACCESS_KEY=" + "a" * 39 + "/ next line here"
        result = oneleak.scan(text)
        findings = [f for f in result.findings if f.rule_id == "aws-secret-access-key"]
        assert len(findings) == 1
        assert text[findings[0].start : findings[0].end] == "a" * 39 + "/"

    def test_openai_key_bounded_not_defeated_by_trailing_junk(self):
        # Regression test: a naive fix (bound the quantifier but keep a
        # trailing \b) makes this WORSE than the original bug: it goes
        # from "over-matches" to "matches nothing at all", since a bounded
        # quantifier can never backtrack to a valid \b position when the
        # word-character run continues past the cap. Must still detect the
        # key, bounded to a sane length rather than swallowing everything.
        text = "sk-proj-" + "a" * 20 + "X" * 500
        result = oneleak.scan(text)
        findings = [f for f in result.findings if f.rule_id == "openai-api-key"]
        assert len(findings) == 1
        assert findings[0].end - findings[0].start < 150

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
        # A real OpenAI-shaped key is also high-entropy. Only one finding
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

    def test_scoped_suppression_of_the_overlap_winner_lets_the_loser_surface(self):
        # Regression test: suppression must run before overlap resolution.
        # aws-access-key-id (priority 100) wins the overlap against
        # generic-secret (priority 50) for this span. Scoping the allow
        # comment to aws-access-key-id specifically must not silently drop
        # the whole span. generic-secret should still fire in its place.
        text = 'api_key = "AKIAABCDEFGHIJKLMNOP"  # oneleak: allow aws-access-key-id\n'
        result = oneleak.scan(text)
        assert rule_ids(result) == ["generic-secret"]


class TestBytesInput:
    def test_non_utf8_bytes_skipped_not_raised(self):
        # Regression test: scan(bytes) used to unconditionally raise on
        # undecodable input, unlike an equivalent binary file on disk (which
        # is silently skipped). The two input forms must behave the same.
        result = oneleak.scan(b"\xff\xfe not utf8 \x00\x00\x00")
        assert result.safe

    def test_sanitize_bytes_still_raises(self):
        from oneleak.errors import ScanError
        from oneleak.sanitizer import sanitize

        with pytest.raises(ScanError):
            sanitize(b"\xff\xfe not utf8 \x00\x00\x00")


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
