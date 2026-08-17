import subprocess

import pytest

import oneleaks
from oneleaks import git
from oneleaks.config import Config


def _init_repo(path):
    subprocess.run(["git", "init", "-q"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.email", "test@test.com"], cwd=path, check=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=path, check=True)


@pytest.fixture
def repo(tmp_path):
    _init_repo(tmp_path)
    return tmp_path


class TestScanStaged:
    def test_scans_staged_index_content_not_working_tree(self, repo):
        secret_file = repo / "secret.env"
        secret_file.write_text("OPENAI_API_KEY=sk-proj-" + "a" * 20 + "\n")
        subprocess.run(["git", "add", "secret.env"], cwd=repo, check=True)
        # Edit again after staging: staged scan must see the pre-edit version.
        secret_file.write_text(
            "OPENAI_API_KEY=sk-proj-" + "a" * 20 + "\nANTHROPIC_KEY=sk-ant-" + "b" * 20 + "\n"
        )

        result = git.scan_staged(cwd=str(repo))
        rule_ids = {f.rule_id for f in result.findings}
        assert "openai-api-key" in rule_ids
        assert "anthropic-api-key" not in rule_ids

    def test_no_staged_changes_is_clean(self, repo):
        result = git.scan_staged(cwd=str(repo))
        assert result.safe

    def test_respects_config_allow_paths(self, repo):
        # Regression test: scan_staged()/scan_changed() must apply config
        # filtering (allow.paths, disabled_rules) exactly like scan() does.
        # They previously called scan_text() directly and skipped it.
        fixtures = repo / "tests" / "fixtures"
        fixtures.mkdir(parents=True)
        (fixtures / "example.env").write_text("OPENAI_API_KEY=sk-proj-" + "a" * 20 + "\n")
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)

        cfg = Config(allow_paths=["tests/fixtures/*"])
        result = git.scan_staged(cwd=str(repo), config=cfg)
        assert result.safe

    def test_respects_config_disabled_rules(self, repo):
        (repo / "secret.env").write_text("OPENAI_API_KEY=sk-proj-" + "a" * 20 + "\n")
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)

        cfg = Config(disabled_rules=["openai-api-key"])
        result = git.scan_staged(cwd=str(repo), config=cfg)
        assert result.safe


class TestScanChanged:
    def test_no_commits_yet_still_scans_staged_and_untracked(self, repo):
        (repo / "secret.env").write_text("OPENAI_API_KEY=sk-proj-" + "a" * 20 + "\n")
        result = git.scan_changed(cwd=str(repo))
        assert any(f.rule_id == "openai-api-key" for f in result.findings)

    def test_untracked_file_after_commit(self, repo):
        (repo / "a.txt").write_text("hello\n")
        subprocess.run(["git", "add", "a.txt"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-q", "-m", "init"], cwd=repo, check=True)

        (repo / "b.env").write_text("OPENAI_API_KEY=sk-proj-" + "a" * 20 + "\n")
        result = git.scan_changed(cwd=str(repo))
        assert any(f.path == "b.env" for f in result.findings)


def _commit_file(repo, name, content, message):
    (repo / name).write_text(content)
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", message], cwd=repo, check=True)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


class TestScanHistory:
    def test_finds_a_secret_introduced_then_removed(self, repo):
        _commit_file(repo, "app.py", "x = 1\n", "c1")
        introducing_sha = _commit_file(
            repo, "app.py", "x = 1\nOPENAI_API_KEY=sk-proj-" + "a" * 30 + "\n", "c2 - oops"
        )
        _commit_file(repo, "app.py", "x = 1\n# removed the secret\n", "c3 - fix")

        # Current content no longer has it, scan_changed()/scan() would miss it.
        current = git.scan_changed(cwd=str(repo))
        assert current.safe

        history = git.scan_history(cwd=str(repo))
        findings = [f for f in history.findings if f.rule_id == "openai-api-key"]
        assert len(findings) == 1
        assert findings[0].commit == introducing_sha
        assert findings[0].path == "app.py"
        assert findings[0].line == 2

    def test_multiline_pem_key_added_in_one_commit_detected_as_one_finding(self, repo):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----\n"
        # Regression test for the hunk-blob approach: scanning added lines
        # independently (rather than joined) would split the BEGIN/END
        # markers into disconnected strings the PEM regex could never match.
        _commit_file(repo, "key.pem", pem, "add key")

        history = git.scan_history(cwd=str(repo))
        pem_findings = [f for f in history.findings if f.rule_id == "pem-private-key"]
        assert len(pem_findings) == 1

    def test_max_commits_truncation_is_reported(self, repo):
        for i in range(5):
            _commit_file(repo, "f.txt", str(i), f"c{i}")

        truncated = git.scan_history(cwd=str(repo), max_commits=3)
        assert truncated.truncated is True

        unlimited = git.scan_history(cwd=str(repo), max_commits=0)
        assert unlimited.truncated is False

    def test_respects_config_disabled_rules(self, repo):
        _commit_file(repo, "app.py", "OPENAI_API_KEY=sk-proj-" + "a" * 20 + "\n", "c1")

        cfg = Config(disabled_rules=["openai-api-key"])
        result = git.scan_history(cwd=str(repo), config=cfg)
        assert result.safe


class TestGitScanningReadsTheSameEncodings:
    """Git scanning used to have its own UTF-8-only decoder, so a UTF-16 file
    was reported by `scan(Path(...))` and silently skipped by `--staged`.
    """

    SECRET = 'key = "sk-proj-' + "a" * 24 + '"\n'

    @staticmethod
    def _stage(repo):
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)

    def test_utf16_file_is_found_when_staged(self, repo):
        (repo / "script.ps1").write_bytes(self.SECRET.encode("utf-16"))
        self._stage(repo)
        result = git.scan_staged(cwd=str(repo))
        assert "openai-api-key" in [f.rule_id for f in result.findings]

    def test_folder_scan_and_staged_scan_agree(self, repo):
        (repo / "utf8.txt").write_text(self.SECRET)
        (repo / "utf16.ps1").write_bytes(self.SECRET.encode("utf-16"))
        self._stage(repo)
        staged = git.scan_staged(cwd=str(repo))
        folder = oneleaks.scan(repo)
        assert len(staged.findings) == len(folder.findings) == 2

    def test_binary_is_still_skipped(self, repo):
        (repo / "blob.bin").write_bytes(b"\x00\x01\x02\x03" * 64)
        self._stage(repo)
        assert git.scan_staged(cwd=str(repo)).findings == []
