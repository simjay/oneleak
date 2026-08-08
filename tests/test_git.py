import subprocess

import pytest

from oneleak import git
from oneleak.config import Config


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
        # Edit again after staging -- staged scan must see the pre-edit version.
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
        # filtering (allow.paths, disabled_rules) exactly like scan() does --
        # they previously called scan_text() directly and skipped it.
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
