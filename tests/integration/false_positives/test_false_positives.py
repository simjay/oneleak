"""Tests that oneleaks does NOT report things that are not secrets.

Every file in the `clean_files/` folder beside this one is safe content that
oneleaks once reported by mistake, reduced from a real file. The test below
scans each one and checks that nothing is reported.

If someone changes a rule and it starts flagging one of these files again,
this test fails and points at the file. Each file says at the top what it is
there to catch.

Tests for secrets we DO want to find are in `tests/integration/secrets/` and
`tests/integration/pii/`. They build the fake secrets in code rather than
storing them in files, because a file full of realistic-looking keys makes
GitHub block the push.
"""

from pathlib import Path

import pytest

import oneleaks

CLEAN_FILES_DIR = Path(__file__).parent / "clean_files"
CLEAN_FILES = sorted(CLEAN_FILES_DIR.iterdir())


def _describe(findings):
    return "\n".join(f"  {f.rule_id} at line {f.line}: {f.preview}" for f in findings)


class TestCleanFiles:
    def test_there_are_files_to_check(self):
        # Without this, a bad path would make every test below pass silently.
        assert len(CLEAN_FILES) >= 8

    @pytest.mark.parametrize("path", CLEAN_FILES, ids=lambda p: p.name)
    def test_file_has_nothing_to_report(self, path):
        findings = oneleaks.scan(path).findings
        assert not findings, f"{path.name} should be clean, but we found:\n{_describe(findings)}"

    @pytest.mark.parametrize("path", CLEAN_FILES, ids=lambda p: p.name)
    def test_file_explains_what_it_is_for(self, path):
        # Each file starts with a note saying what mistake it guards against,
        # so a future failure explains itself. JSON has no comments, so those
        # files use a "_why" key instead.
        top = path.read_text(errors="replace")[:800]
        assert "What this catches:" in top or '"_why"' in top, (
            f"{path.name} needs a note at the top saying what it is for"
        )

    def test_scanning_the_whole_folder_is_also_clean(self):
        # Some checks depend on the file name or extension, so scanning the
        # folder is not the same as scanning each file on its own.
        assert oneleaks.scan(CLEAN_FILES_DIR).findings == []


class TestWhyThoseFilesAreClean:
    """The same checks written directly, so a failure points at the rule
    instead of at a file.
    """

    def test_a_link_is_not_a_secret(self):
        text = "https://github.com/psf/requests/security/advisories/GHSA-9wx4-h78v-vm56"
        assert oneleaks.scan(text).findings == []

    def test_but_a_real_random_looking_key_is_still_found(self):
        # The link check must not also hide ordinary keys that contain "/".
        assert oneleaks.scan("K7xQ/mZ2vR8pLd4T/wY6nB3jH9sA1cF5eG0uV").findings

    def test_code_is_not_a_secret(self):
        for text in (
            "def f(username: bytes | str, password: bytes | str) -> str:",
            "username, password = get_auth_from_url(proxy)",
            "secret: 'shhhh, very secret'",
            "markup = '<label for=\"password\">Password</label>'",
        ):
            assert oneleaks.scan(text).findings == [], text

    def test_but_a_real_password_in_quotes_is_still_found(self):
        assert oneleaks.scan('password = "hL8vQ2mZx7Tn4Kd9"').findings

    def test_the_words_user_and_pass_in_a_url_are_not_a_secret(self):
        for text in (
            "http://user:pass@proxy.example.org:1080",
            "https://user:password@host/path",
        ):
            assert oneleaks.scan(text).findings == [], text

    def test_but_a_real_password_in_a_url_is_still_found(self):
        assert oneleaks.scan("https://svc:hL8vQ2mZx7Tn4Kd9@internal.example.com/").findings
