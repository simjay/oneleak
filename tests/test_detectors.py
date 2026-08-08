from oneleak.detectors import (
    entropy_candidates,
    generic_assignment_candidates,
    shannon_entropy,
)


class TestEntropy:
    def test_low_entropy_repeated_chars(self):
        assert shannon_entropy("aaaaaaaaaa") == 0.0

    def test_high_entropy_random_string(self):
        assert shannon_entropy("kX9mQ2vR7pL4wZ8bN1cT6") > 3.5

    def test_uuid_not_flagged(self):
        text = "id: f47ac10b-58cc-4372-a567-0e02b2c3d479"
        assert entropy_candidates(text) == []

    def test_pure_hex_hash_not_flagged(self):
        # sha1-length hex hash -- classic false-positive trap, excluded in v0.1
        text = "commit da39a3ee5e6b4b0d3255bfef95601890afd80709abc123"
        assert entropy_candidates(text) == []

    def test_repeated_char_run_not_flagged(self):
        text = "padding=" + "a" * 40
        assert entropy_candidates(text) == []

    def test_real_looking_token_flagged(self):
        text = "token = kX9mQ2vR7pL4wZ8bN1cT6dJ5hF3sA0gY"
        assert len(entropy_candidates(text)) >= 1

    def test_below_min_length_not_flagged(self):
        assert entropy_candidates("kX9mQ2vR7p", min_length=20) == []


class TestGenericAssignment:
    def test_double_quoted_python_style(self):
        matches = generic_assignment_candidates('password = "hello123"')
        assert len(matches) == 1

    def test_yaml_style(self):
        text = "database:\n  password: hello123\n"
        matches = generic_assignment_candidates(text)
        assert len(matches) == 1

    def test_env_style(self):
        matches = generic_assignment_candidates("TOKEN=abc123def456")
        assert len(matches) == 1

    def test_placeholder_value_skipped(self):
        assert generic_assignment_candidates('password = "changeme"') == []

    def test_too_short_value_skipped(self):
        assert generic_assignment_candidates('password = "ab"') == []

    def test_span_covers_value_only(self):
        text = 'api_key = "supersecretvalue"'
        matches = generic_assignment_candidates(text)
        assert len(matches) == 1
        m = matches[0]
        assert text[m.start : m.end] == "supersecretvalue"
