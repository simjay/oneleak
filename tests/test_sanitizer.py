import oneleaks


class TestBasicSanitize:
    def test_replaces_secret_with_typed_placeholder(self):
        text = "OPENAI_API_KEY=sk-proj-" + "a" * 20
        result = oneleaks.sanitize(text)
        assert "<OPENAI_API_KEY_1>" in result.text
        assert "sk-proj-" not in result.text

    def test_mapping_none_by_default(self):
        text = "OPENAI_API_KEY=sk-proj-" + "a" * 20
        result = oneleaks.sanitize(text)
        assert result.mapping is None

    def test_mapping_populated_with_reveal(self):
        text = "OPENAI_API_KEY=sk-proj-" + "a" * 20
        result = oneleaks.sanitize(text, reveal=True)
        assert result.mapping is not None
        assert result.mapping["<OPENAI_API_KEY_1>"].value == "sk-proj-" + "a" * 20


class TestReferentialConsistency:
    def test_repeated_value_reuses_placeholder(self):
        text = "Email alice@example.com. Contact alice@example.com again."
        result = oneleaks.sanitize(text)
        assert result.text.count("<EMAIL_1>") == 2

    def test_distinct_values_get_distinct_numbers(self):
        text = "alice@example.com and bob@example.com"
        result = oneleaks.sanitize(text)
        assert "<EMAIL_1>" in result.text
        assert "<EMAIL_2>" in result.text


class TestDesanitize:
    def test_round_trip(self):
        text = "OPENAI_API_KEY=sk-proj-" + "a" * 20 + "\nemail=alice@example.com\n"
        result = oneleaks.sanitize(text, reveal=True)
        restored = oneleaks.desanitize(result.text, result.mapping)
        assert restored == text

    def test_missing_placeholder_in_text_is_ignored(self):
        from oneleaks.models import MappingEntry

        mapping = {"<EMAIL_1>": MappingEntry(value="alice@example.com", rule_id="email")}
        assert oneleaks.desanitize("no placeholders here", mapping) == "no placeholders here"

    def test_unmapped_placeholder_shaped_token_left_untouched(self):
        from oneleaks.models import MappingEntry

        mapping = {"<EMAIL_1>": MappingEntry(value="alice@example.com", rule_id="email")}
        text = "<EMAIL_1> and <EMAIL_2>"
        assert oneleaks.desanitize(text, mapping) == "alice@example.com and <EMAIL_2>"


class TestSeedMapping:
    def test_seed_mapping_continues_numbering_across_calls(self):
        r1 = oneleaks.sanitize("alice@example.com", reveal=True)
        r2 = oneleaks.sanitize("bob@example.com", reveal=True, seed_mapping=r1.mapping)
        assert "<EMAIL_1>" in r1.text
        assert "<EMAIL_2>" in r2.text

    def test_seed_mapping_reuses_placeholder_for_repeated_value(self):
        r1 = oneleaks.sanitize("alice@example.com", reveal=True)
        r2 = oneleaks.sanitize("alice@example.com again", reveal=True, seed_mapping=r1.mapping)
        assert "<EMAIL_1>" in r2.text
        assert "<EMAIL_2>" not in r2.text


class TestOffsetSafety:
    def test_multiple_findings_same_text(self):
        text = "sk-proj-" + "a" * 20 + " and " + "sk-ant-" + "b" * 20
        result = oneleaks.sanitize(text)
        assert "<OPENAI_API_KEY_1>" in result.text
        assert "<ANTHROPIC_API_KEY_1>" in result.text

    def test_unicode_text_offsets(self):
        text = "café OPENAI_API_KEY=sk-proj-" + "a" * 20 + " done"
        result = oneleaks.sanitize(text, reveal=True)
        assert "<OPENAI_API_KEY_1>" in result.text
        restored = oneleaks.desanitize(result.text, result.mapping)
        assert restored == text
