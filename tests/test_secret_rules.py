from oneleak import secret_rules


class TestBuiltinEntries:
    def test_loads_all_secret_rules(self):
        entries = secret_rules.builtin_entries()
        ids = {e["id"] for e in entries}
        assert {"aws-access-key-id", "github-pat", "openai-api-key"} <= ids

    def test_every_entry_is_secret_category(self):
        assert all(e["category"] == "secret" for e in secret_rules.builtin_entries())
