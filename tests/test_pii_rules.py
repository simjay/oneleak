from oneleaks import pii_rules
from oneleaks.config import parse_config
from oneleaks.errors import ConfigError


class TestBuiltinEntries:
    def test_loads_all_pii_rules(self):
        entries = pii_rules.builtin_entries()
        ids = {e["id"] for e in entries}
        assert {"email", "phone", "ssn", "credit-card", "imei"} <= ids

    def test_every_entry_is_pii_category(self):
        assert all(e["category"] == "pii" for e in pii_rules.builtin_entries())


class TestKnownTypes:
    def test_matches_builtin_entries(self):
        assert pii_rules.known_types() == {e["type"] for e in pii_rules.builtin_entries()}

    def test_config_validation_uses_derived_types_not_a_hardcoded_list(self):
        # Every builtin type must be accepted...
        for type_ in pii_rules.known_types():
            parse_config(f"pii:\n  {type_}: false\n")
        # ...and anything outside that set must still be rejected.
        try:
            parse_config("pii:\n  not_a_real_type: false\n")
        except ConfigError:
            pass
        else:
            raise AssertionError("expected ConfigError for an unknown pii type")


class TestTypeToRuleId:
    def test_covers_every_known_type(self):
        assert set(pii_rules.type_to_rule_id()) == pii_rules.known_types()

    def test_maps_to_real_rule_ids(self):
        mapping = pii_rules.type_to_rule_id()
        assert mapping["credit_card"] == "credit-card"
        assert mapping["mac_address"] == "mac-address"
        assert mapping["bank_routing_number"] == "bank-routing-number"
