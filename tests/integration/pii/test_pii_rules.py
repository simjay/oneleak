import pytest
from helpers import rule_ids

import oneleaks
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


# --- The rules find what they are meant to find ---


class TestNewPIIRules:
    def test_mac_address(self):
        result = oneleaks.scan("device mac: AA:BB:CC:DD:EE:FF")
        assert "mac-address" in rule_ids(result)

    def test_mac_address_negative_malformed(self):
        result = oneleaks.scan("device mac: AA:BB:CC:DD:EE")
        assert "mac-address" not in rule_ids(result)

    def test_imei_valid_checksum(self):
        result = oneleaks.scan("imei: 490154203237518")
        assert "imei" in rule_ids(result)

    def test_imei_invalid_checksum(self):
        result = oneleaks.scan("imei: 490154203237519")
        assert "imei" not in rule_ids(result)

    def test_bank_routing_number_with_keyword_and_valid_checksum(self):
        result = oneleaks.scan("routing number: 021000021")
        assert "bank-routing-number" in rule_ids(result)

    def test_bank_routing_number_negative_without_keyword(self):
        result = oneleaks.scan("id: 021000021")
        assert "bank-routing-number" not in rule_ids(result)

    def test_bank_routing_number_negative_invalid_checksum(self):
        result = oneleaks.scan("routing number: 021000022")
        assert "bank-routing-number" not in rule_ids(result)


class TestCreditCardDetection:
    def test_real_card_detected(self):
        result = oneleaks.scan("card: 4111111111111111")
        assert "credit-card" in rule_ids(result)

    def test_spaced_and_hyphenated_forms(self):
        assert "credit-card" in rule_ids(oneleaks.scan("card: 4111 1111 1111 1111"))
        assert "credit-card" in rule_ids(oneleaks.scan("card: 4111-1111-1111-1111"))

    def test_go_pseudo_version_is_not_a_card(self):
        # The separator in the card pattern may sit anywhere, so this reads as
        # a 17-digit run and passes Luhn. The issuer check is what stops it.
        text = "golang.org/x/crypto v0.0.0-20190510104115-cbcb75029529"
        assert "credit-card" not in rule_ids(oneleaks.scan(text))

    def test_imei_still_outranks_credit_card_on_a_genuine_collision(self):
        # An Amex number is 15 digits and Luhn-valid, so both rules match it.
        # imei's priority 105 has to beat credit-card's 100.
        result = oneleaks.scan("imei: 378282246310005")
        assert rule_ids(result) == ["imei"]


class TestIPAddressDetection:
    def test_public_address_is_reported(self):
        assert "ipv4" in rule_ids(oneleaks.scan("resolver = 8.8.8.8"))

    @pytest.mark.parametrize("text", ["host 127.0.0.1", "bind 0.0.0.0", "lan 192.168.1.5"])
    def test_non_routable_address_is_not_pii(self, text):
        # These appear in the configs, tests and docs of nearly every repo and
        # identify nobody.
        assert "ipv4" not in rule_ids(oneleaks.scan(text))

    def test_public_v6_reported_documentation_v6_not(self):
        assert "ipv6" in rule_ids(oneleaks.scan("dns 2606:4700:4700::1111"))
        assert "ipv6" not in rule_ids(oneleaks.scan("dns 2001:db8:85a3::8a2e:370:7334"))
