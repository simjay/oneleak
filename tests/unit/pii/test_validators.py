import pytest

from oneleaks import validators


class TestLuhn:
    def test_valid_visa(self):
        assert validators.luhn("4111111111111111")

    def test_invalid_checksum(self):
        assert not validators.luhn("4111111111111112")

    def test_too_short(self):
        assert not validators.luhn("411111")

    def test_non_digit(self):
        assert not validators.luhn("411111111111111a")


class TestLuhnAsIMEIChecksum:
    def test_valid_imei(self):
        # IMEI's real check digit is the Luhn algorithm, the standard textbook
        # example IMEI used to illustrate it.
        assert validators.luhn("490154203237518")

    def test_invalid_imei_checksum(self):
        assert not validators.luhn("490154203237519")


class TestABARouting:
    def test_valid(self):
        assert validators.aba_routing("021000021")

    def test_invalid_checksum(self):
        assert not validators.aba_routing("021000022")

    def test_wrong_length(self):
        assert not validators.aba_routing("02100002")

    def test_non_digit(self):
        assert not validators.aba_routing("02100002a")


class TestSSN:
    def test_valid(self):
        assert validators.ssn("123-45-6789")

    def test_area_000_invalid(self):
        assert not validators.ssn("000-45-6789")

    def test_area_666_invalid(self):
        assert not validators.ssn("666-45-6789")

    def test_area_900_range_invalid(self):
        assert not validators.ssn("900-45-6789")

    def test_group_00_invalid(self):
        assert not validators.ssn("123-00-6789")

    def test_serial_0000_invalid(self):
        assert not validators.ssn("123-45-0000")

    def test_post_2011_high_area_number_is_valid(self):
        # Area numbers above the old (pre-2011) state-assignment tables are
        # valid post-randomization, and must NOT be rejected.
        assert validators.ssn("772-45-6789")
        assert validators.ssn("850-45-6789")


class TestIBAN:
    def test_valid_german_iban(self):
        assert validators.iban("DE89 3704 0044 0532 0130 00")

    def test_invalid_checksum(self):
        assert not validators.iban("DE89 3704 0044 0532 0130 01")

    def test_wrong_length_for_country(self):
        assert not validators.iban("DE89370400440532013000123456")

    def test_garbage(self):
        assert not validators.iban("not-an-iban")


class TestIP:
    def test_valid_ipv4(self):
        assert validators.ipv4("192.168.1.1")

    def test_invalid_ipv4_octet(self):
        assert not validators.ipv4("999.168.1.1")

    def test_valid_ipv6(self):
        assert validators.ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334")

    def test_invalid_ipv6(self):
        assert not validators.ipv6("not-an-ipv6-address")


class TestJWT:
    def test_valid_structure(self):
        # header {"alg":"HS256","typ":"JWT"} base64url-encoded
        header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        assert validators.jwt(f"{header}.payload.signature")

    def test_wrong_segment_count(self):
        assert not validators.jwt("only.two")

    def test_header_not_json(self):
        assert not validators.jwt("bm90anNvbg.payload.signature")


class TestCreditCard:
    """Luhn alone accepts roughly one digit run in ten, so the issuer prefix
    is what separates a card from a number that merely checksums.
    """

    def test_visa(self):
        assert validators.credit_card("4111111111111111")

    def test_mastercard(self):
        assert validators.credit_card("5555555555554444")

    def test_mastercard_2_series(self):
        assert validators.credit_card("2223003122003222")

    def test_amex(self):
        assert validators.credit_card("378282246310005")

    def test_discover(self):
        assert validators.credit_card("6011111111111117")

    def test_jcb(self):
        assert validators.credit_card("3530111333300000")

    def test_diners(self):
        assert validators.credit_card("30569309025904")

    def test_rejects_bad_checksum(self):
        assert not validators.credit_card("4111111111111112")

    def test_rejects_go_pseudo_version_timestamp(self):
        # From `golang.org/x/crypto v0.0.0-20190510104115-cbcb75029529`, which
        # is Luhn-valid by chance and used to be reported as a `high` card.
        assert validators.luhn("20190510104115")
        assert not validators.credit_card("20190510104115")

    def test_rejects_valid_checksum_at_wrong_length_for_issuer(self):
        # Amex prefix, but 16 digits instead of 15.
        assert validators.luhn("3782822463100052")
        assert not validators.credit_card("3782822463100052")

    def test_rejects_unknown_issuer_prefix(self):
        assert validators.luhn("9999999999999995")
        assert not validators.credit_card("9999999999999995")


class TestPublicIPValidators:
    """The built-in PII rules use these rather than plain parsing. An address
    that cannot leave the machine or the local network identifies nobody.
    """

    def test_public_v4_accepted(self):
        assert validators.public_ipv4("8.8.8.8")

    def test_public_v6_accepted(self):
        assert validators.public_ipv6("2606:4700:4700::1111")

    @pytest.mark.parametrize(
        "address",
        ["127.0.0.1", "0.0.0.0", "10.0.0.5", "192.168.1.1", "172.16.0.1", "169.254.1.1"],
    )
    def test_non_routable_v4_rejected(self, address):
        assert not validators.public_ipv4(address)

    def test_documentation_ranges_rejected(self):
        # RFC 5737 and RFC 3849 exist so docs can show an address safely.
        assert not validators.public_ipv4("192.0.2.44")
        assert not validators.public_ipv4("198.51.100.7")
        assert not validators.public_ipv4("203.0.113.9")
        assert not validators.public_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334")

    def test_plain_validators_still_accept_everything(self):
        # Unchanged, so a custom rule asking for "is this an IP" keeps working.
        assert validators.ipv4("127.0.0.1")
        assert validators.ipv6("2001:db8::1")
