from oneleak import validators


class TestLuhn:
    def test_valid_visa(self):
        assert validators.luhn("4111111111111111")

    def test_invalid_checksum(self):
        assert not validators.luhn("4111111111111112")

    def test_too_short(self):
        assert not validators.luhn("411111")

    def test_non_digit(self):
        assert not validators.luhn("411111111111111a")


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
        # valid post-randomization; must NOT be rejected.
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
