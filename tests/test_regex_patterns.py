# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact-core

"""Unit tests for Layer 1: deterministic regex patterns."""

from __future__ import annotations

import pytest

from pw_redact.redactor.regex_patterns import detect_regex


def _types(text: str) -> set[str]:
    """Return set of entity types detected in text."""
    return {e.entity_type for e in detect_regex(text)}


def _texts(text: str, entity_type: str) -> list[str]:
    """Return matched texts for a specific entity type."""
    return [e.text for e in detect_regex(text) if e.entity_type == entity_type]


# ── US_SSN ──────────────────────────────────────────────────────────


class TestSSN:
    def test_dashes(self):
        assert "US_SSN" in _types("SSN: 123-45-6789")

    def test_spaces(self):
        assert "US_SSN" in _types("SSN: 123 45 6789")

    def test_no_separators(self):
        assert "US_SSN" in _types("SSN: 123456789")

    def test_four_digit_year_not_ssn(self):
        # A four-digit number like "2025" should not match (too short)
        assert "US_SSN" not in _types("The year is 2025")

    def test_extracted_text(self):
        entities = detect_regex("His SSN is 123-45-6789 on file.")
        ssn = [e for e in entities if e.entity_type == "US_SSN"]
        assert ssn[0].text == "123-45-6789"


# ── CREDIT_CARD ─────────────────────────────────────────────────────


class TestCreditCard:
    def test_spaces(self):
        assert "CREDIT_CARD" in _types("Card: 4111 1111 1111 1111")

    def test_dashes(self):
        assert "CREDIT_CARD" in _types("Card: 4111-1111-1111-1111")

    def test_no_separators(self):
        assert "CREDIT_CARD" in _types("Card: 4111111111111111")

    def test_short_number_not_cc(self):
        assert "CREDIT_CARD" not in _types("Number: 411111111111")  # 12 digits


# ── EMAIL ───────────────────────────────────────────────────────────


class TestEmail:
    def test_standard_email(self):
        assert "EMAIL" in _types("Contact: john@example.com")

    def test_email_with_dots(self):
        assert "EMAIL" in _types("Contact: john.doe@company.co.uk")

    def test_email_with_plus(self):
        assert "EMAIL" in _types("Contact: user+tag@gmail.com")

    def test_not_email(self):
        assert "EMAIL" not in _types("This is not an email address")

    def test_extracted_text(self):
        texts = _texts("Send to john@example.com please", "EMAIL")
        assert texts == ["john@example.com"]


# ── EIN ─────────────────────────────────────────────────────────────


class TestEIN:
    def test_ein_with_dash(self):
        assert "EIN" in _types("EIN: 12-3456789")

    def test_ein_extracted(self):
        texts = _texts("EIN is 34-5678901 for the trust", "EIN")
        assert texts == ["34-5678901"]

    def test_plain_number_not_ein(self):
        # Without dash, should NOT match as EIN (avoids false positives)
        assert "EIN" not in _types("Number: 123456789")


# ── US_PHONE ────────────────────────────────────────────────────────


class TestPhone:
    def test_parens(self):
        assert "US_PHONE" in _types("Call (610) 555-1234")

    def test_dots(self):
        assert "US_PHONE" in _types("Call 610.555.1234")

    def test_with_country_code(self):
        assert "US_PHONE" in _types("Call +1-610-555-1234")

    def test_short_not_phone(self):
        assert "US_PHONE" not in _types("Code: 12345")


# ── DATE_OF_BIRTH ──────────────────────────────────────────────────


class TestDOB:
    def test_dob_prefix(self):
        assert "DATE_OF_BIRTH" in _types("DOB: 03/15/1980")

    def test_born_prefix(self):
        assert "DATE_OF_BIRTH" in _types("born 03-15-1980")

    def test_date_without_context_not_dob(self):
        # A date without DOB/born context should not match
        assert "DATE_OF_BIRTH" not in _types("Filed on 03/15/2025")

    def test_extracted_text(self):
        # The capture group should return just the date
        texts = _texts("DOB: 03/15/1980 on record", "DATE_OF_BIRTH")
        assert texts == ["03/15/1980"]

    def test_birthdate_keyword(self):
        assert "DATE_OF_BIRTH" in _types("birthdate: 03/15/1980")

    def test_yyyy_mm_dd_format(self):
        texts = _texts("DOB: 1980-03-15", "DATE_OF_BIRTH")
        assert texts == ["1980-03-15"]

    def test_date_of_birth_hyphenated(self):
        assert "DATE_OF_BIRTH" in _types("date-of-birth: 03/15/1980")


# ── ACCOUNT_NUMBER ─────────────────────────────────────────────────


class TestAccountNumber:
    def test_acct_hash(self):
        assert "ACCOUNT_NUMBER" in _types("acct #12345678")

    def test_account_number(self):
        assert "ACCOUNT_NUMBER" in _types("account number: 8834567890")

    def test_extracted_digits(self):
        texts = _texts("acct #12345678 at bank", "ACCOUNT_NUMBER")
        assert texts == ["12345678"]


# ── JWT ─────────────────────────────────────────────────────────────


class TestJWT:
    def test_jwt_detected(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123_-xyz"
        assert "JWT" in _types(f"Token: {token}")

    def test_not_jwt(self):
        assert "JWT" not in _types("eyJnot-a-jwt")


# ── API_KEY ─────────────────────────────────────────────────────────


class TestAPIKey:
    def test_api_key_equals(self):
        assert "API_KEY" in _types("api_key=sk_test_dummy-not-a-secret")

    def test_apikey_colon(self):
        assert "API_KEY" in _types('"apikey": "abcdefghijklm"')

    def test_short_value_ignored(self):
        # Values under 10 chars should not match
        assert "API_KEY" not in _types("api_key=short")

    def test_uppercase_env_var(self):
        # STRIPE_API_KEY — (?i) flag lets regex match "API_KEY" substring
        assert "API_KEY" in _types("STRIPE_API_KEY=sk_test_dummy-not-a-secret")

    def test_prefixed_api_key(self):
        assert "API_KEY" in _types("PW_REDACT_API_KEY=some_long_value_here")


# ── BEARER_TOKEN ────────────────────────────────────────────────────


class TestBearerToken:
    def test_bearer_detected(self):
        assert "BEARER_TOKEN" in _types("Authorization: Bearer " + "eyJhbG" + "ciOiJIUzI1NiJ9" + "abcdefghijk")  # noqa: E501 - split to avoid secret scanning false positive

    def test_short_bearer_ignored(self):
        assert "BEARER_TOKEN" not in _types("Bearer short")


# ── DB_URL ──────────────────────────────────────────────────────────


class TestDBUrl:
    def test_postgres(self):
        assert "DB_URL" in _types("DATABASE=postgres://user:pass@host:5432/db")

    def test_redis(self):
        assert "DB_URL" in _types("redis://default:secret@redis.example.com:6379")

    def test_not_db_url(self):
        assert "DB_URL" not in _types("https://example.com")


# ── CRYPTO_PRIVATE_KEY ──────────────────────────────────────────────


class TestCryptoPrivateKey:
    def test_eth_private_key(self):
        # 0x + 64 hex chars
        key = "0x" + "a1b2c3d4" * 8  # 64 hex chars
        assert "CRYPTO_PRIVATE_KEY" in _types(f"Key: {key}")

    def test_extracted_text(self):
        key = "0x" + "deadbeef" * 8
        texts = _texts(f"pk={key} done", "CRYPTO_PRIVATE_KEY")
        assert texts == [key]

    def test_short_hex_not_private_key(self):
        # 0x + 40 hex (address, not private key)
        addr = "0x" + "a1b2c3d4" * 5
        assert "CRYPTO_PRIVATE_KEY" not in _types(f"Addr: {addr}")

    def test_no_0x_prefix_not_matched(self):
        bare = "a1b2c3d4" * 8
        assert "CRYPTO_PRIVATE_KEY" not in _types(f"Key: {bare}")


# ── CRYPTO_ADDRESS ─────────────────────────────────────────────────


class TestCryptoAddress:
    def test_eth_address(self):
        addr = "0x" + "AbCdEf12" * 5  # 40 hex chars
        assert "CRYPTO_ADDRESS" in _types(f"Wallet: {addr}")

    def test_extracted_text(self):
        addr = "0x" + "1234567890abcdef" * 2 + "12345678"  # exactly 40
        texts = _texts(f"addr={addr} ok", "CRYPTO_ADDRESS")
        assert texts == [addr]

    def test_too_short_not_address(self):
        short = "0x" + "abcdef12" * 4  # 32 hex, not 40
        assert "CRYPTO_ADDRESS" not in _types(f"Addr: {short}")


# ── CRYPTO_SEED ────────────────────────────────────────────────────


class TestCryptoSeed:
    def test_seed_phrase_quoted(self):
        assert "CRYPTO_SEED" in _types(
            'seed phrase: "abandon abandon abandon abandon abandon abandon '
            'abandon abandon abandon abandon abandon about"'
        )

    def test_mnemonic_quoted(self):
        assert "CRYPTO_SEED" in _types(
            "mnemonic='zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong'"
        )

    def test_recovery_phrase(self):
        assert "CRYPTO_SEED" in _types(
            'recovery phrase = "word1 word2 word3 word4 word5 word6"'
        )

    def test_no_quotes_not_matched(self):
        # Without quotes, we can't reliably detect where the phrase ends
        assert "CRYPTO_SEED" not in _types(
            "seed phrase is abandon abandon abandon"
        )


# ── PASSWORD ──────────────────────────────────────────────────────


class TestPassword:
    def test_password_equals(self):
        assert "PASSWORD" in _types("password=mysecretpass")

    def test_passwd_colon(self):
        assert "PASSWORD" in _types('"passwd": "abc123xyz"')

    def test_password_in_json(self):
        assert "PASSWORD" in _types('{"password": "hunter2"}')

    def test_short_password_ignored(self):
        # Values under 3 chars should not match
        assert "PASSWORD" not in _types("password=ab")


# ── SECRET_VALUE ──────────────────────────────────────────────────


class TestSecretValue:
    def test_secret_equals(self):
        assert "SECRET_VALUE" in _types("secret=sk_test_dummy-not-a-secret")

    def test_client_secret(self):
        assert "SECRET_VALUE" in _types('"client_secret": "abcdefghijklm"')

    def test_private_key(self):
        assert "SECRET_VALUE" in _types("private_key=my_long_private_key_value")

    def test_credential(self):
        assert "SECRET_VALUE" in _types("credential=abc123def456")

    def test_short_ignored(self):
        assert "SECRET_VALUE" not in _types("secret=abc")

    def test_secret_key(self):
        assert "SECRET_VALUE" in _types("SECRET_KEY=my_long_secret_value")

    def test_secret_access_key(self):
        assert "SECRET_VALUE" in _types("secret_access_key=DUMMY-not-a-real-access-key")

    def test_webhook_secret(self):
        # "secret" appears as substring — regex matches from there
        assert "SECRET_VALUE" in _types("WEBHOOK_SECRET=dummy-webhook-not-a-secret")


# ── AUTH_TOKEN ────────────────────────────────────────────────────


class TestAuthToken:
    def test_access_token(self):
        assert "AUTH_TOKEN" in _types("access_token=eyJhbGciOiJIUzI1NiIsInR5")

    def test_refresh_token(self):
        assert "AUTH_TOKEN" in _types('"refresh_token": "abc123def456ghi789jkl012"')

    def test_session_id(self):
        assert "AUTH_TOKEN" in _types("session_id=a1b2c3d4e5f6g7h8i9j0k1l2")

    def test_csrf_token(self):
        assert "AUTH_TOKEN" in _types("csrf_token=abcdefghijklmnopqrstuvwx")

    def test_short_token_ignored(self):
        assert "AUTH_TOKEN" not in _types("access_token=short")


# ── MAGIC_LINK ────────────────────────────────────────────────────


class TestMagicLink:
    def test_reset_link(self):
        assert "MAGIC_LINK" in _types(
            "reset_link=https://example.com/reset?token=abc123def456"
        )

    def test_magic_link(self):
        assert "MAGIC_LINK" in _types(
            'magic-link: "https://app.com/verify?t=abc123def456789012"'
        )

    def test_verification_link(self):
        assert "MAGIC_LINK" in _types(
            "verification_link=https://example.com/verify/abc123def456"
        )

    def test_short_link_ignored(self):
        assert "MAGIC_LINK" not in _types("reset_link=http://x.co")


# ── NMLS_ID ────────────────────────────────────────────────────────


class TestNMLSId:
    def test_nmls_hash(self):
        assert "NMLS_ID" in _types("NMLS# 123456")

    def test_mlo_number(self):
        assert "NMLS_ID" in _types("MLO: 12345678")

    def test_nmls_id_colon(self):
        assert "NMLS_ID" in _types("NMLS ID: 987654")

    def test_no_context_not_nmls(self):
        assert "NMLS_ID" not in _types("The code is 123456")

    def test_too_short_ignored(self):
        assert "NMLS_ID" not in _types("NMLS: 1234")

    def test_extracted_text(self):
        texts = _texts("NMLS #567890 on record", "NMLS_ID")
        assert texts == ["567890"]


# ── LOAN_NUMBER ────────────────────────────────────────────────────


class TestLoanNumber:
    def test_loan_hash(self):
        assert "LOAN_NUMBER" in _types("Loan #ABC12345678")

    def test_mortgage_number(self):
        assert "LOAN_NUMBER" in _types("mortgage number: 1234567890AB")

    def test_note_number(self):
        assert "LOAN_NUMBER" in _types("note #LN-2025-0042")

    def test_no_context_not_loan(self):
        assert "LOAN_NUMBER" not in _types("Reference: ABC12345678")

    def test_short_not_loan(self):
        assert "LOAN_NUMBER" not in _types("loan# AB12")


# ── MERS_MIN ──────────────────────────────────────────────────────


class TestMERSMIN:
    def test_mers_18_digits(self):
        assert "MERS_MIN" in _types("MERS# 100123456789012345")

    def test_min_colon(self):
        assert "MERS_MIN" in _types("MIN: 100123456789012345")

    def test_short_not_min(self):
        # Only exactly 18 digits should match
        assert "MERS_MIN" not in _types("MERS: 12345678")

    def test_extracted_text(self):
        texts = _texts("MERS# 100123456789012345 recorded", "MERS_MIN")
        assert texts == ["100123456789012345"]


# ── FHA_CASE_NUMBER ───────────────────────────────────────────────


class TestFHACaseNumber:
    def test_fha_case(self):
        assert "FHA_CASE_NUMBER" in _types("FHA case #123-4567890")

    def test_va_case_with_suffix(self):
        assert "FHA_CASE_NUMBER" in _types("VA: 123-4567890-703")

    def test_usda_case(self):
        assert "FHA_CASE_NUMBER" in _types("USDA #456-7890123")

    def test_no_context_not_fha(self):
        assert "FHA_CASE_NUMBER" not in _types("Code: 123-4567890")

    def test_extracted_text(self):
        texts = _texts("FHA case 123-4567890-703", "FHA_CASE_NUMBER")
        assert texts == ["123-4567890-703"]


# ── PARCEL_NUMBER ─────────────────────────────────────────────────


class TestParcelNumber:
    def test_apn_dashes(self):
        assert "PARCEL_NUMBER" in _types("APN: 123-456-789")

    def test_tax_parcel(self):
        assert "PARCEL_NUMBER" in _types("tax parcel# 12-34-567-890-0000")

    def test_property_index(self):
        assert "PARCEL_NUMBER" in _types("property index: 04-23-100-015")

    def test_assessor(self):
        assert "PARCEL_NUMBER" in _types("assessor# R1234567890")

    def test_no_context_not_parcel(self):
        assert "PARCEL_NUMBER" not in _types("The value is 123-456-789")


# ── MLS_NUMBER ────────────────────────────────────────────────────


class TestMLSNumber:
    def test_mls_hash(self):
        assert "MLS_NUMBER" in _types("MLS# PM23456789")

    def test_listing_number(self):
        assert "MLS_NUMBER" in _types("listing: 1234567890")

    def test_mls_id(self):
        assert "MLS_NUMBER" in _types("MLS ID: AR2025001")

    def test_no_context_not_mls(self):
        assert "MLS_NUMBER" not in _types("Reference: PM23456789")


# ── FILE_REFERENCE ────────────────────────────────────────────────


class TestFileReference:
    def test_escrow_number(self):
        assert "FILE_REFERENCE" in _types("escrow# NCS-123456-LA")

    def test_title_number(self):
        assert "FILE_REFERENCE" in _types("title number: T2025-00789")

    def test_instrument_number(self):
        assert "FILE_REFERENCE" in _types("instrument# 2025-0123456")

    def test_closing_number(self):
        assert "FILE_REFERENCE" in _types("closing #CLO-2025-987")

    def test_no_context_not_file(self):
        assert "FILE_REFERENCE" not in _types("Reference: NCS-123456-LA")


# ── US_ROUTING ────────────────────────────────────────────────────


class TestUSRouting:
    def test_routing_with_context(self):
        assert "US_ROUTING" in _types("routing number: 021000021")

    def test_aba_context(self):
        assert "US_ROUTING" in _types("ABA# 031100649")

    def test_transit_context(self):
        assert "US_ROUTING" in _types("transit: 021000021")

    def test_no_context_not_routing(self):
        # Without routing/aba/transit keyword, should not match
        assert "US_ROUTING" not in _types("The code is 021000021")

    def test_high_first_digit_not_routing(self):
        # ABA routing numbers start with 0-3
        assert "US_ROUTING" not in _types("routing: 521000021")

    def test_extracted_text(self):
        texts = _texts("routing# 021000021 for bank", "US_ROUTING")
        assert texts == ["021000021"]


# ── DRIVERS_LICENSE ───────────────────────────────────────────────


class TestDriversLicense:
    def test_dl_with_context(self):
        assert "DRIVERS_LICENSE" in _types("Driver's License: A1234567")

    def test_dl_hash(self):
        assert "DRIVERS_LICENSE" in _types("DL# D12345678901234")

    def test_drivers_lic(self):
        assert "DRIVERS_LICENSE" in _types("drivers lic. B87654321")

    def test_no_context_not_dl(self):
        # Without driver/DL context, should not match
        assert "DRIVERS_LICENSE" not in _types("Reference: A1234567")

    def test_extracted_text(self):
        texts = _texts("DL: A12345678", "DRIVERS_LICENSE")
        assert texts == ["A12345678"]


# ── STREET_ADDRESS ────────────────────────────────────────────────


class TestStreetAddress:
    def test_simple_address(self):
        assert "STREET_ADDRESS" in _types("Lives at 42 Oak Lane")

    def test_address_with_unit(self):
        assert "STREET_ADDRESS" in _types("123 Main Street #201")

    def test_boulevard(self):
        assert "STREET_ADDRESS" in _types("456 Elm Boulevard is nearby")

    def test_avenue_with_suite(self):
        assert "STREET_ADDRESS" in _types("789 Park Avenue Suite 100")

    def test_court(self):
        assert "STREET_ADDRESS" in _types("15 Maple Court is the rental")

    def test_no_suffix_not_address(self):
        assert "STREET_ADDRESS" not in _types("The number 42 is important")


# ── CRM_ID ────────────────────────────────────────────────────────


class TestCRMId:
    def test_crm_hash(self):
        assert "CRM_ID" in _types("crm# 12345")

    def test_client_id(self):
        assert "CRM_ID" in _types("client_id: 987654")

    def test_contact_id(self):
        assert "CRM_ID" in _types("contact id: 45678")

    def test_customer_id(self):
        assert "CRM_ID" in _types("customer_id=1234567890")

    def test_no_context_not_crm(self):
        assert "CRM_ID" not in _types("The number is 12345")

    def test_too_short_ignored(self):
        # Under 4 digits should not match
        assert "CRM_ID" not in _types("crm: 123")

    def test_extracted_text(self):
        texts = _texts("client_id: 987654 in system", "CRM_ID")
        assert texts == ["987654"]


# ── PLATFORM_ID ───────────────────────────────────────────────────


class TestPlatformId:
    def test_org_id_uuid(self):
        assert "PLATFORM_ID" in _types(
            "org_id: a1b2c3d4-e5f6-7890-abcd-ef1234567890"
        )

    def test_wallet_id_hex(self):
        assert "PLATFORM_ID" in _types(
            "wallet_id=deadbeef1234567890abcdef"
        )

    def test_tenant_id(self):
        assert "PLATFORM_ID" in _types(
            "tenant_id: abc123def456abc123def456"
        )

    def test_vault_id(self):
        assert "PLATFORM_ID" in _types(
            "vault_id: 0123456789abcdef01234567"
        )

    def test_signer_id(self):
        assert "PLATFORM_ID" in _types(
            "signer_id=abcdef1234567890abcdef12"
        )

    def test_no_context_not_platform(self):
        # Without infra context keyword, should not match
        assert "PLATFORM_ID" not in _types(
            "hash: a1b2c3d4e5f6a1b2c3d4e5f6"
        )

    def test_non_hex_not_matched(self):
        # Contains g, h, etc. which are not hex digits
        assert "PLATFORM_ID" not in _types(
            "org_id: ghijklmnopqrstuvwxyz1234"
        )


# ── Keyword-triggered patterns do not take the next ordinary word ───


class TestKeywordPatternsNoOverRedaction:
    """Before the digit requirement, the next ordinary word after a keyword was
    redacted ("loan application" -> LOAN_NUMBER "application")."""

    @pytest.mark.parametrize(
        "text,entity_type",
        [
            ("We discussed the mortgage refinancing options.", "LOAN_NUMBER"),
            ("The loan application is pending.", "LOAN_NUMBER"),
            ("The note: borrower requested forbearance.", "LOAN_NUMBER"),
            ("Denote everything clearly.", "LOAN_NUMBER"),
            ("Order title insurance before closing.", "FILE_REFERENCE"),
            ("The closing disclosure arrived.", "FILE_REFERENCE"),
            ("Please sign the document tomorrow.", "FILE_REFERENCE"),
            ("Read the escrow instructions.", "FILE_REFERENCE"),
            ("Recording requirements vary by county.", "FILE_REFERENCE"),
            ("Review the listing agreement.", "MLS_NUMBER"),
            ("Check the assessor valuation.", "PARCEL_NUMBER"),
            ("The parcel boundaries changed.", "PARCEL_NUMBER"),
        ],
    )
    def test_ordinary_word_not_detected(self, text, entity_type):
        assert entity_type not in _types(text)

    @pytest.mark.parametrize(
        "text,entity_type,value",
        [
            ("Loan #ABC12345678", "LOAN_NUMBER", "ABC12345678"),
            ("note #LN-2025-0042", "LOAN_NUMBER", "LN-2025-0042"),
            ("title number: T2025-00789", "FILE_REFERENCE", "T2025-00789"),
            ("escrow# NCS-123456-LA", "FILE_REFERENCE", "NCS-123456-LA"),
            ("MLS# PM23456789", "MLS_NUMBER", "PM23456789"),
            ("assessor# R1234567890", "PARCEL_NUMBER", "R1234567890"),
        ],
    )
    def test_identifiers_with_digits_still_detected(self, text, entity_type, value):
        assert _texts(text, entity_type) == [value]


class TestKeywordStart:
    """The keyword may follow "_", a digit or start a camelCase part, but not
    sit inside a lowercase word."""

    @pytest.mark.parametrize(
        "text,entity_type,value",
        [
            ("client_loan: 12345678", "LOAN_NUMBER", "12345678"),
            ("HomeLoan #12345678", "LOAN_NUMBER", "12345678"),
            ("2ndMortgage 12345678", "LOAN_NUMBER", "12345678"),
            ("2Mortgage 12345678", "LOAN_NUMBER", "12345678"),
            ("HomeTitle 123456A", "FILE_REFERENCE", "123456A"),
            ("new_listing: AR2025001", "MLS_NUMBER", "AR2025001"),
            ("county_APN: 123-456-789", "PARCEL_NUMBER", "123-456-789"),
        ],
    )
    def test_detected(self, text, entity_type, value):
        assert _texts(text, entity_type) == [value]

    @pytest.mark.parametrize(
        "text", ["denote 12345678", "Denote 12345678", "LOANLOAN 12345678", "subtitle 1234567"]
    )
    def test_inside_word_not_detected(self, text):
        assert not ({"LOAN_NUMBER", "FILE_REFERENCE"} & _types(text))
