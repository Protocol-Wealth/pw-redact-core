# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact-core

"""Look-alike separators and invisible characters must not hide PII.

Each case below came back unredacted before detection ran on canonical text:
through the API for the look-alike dashes and spaces, and through the library
(``PWRedactor.redact``, which skips the HTTP input validator) for the invisible
characters too. All values are synthetic.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

import pw_redact.main as main_module
from pw_redact.config import settings
from pw_redact.main import app
from pw_redact.redactor.unicode_canon import canonicalize, to_original_span
from pw_redact.security.rate_limiter import RateLimiter

SSN = "123-45-6789"
CARD = "4111 1111 1111 1111"

# name -> (text, placeholder type, the original value as written)
BYPASSES = {
    "SSN, non-breaking hyphen U+2011": ("SSN 123\u201145\u20116789", "US_SSN"),
    "SSN, minus sign U+2212": ("SSN 123\u221245\u22126789", "US_SSN"),
    "SSN, en dash U+2013": ("SSN 123\u201345\u20136789", "US_SSN"),
    "SSN, hyphen U+2010": ("SSN 123\u201045\u20106789", "US_SSN"),
    "SSN, fullwidth hyphen U+FF0D": ("SSN 123\uff0d45\uff0d6789", "US_SSN"),
    "SSN, zero-width space": ("SSN 123\u200b-45-6789", "US_SSN"),
    "SSN, soft hyphen": ("SSN 123\u00ad-45-6789", "US_SSN"),
    "SSN, word joiner and BOM": ("SSN 12\u20603-45-67\ufeff89", "US_SSN"),
    "card, NBSP": ("card 4111\u00a01111\u00a01111\u00a01111", "CREDIT_CARD"),
    "card, narrow NBSP": ("card 4111\u202f1111\u202f1111\u202f1111", "CREDIT_CARD"),
    "card, thin space": ("card 4111\u20091111\u20091111\u20091111", "CREDIT_CARD"),
    "email, zero-width space": ("email: jane.doe\u200b@example.com", "EMAIL"),
}


def _digits(s: str) -> str:
    return "".join(c for c in s if c.isdigit())


@pytest.mark.parametrize("text,etype", list(BYPASSES.values()), ids=list(BYPASSES))
def test_library_redacts_bypass(redactor, text, etype):
    result = redactor.redact(text)
    entries = [e for e in result.manifest.placeholders if e.entity_type == etype]
    assert entries, f"{etype} not detected in {text!r}: {result.sanitized_text!r}"
    entry = entries[0]
    # Offsets are on the caller's text, and the original is kept verbatim,
    # hidden characters included, so rehydration restores exactly what was sent.
    assert text[entry.start : entry.end] == entry.original
    assert f"<{etype}_1>" in result.sanitized_text
    # Nothing of the value survives: no digit run, no fragment of the address.
    if etype != "EMAIL":
        assert _digits(entry.original) not in _digits(result.sanitized_text)
    else:
        assert "example.com" not in result.sanitized_text
    assert result.sanitized_text.startswith(text[: entry.start])
    assert result.sanitized_text.endswith(text[entry.end :])


@pytest.mark.parametrize("text,etype", list(BYPASSES.values()), ids=list(BYPASSES))
def test_rehydrate_restores_the_exact_original(redactor, rehydrator, text, etype):
    result = redactor.redact(text)
    assert rehydrator.rehydrate(result.sanitized_text, result.manifest.to_dict()) == text


@pytest.mark.parametrize("text,etype", list(BYPASSES.values()), ids=list(BYPASSES))
def test_detect_reports_original_offsets(redactor, text, etype):
    hits = [e for e in redactor.detect(text) if e.entity_type == etype]
    assert hits
    assert text[hits[0].start : hits[0].end] == hits[0].text


@pytest.mark.parametrize(
    "ascii_text,lookalike",
    [
        (
            "AGI is $425,000 and the rate is 24% bracket.",
            "AGI is $425,000\u00a0and the rate is 24% bracket.",
        ),
        ("Planning years 2026-2030 at age 65.", "Planning years 2026\u20132030 at age 65."),
    ],
    ids=["amounts and brackets", "year range with en dash"],
)
def test_financial_data_survives_like_its_ascii_form(redactor, ascii_text, lookalike):
    """Canonicalizing must not start redacting what the allow-list preserves."""
    plain = redactor.redact(ascii_text)
    fancy = redactor.redact(lookalike)
    assert [e.entity_type for e in fancy.manifest.placeholders] == [
        e.entity_type for e in plain.manifest.placeholders
    ]
    assert "$425,000" in fancy.sanitized_text or "$425,000" not in lookalike


def test_offsets_after_a_value_with_dropped_characters(redactor):
    text = "A 123\u200b-45-6789 then B 987-65-4321."
    result = redactor.redact(text)
    for entry in result.manifest.placeholders:
        assert text[entry.start : entry.end] == entry.original
    assert result.sanitized_text == "A <US_SSN_1> then B <US_SSN_2>."


def test_canonicalize_maps_every_kept_character():
    text = "a\u00ad\u2011b\u00a0c\u200b"
    canon, index_map = canonicalize(text)
    assert canon == "a-b c"
    assert index_map == [0, 2, 3, 4, 5, len(text)]
    assert to_original_span(index_map, 0, 3) == (0, 4)
    assert to_original_span(index_map, 4, 5) == (5, 6)


@pytest.fixture()
def _app_state(redactor):
    main_module._redactor = redactor
    main_module._rate_limiter = RateLimiter(rpm=6000, burst=100)
    previous = settings.pw_redact_api_key
    settings.pw_redact_api_key = "test-only-key-not-a-secret-0123456789"
    yield {"Authorization": "Bearer test-only-key-not-a-secret-0123456789"}
    settings.pw_redact_api_key = previous
    main_module._redactor = None
    main_module._rate_limiter = None


@pytest.mark.asyncio
@pytest.mark.parametrize("text,etype", list(BYPASSES.values()), ids=list(BYPASSES))
async def test_api_redacts_bypass(_app_state, text, etype):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.post("/v1/redact", json={"text": text}, headers=_app_state)
    assert resp.status_code == 200
    body = resp.json()
    assert f"<{etype}_1>" in body["sanitized_text"]
    if etype != "EMAIL":
        assert "6789" not in body["sanitized_text"] and "1111" not in body["sanitized_text"]
