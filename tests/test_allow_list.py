# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact-core

"""Unit tests for Layer 4: allow-list financial data preservation."""

from __future__ import annotations

from pw_redact.redactor.allow_list import compile_allow_patterns, get_allow_terms


def _matches(text: str) -> bool:
    """Return True if text matches any allow-list pattern."""
    patterns = compile_allow_patterns()
    return any(p.fullmatch(text) for p in patterns)


# ── Dollar amounts ──────────────────────────────────────────────────


class TestDollarAmounts:
    def test_dollar_with_commas(self):
        assert _matches("$425,000")

    def test_dollar_k(self):
        assert _matches("$50k")

    def test_dollar_with_cents(self):
        assert _matches("$10.50")

    def test_dollar_million(self):
        assert _matches("$1,200,000")


# ── Numbers with commas ────────────────────────────────────────────


class TestCommaSeparatedNumbers:
    def test_thousands(self):
        assert _matches("425,000")

    def test_small_thousands(self):
        assert _matches("95,000")

    def test_millions(self):
        assert _matches("1,200,000")

    def test_no_commas_not_matched(self):
        # Plain numbers without commas should NOT match this pattern
        # (they might be PII and should be treated with caution)
        assert not _matches("425000")


# ── Percentages ────────────────────────────────────────────────────


class TestPercentages:
    def test_integer_pct(self):
        assert _matches("32%")

    def test_decimal_pct(self):
        assert _matches("6.75%")

    def test_small_pct(self):
        assert _matches("0.95%")


# ── Years ──────────────────────────────────────────────────────────


class TestYears:
    def test_planning_year(self):
        assert _matches("2032")

    def test_current_year(self):
        assert _matches("2026")

    def test_far_future(self):
        assert _matches("2099")

    def test_past_year_not_matched(self):
        # 2019 and earlier not in range
        assert not _matches("2019")


# ── Financial acronyms ─────────────────────────────────────────────


class TestAcronyms:
    def test_agi(self):
        assert _matches("AGI")

    def test_rmd(self):
        assert _matches("RMD")

    def test_529(self):
        assert _matches("529")

    def test_w2(self):
        assert _matches("W2")

    def test_1099(self):
        assert _matches("1099")


# ── Form references ────────────────────────────────────────────────


class TestFormReferences:
    def test_form_1040(self):
        assert _matches("Form 1040")

    def test_schedule_d(self):
        assert _matches("Schedule D")

    def test_irc_section(self):
        assert _matches("IRC §1015")


# ── Ages ───────────────────────────────────────────────────────────


class TestAges:
    def test_age_65(self):
        assert _matches("age 65")

    def test_age_59_5(self):
        assert _matches("age 59.5")

    def test_age_70_5(self):
        assert _matches("age 70.5")


# ── Basis points ───────────────────────────────────────────────────


class TestBasisPoints:
    def test_bps(self):
        assert _matches("250 bps")

    def test_bp_singular(self):
        assert _matches("50 bp")

    def test_basis_points_spelled(self):
        assert _matches("100 basis points")


# ── PII should NOT match ──────────────────────────────────────────


class TestPIINotAllowed:
    def test_ssn_not_allowed(self):
        assert not _matches("123-45-6789")

    def test_phone_not_allowed(self):
        assert not _matches("(610) 555-1234")

    def test_email_not_allowed(self):
        assert not _matches("john@example.com")

    def test_name_not_allowed(self):
        assert not _matches("John Smith")


# ── Allow terms ────────────────────────────────────────────────────


# ── Mortgage / RE acronyms ─────────────────────────────────────────


class TestMortgageAcronyms:
    def test_ltv(self):
        assert _matches("LTV")

    def test_dti(self):
        assert _matches("DTI")

    def test_pmi(self):
        assert _matches("PMI")

    def test_alta(self):
        assert _matches("ALTA")

    def test_tila(self):
        assert _matches("TILA")

    def test_hmda(self):
        assert _matches("HMDA")

    def test_arm(self):
        assert _matches("ARM")

    def test_heloc(self):
        assert _matches("HELOC")

    def test_voe(self):
        assert _matches("VOE")


# ── Allow terms ────────────────────────────────────────────────────


class TestAllowTerms:
    def test_returns_list(self):
        terms = get_allow_terms()
        assert isinstance(terms, list)
        assert "AGI" in terms
        assert "CUSIP" in terms

    def test_roth_is_not_a_literal_term(self):
        # A literal "Roth" made Presidio drop the surname in "Mr. Roth".
        # The product sense is kept by is_roth_account() instead.
        assert "Roth" not in get_allow_terms()

    def test_mortgage_terms_present(self):
        terms = get_allow_terms()
        assert "LTV" in terms
        assert "ALTA" in terms
        assert "FNMA" in terms
        assert "FHA" in terms
        assert "HOA" in terms


# ── Roth: product vs surname ───────────────────────────────────────


class TestIsRothAccount:
    @staticmethod
    def _check(text: str, word: str = "Roth") -> bool:
        from pw_redact.redactor.allow_list import is_roth_account

        start = text.index(word)
        return is_roth_account(text, start, start + len(word))

    def test_roth_ira(self):
        assert self._check("Open a Roth IRA.")

    def test_roth_401k(self):
        assert self._check("Use the Roth 401(k).")

    def test_roth_conversion(self):
        assert self._check("Roth conversion of 50,000")

    def test_backdoor_roth(self):
        assert self._check("Explore backdoor Roth.")

    def test_whole_span_roth_ira(self):
        assert self._check("Fund the Roth IRA.", "Roth IRA")

    def test_honorific_is_person(self):
        assert not self._check("Mr. Roth called.")
        assert not self._check("Mrs. Roth IRA questions")  # honorific wins

    def test_bare_name_is_person(self):
        assert not self._check("I spoke with Roth yesterday.")

    def test_possessive_is_person(self):
        assert not self._check("Roth's daughter called.")

    def test_other_word_not_matched(self):
        assert not self._check("Rothschild called.", "Rothschild")
