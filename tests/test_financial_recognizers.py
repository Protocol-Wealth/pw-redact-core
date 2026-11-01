# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact-core

"""Unit tests for Layer 3: custom financial Presidio recognizers."""

from __future__ import annotations

import pytest

from pw_redact.redactor.financial_recognizers import get_financial_recognizers


def _get_recognizer(entity_type: str):
    """Find recognizer supporting the given entity type."""
    for r in get_financial_recognizers():
        if entity_type in r.supported_entities:
            return r
    raise ValueError(f"No recognizer for {entity_type}")


# ── CUSIP ───────────────────────────────────────────────────────────


class TestCUSIP:
    def test_valid_cusip(self):
        rec = _get_recognizer("CUSIP")
        results = rec.analyze("CUSIP: 594918104", ["CUSIP"])
        assert any(r.entity_type == "CUSIP" for r in results)

    def test_cusip_with_context(self):
        rec = _get_recognizer("CUSIP")
        results = rec.analyze("The security 037833100 in portfolio", ["CUSIP"])
        assert any(r.entity_type == "CUSIP" for r in results)

    def test_short_string_not_cusip(self):
        rec = _get_recognizer("CUSIP")
        results = rec.analyze("Code: ABC12", ["CUSIP"])
        assert not any(r.entity_type == "CUSIP" for r in results)


# ── ACCOUNT_REF ────────────────────────────────────────────────────


class TestAccountRef:
    def test_ending_in(self):
        rec = _get_recognizer("ACCOUNT_REF")
        results = rec.analyze("account ending in 7890", ["ACCOUNT_REF"])
        assert any(r.entity_type == "ACCOUNT_REF" for r in results)

    def test_acct_hash(self):
        rec = _get_recognizer("ACCOUNT_REF")
        results = rec.analyze("acct#12345678", ["ACCOUNT_REF"])
        assert any(r.entity_type == "ACCOUNT_REF" for r in results)

    def test_no_context(self):
        rec = _get_recognizer("ACCOUNT_REF")
        results = rec.analyze("The number 7890", ["ACCOUNT_REF"])
        assert not any(r.entity_type == "ACCOUNT_REF" for r in results)


# ── POLICY_NUMBER ──────────────────────────────────────────────────


class TestPolicyNumber:
    def test_policy_number(self):
        rec = _get_recognizer("POLICY_NUMBER")
        results = rec.analyze("policy#ABC123DEF456", ["POLICY_NUMBER"])
        assert any(r.entity_type == "POLICY_NUMBER" for r in results)

    def test_plan_number(self):
        rec = _get_recognizer("POLICY_NUMBER")
        results = rec.analyze("plan: RETIRE2025X", ["POLICY_NUMBER"])
        assert any(r.entity_type == "POLICY_NUMBER" for r in results)

    def test_no_context(self):
        rec = _get_recognizer("POLICY_NUMBER")
        results = rec.analyze("value: ABC123DEF456", ["POLICY_NUMBER"])
        assert not any(r.entity_type == "POLICY_NUMBER" for r in results)


class TestPolicyNumberNoOverRedaction:
    @pytest.mark.parametrize(
        "text",
        [
            "The contract renewal is due.",
            "Plan contributions increased.",
            "The policy holders were notified.",
            "We will plan accordingly.",
        ],
    )
    def test_ordinary_words_not_detected(self, text):
        rec = _get_recognizer("POLICY_NUMBER")
        assert rec.analyze(text, ["POLICY_NUMBER"]) == []

    def test_keyword_inside_word_not_detected(self):
        rec = _get_recognizer("POLICY_NUMBER")
        assert rec.analyze("airplane AB1234567", ["POLICY_NUMBER"]) == []

    def test_contract_number_still_detected(self):
        rec = _get_recognizer("POLICY_NUMBER")
        results = rec.analyze("contract # VA2025000123", ["POLICY_NUMBER"])
        assert any(r.entity_type == "POLICY_NUMBER" for r in results)


class TestPolicyNumberBounds:
    def test_long_number_fully_covered(self):
        # With a trailing \b and a 20-character bound this was missed entirely.
        text = "Policy: 123456789012345678901"
        rec = _get_recognizer("POLICY_NUMBER")
        spans = [text[r.start : r.end] for r in rec.analyze(text, ["POLICY_NUMBER"])]
        assert spans == [text]

    @pytest.mark.parametrize("text", ["MyPlan 1234567", "group_policy: AB123456"])
    def test_keyword_after_camel_case_or_underscore(self, text):
        rec = _get_recognizer("POLICY_NUMBER")
        assert rec.analyze(text, ["POLICY_NUMBER"])

    def test_keyword_inside_upper_word_not_detected(self):
        rec = _get_recognizer("POLICY_NUMBER")
        assert rec.analyze("PLANPLAN 1234567", ["POLICY_NUMBER"]) == []


class TestPolicyNumberFullRun:
    @pytest.mark.parametrize("length", [64, 65, 70, 500])
    def test_whole_value_covered(self, length):
        value = "1" * length
        text = f"Policy {value} on file"
        rec = _get_recognizer("POLICY_NUMBER")
        spans = [(r.start, r.end) for r in rec.analyze(text, ["POLICY_NUMBER"])]
        assert spans == [(0, len("Policy ") + length)]

    def test_quarter_is_not_a_policy_number(self):
        rec = _get_recognizer("POLICY_NUMBER")
        assert rec.analyze("The contract 2025Q1 renewal", ["POLICY_NUMBER"]) == []
        assert rec.analyze("plan: 2025q4", ["POLICY_NUMBER"]) == []

    def test_quarter_prefix_of_longer_id_still_detected(self):
        rec = _get_recognizer("POLICY_NUMBER")
        assert rec.analyze("contract 2025Q1A77", ["POLICY_NUMBER"])

    @pytest.mark.parametrize(
        "text",
        [
            "Plan" * 25_000 + "1",
            "PLAN" * 25_000,
            "policy " + "A" * 100_000,
            "policy " + "1" * 100_000,
            ("policy " + "A" * 70 + " ") * 1_300,
        ],
        ids=["camel-repeat", "upper-repeat", "no-digit-run", "digit-run", "many-no-digit"],
    )
    def test_100kb_inputs_are_fast(self, text):
        import time

        rec = _get_recognizer("POLICY_NUMBER")
        start = time.perf_counter()
        rec.analyze(text, ["POLICY_NUMBER"])
        assert time.perf_counter() - start < 1.0
