# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact-core

"""Layer 3: Custom Presidio recognizers for financial advisory entities."""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer


def get_financial_recognizers() -> list[PatternRecognizer]:
    """Return custom recognizers for financial advisory context."""
    recognizers: list[PatternRecognizer] = []

    # CUSIP — 9 characters: 6 alphanumeric issuer + 2 alphanumeric issue + 1 check digit
    cusip = PatternRecognizer(
        supported_entity="CUSIP",
        name="cusip_recognizer",
        patterns=[Pattern("cusip", r"\b[A-Z0-9]{6}[A-Z0-9]{2}[0-9]\b", 0.6)],
        context=["cusip", "security", "holding", "fund", "isin"],
    )
    recognizers.append(cusip)

    # Account references — "account ending in 7890", "acct #12345678"
    account_ref = PatternRecognizer(
        supported_entity="ACCOUNT_REF",
        name="account_ref_recognizer",
        patterns=[
            Pattern(
                "acct_ending",
                r"(?i)(?:account|acct)\s+ending\s+in\s+(\d{4,})",
                0.8,
            ),
            Pattern(
                "acct_number",
                r"(?i)(?:account|acct)[\s#]*(\d{4,})",
                0.6,
            ),
        ],
    )
    recognizers.append(account_ref)

    # Policy / plan / contract numbers
    policy = PatternRecognizer(
        supported_entity="POLICY_NUMBER",
        name="policy_number_recognizer",
        patterns=[
            Pattern(
                "policy",
                # The value must contain a digit, so "plan contributions" or
                # "contract renewal" is not taken for a policy number.
                r"(?i)\b(?:policy|plan|contract)[\s#:]*((?=[A-Z0-9]{0,19}\d)[A-Z0-9]{6,20})\b",
                0.6,
            ),
        ],
    )
    recognizers.append(policy)

    return recognizers
