# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact-core

"""Layer 1: Deterministic regex patterns for structured PII detection."""

from __future__ import annotations

from dataclasses import dataclass

import regex as re  # Use 'regex' module for possessive quantifiers (ReDoS protection)


@dataclass(frozen=True)
class DetectedEntity:
    """A PII entity detected by any layer."""

    entity_type: str
    start: int
    end: int
    score: float
    text: str


@dataclass(frozen=True)
class _PatternDef:
    """Internal definition of a regex pattern."""

    regex: str
    score: float
    group: int = 0  # 0 = full match, 1+ = capture group index


# Keyword-triggered identifier patterns (LOAN_NUMBER, PARCEL_NUMBER, MLS_NUMBER,
# FILE_REFERENCE, and POLICY_NUMBER in financial_recognizers.py) require the
# captured value to contain a digit (the "(?=...\d)" lookahead). Without that,
# the next ordinary word was redacted: "loan application", "title insurance",
# "listing agreement". Identifiers made only of letters are no longer caught.
#
# KEYWORD_START: the keyword is not inside a lowercase word ("denote", "PLANPLAN"),
# but it may follow "_", a digit or punctuation ("client_loan", "2Mortgage"), or
# start a camelCase part ("HomeLoan", "2ndMortgage"). The case-sensitive parts
# use (?-i:...) because the patterns, and Presidio's flags, are case-insensitive.
KEYWORD_START = r"(?:(?<![a-zA-Z])|(?<=(?-i:[a-z]))(?=(?-i:[A-Z])))"

# Patterns ordered by specificity (highest first).
# When two patterns match the same span, the higher-score one wins.
PATTERN_DEFS: dict[str, _PatternDef] = {
    # --- Structured secrets (highest confidence) ---
    "JWT": _PatternDef(
        regex=r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
        score=1.0,
    ),
    "DB_URL": _PatternDef(
        regex=r"(?:postgres|mysql|mongodb|redis)://[^:\s]+:[^@\s]+@[^\s]*",
        score=0.95,
    ),
    "BEARER_TOKEN": _PatternDef(
        regex=r"Bearer\s+([A-Za-z0-9._-]{20,})",
        score=0.90,
        group=1,
    ),
    "API_KEY": _PatternDef(
        regex=r"""(?i)["\']?(?:api[_-]?key|apikey)["\']?\s*[=:]\s*["\']?([A-Za-z0-9._-]{10,})["\']?""",
        score=0.85,
        group=1,
    ),
    "PASSWORD": _PatternDef(
        regex=r"""(?i)["\']?(?:password|passwd)["\']?\s*[=:]\s*["\']?([^"\'\s,}]{3,})["\']?""",
        score=0.90,
        group=1,
    ),
    "SECRET_VALUE": _PatternDef(
        regex=r"""(?i)["\']?(?:client_secret|secret_access_key|secret_key|secret|private_key|credential)["\']?\s*[=:]\s*["\']?([A-Za-z0-9._+/=-]{10,})["\']?""",
        score=0.85,
        group=1,
    ),
    "AUTH_TOKEN": _PatternDef(
        regex=r"""(?i)["\']?(?:access_token|refresh_token|id_token|session_id|csrf_token)["\']?\s*[=:]\s*["\']?([A-Za-z0-9._-]{20,})["\']?""",
        score=0.85,
        group=1,
    ),
    "MAGIC_LINK": _PatternDef(
        regex=r"""(?i)(?:magic[_-]?link|reset[_-]?link|verification[_-]?link)["\']?\s*[=:]\s*["\']?([^\s"\']{20,})["\']?""",
        score=0.85,
        group=1,
    ),
    # --- Crypto keys and addresses ---
    "CRYPTO_PRIVATE_KEY": _PatternDef(
        regex=r"\b0x[a-fA-F0-9]{64}\b",
        score=0.95,
    ),
    "CRYPTO_ADDRESS": _PatternDef(
        regex=r"\b0x[a-fA-F0-9]{40}\b",
        score=0.85,
    ),
    "CRYPTO_SEED": _PatternDef(
        regex=(
            r"""(?i)(?:seed\s*phrase|mnemonic|recovery\s*(?:phrase|words?))"""
            r"""[:\s=]*["\'](.+?)["\']"""
        ),
        score=0.95,
        group=1,
    ),
    # --- Financial identifiers ---
    "CREDIT_CARD": _PatternDef(
        regex=r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
        score=0.95,
    ),
    "US_SSN": _PatternDef(
        regex=r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b",
        score=0.90,
    ),
    "EMAIL": _PatternDef(
        regex=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        score=0.95,
    ),
    # --- Context-dependent patterns ---
    "DATE_OF_BIRTH": _PatternDef(
        regex=(
            r"(?i)\b(?:DOB|born|birthday|birth.?date|date.?of.?birth)"
            r"[:\s=]*(\d{4}[-/]\d{1,2}[-/]\d{1,2}|\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b"
        ),
        score=0.85,
        group=1,
    ),
    "EIN": _PatternDef(
        regex=r"\b\d{2}-\d{7}\b",  # Require hyphen to distinguish from bare 9-digit numbers
        score=0.80,
    ),
    "US_PHONE": _PatternDef(
        regex=r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
        score=0.80,
    ),
    "ACCOUNT_NUMBER": _PatternDef(
        regex=r"(?i)\b(?:(?:account|acct?)\.?\s*(?:#|no\.?|number)?:?\s*)(\d{6,17})\b",
        score=0.85,
        group=1,
    ),
    # --- PII filter patterns ---
    "US_ROUTING": _PatternDef(
        regex=r"(?i)(?:routing|aba|transit)\s*(?:(?:#|no\.?|number)\s*)?(?::?\s*)([0-3]\d{8})\b",
        score=0.80,
        group=1,
    ),
    "DRIVERS_LICENSE": _PatternDef(
        regex=r"(?i)(?:driver'?s?\s*(?:license|lic\.?)|DL)\s*(?:[#:]\s*)?([A-Za-z]\d{7,14})\b",
        score=0.75,
        group=1,
    ),
    "STREET_ADDRESS": _PatternDef(
        regex=(
            r"(?i)\b\d{1,5}\s++(?:[A-Za-z]++\s++){1,3}"  # possessive ++ prevents ReDoS
            r"(?:St|Street|Ave|Avenue|Blvd|Boulevard|Dr|Drive|Ln|Lane|"
            r"Rd|Road|Ct|Court|Way|Pl|Place|Cir|Circle)"
            r"\.?\b(?:\s*+(?:#|Ste|Suite|Apt|Unit)\s*+\w++)?"
        ),
        score=0.70,
    ),
    # --- Mortgage / Real Estate / Title ---
    "NMLS_ID": _PatternDef(
        regex=(
            r"(?i)(?:NMLS|MLO)\s*(?:(?:#|no\.?|number|id)\s*)?(?:[#:=]\s*)?"
            r"(\d{5,12})\b"
        ),
        score=0.80,
        group=1,
    ),
    "LOAN_NUMBER": _PatternDef(
        regex=(
            r"(?i)" + KEYWORD_START + r"(?:loan|mortgage|note)\s*(?:(?:#|no\.?|number|id)\s*)?"
            r"(?:[#:=]\s*)?((?=[-A-Z0-9]{0,19}\d)[A-Z0-9][-A-Z0-9]{7,19})\b"
        ),
        score=0.80,
        group=1,
    ),
    "MERS_MIN": _PatternDef(
        regex=r"(?i)(?:MERS|MIN)\s*(?:[#:=]\s*)?(\d{18})\b",
        score=0.85,
        group=1,
    ),
    "FHA_CASE_NUMBER": _PatternDef(
        regex=(
            r"(?i)(?:FHA|VA|USDA)\s*(?:case)?\s*(?:[#:=]\s*)?"
            r"(\d{3}-\d{7}(?:-\d{3})?)\b"
        ),
        score=0.85,
        group=1,
    ),
    "PARCEL_NUMBER": _PatternDef(
        regex=(
            r"(?i)"
            + KEYWORD_START
            + r"(?:APN|parcel|tax\s*+(?:parcel|id|lot)|property\s*+(?:index|id|PIN)"
            r"|assessor)\s*+(?:(?:#|no\.?|number)\s*+)?(?:[#:=]\s*+)?"
            r"((?=[-A-Z0-9./]{0,24}\d)[A-Z0-9][-A-Z0-9./]{4,24}+)\b"
        ),
        score=0.80,
        group=1,
    ),
    "MLS_NUMBER": _PatternDef(
        regex=(
            r"(?i)" + KEYWORD_START + r"(?:MLS|listing)\s*(?:(?:#|no\.?|number|id)\s*)?"
            r"(?:[#:=]\s*)?((?=[A-Z0-9]{0,14}\d)[A-Z0-9]{6,15})\b"
        ),
        score=0.75,
        group=1,
    ),
    "FILE_REFERENCE": _PatternDef(
        regex=(
            r"(?i)" + KEYWORD_START + r"(?:escrow|title|closing|instrument|recording|document)"
            r"\s*(?:(?:#|no\.?|number)\s*)?(?:[#:=]\s*)?"
            r"((?=[-A-Z0-9]{0,19}\d)[A-Z0-9][-A-Z0-9]{5,19})\b"
        ),
        score=0.75,
        group=1,
    ),
    # --- Internal system identifiers (vendor-agnostic) ---
    "CRM_ID": _PatternDef(
        regex=(
            r"(?i)(?:crm|contact[_\s]?id|client[_\s]?id|customer[_\s]?id"
            r"|lead[_\s]?id|record[_\s]?id|advisor[_\s]?id)"
            r"\s*(?:[#:=]\s*)?(\d{4,10})\b"
        ),
        score=0.85,
        group=1,
    ),
    "PLATFORM_ID": _PatternDef(
        regex=(
            r"(?i)(?:org[_\s]?id|sub[_\s]?org|tenant[_\s]?id|workspace[_\s]?id"
            r"|vault[_\s]?id|signer[_\s]?id|key[_\s]?id|wallet[_\s]?id)"
            r"\s*(?:[#:=]\s*)?([a-f0-9][a-f0-9-]{19,})\b"
        ),
        score=0.75,
        group=1,
    ),
}

# Compiled patterns (lazy-initialized)
_compiled: dict[str, re.Pattern[str]] = {}


def _get_compiled() -> dict[str, re.Pattern[str]]:
    if not _compiled:
        for name, pdef in PATTERN_DEFS.items():
            _compiled[name] = re.compile(pdef.regex)
    return _compiled


def detect_regex(text: str) -> list[DetectedEntity]:
    """Run all regex patterns against text, return detected entities."""
    compiled = _get_compiled()
    entities: list[DetectedEntity] = []

    for entity_type, pattern in compiled.items():
        pdef = PATTERN_DEFS[entity_type]
        for match in pattern.finditer(text):
            if pdef.group > 0 and match.lastindex and match.lastindex >= pdef.group:
                start = match.start(pdef.group)
                end = match.end(pdef.group)
                matched_text = match.group(pdef.group)
            else:
                start = match.start()
                end = match.end()
                matched_text = match.group()

            entities.append(
                DetectedEntity(
                    entity_type=entity_type,
                    start=start,
                    end=end,
                    score=pdef.score,
                    text=matched_text,
                )
            )

    return entities
