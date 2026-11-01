# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact-core

"""Layer 4: Allow-list patterns for financial data that must survive redaction."""

from __future__ import annotations

import re

# Regex patterns for financial data that should NEVER be redacted.
# These are checked against detected entity text via re.fullmatch().
ALLOW_PATTERNS: list[str] = [
    # Dollar amounts: $425,000  $50k  $10.50  $1,200,000
    r"\$[\d,]+(?:\.\d{1,2})?(?:[kKmMbB])?",
    # Numbers with commas (must have at least one comma group): 425,000  1,200,000
    r"\d{1,3}(?:,\d{3})+(?:\.\d{1,2})?",
    # Percentages: 32%  6.75%  0.95%
    r"\d+\.?\d*\s*%",
    # Tax bracket references: "32% bracket"  "24% rate"
    r"(?:10|12|22|24|32|35|37)\s*%\s*(?:bracket|rate|tier)",
    # Basis points: 250 bps  50bp
    r"\d+\s*(?:bps?|basis\s+points?)",
    # Planning years: 2024-2099
    r"20[2-9]\d",
    # Ages and milestones: age 59.5  age 70.5  age 65
    r"(?i)age\s+\d{1,3}(?:\.\d)?",
    # IRS form references: Form 1040  Schedule D  IRC §1015
    r"(?:Form|Schedule|IRC\s*§?)\s*[A-Z0-9§.-]+",
    # Financial acronyms
    r"(?:AGI|MAGI|QBI|RMD|QCD|NUA|IRA|SEP|SIMPLE|401k|403b|457b|529|HSA|FSA|W2|W-2|1099)",
    # Mortgage / underwriting / real estate acronyms
    r"(?:LTV|DTI|PMI|PITI|MIP|UFMIP|ARM|FRM|HELOC|HEL)",
    r"(?:TILA|RESPA|ECOA|HMDA|TRID|URLA|QM|ATR)",
    r"(?:DU|LP|AUS|GFE|LE|CD|HUD)",
    r"(?:ALTA|CLTA|CPL|FNMA|FHLMC|GNMA)",
    r"(?:VOE|VOD|VOM|VOR)",
]

# Literal strings passed to Presidio's allow_list parameter.
# These are exact-match exclusions from NLP detection.
ALLOW_TERMS: list[str] = [
    "AGI",
    "MAGI",
    "QBI",
    "RMD",
    "QCD",
    "NUA",
    "IRA",
    "SEP",
    "SIMPLE",
    "HSA",
    "FSA",
    # "Roth" is deliberately absent: it is also a surname ("Mr. Roth"), and a
    # literal entry here made Presidio drop every lone "Roth" PERSON detection.
    # is_roth_account() keeps the product sense instead, from its context.
    "FICO",
    "CUSIP",
    "ISIN",
    "ETF",
    "NAV",
    "AUM",
    "EBITDA",
    "P/E",
    "EPS",
    "ROI",
    "ROE",
    "CROIC",
    "W2",
    "W-2",
    "1099",
    # Mortgage / underwriting / real estate
    "LTV",
    "DTI",
    "PMI",
    "PITI",
    "MIP",
    "ARM",
    "FRM",
    "HELOC",
    "TILA",
    "RESPA",
    "ECOA",
    "HMDA",
    "TRID",
    "URLA",
    "ALTA",
    "CLTA",
    "FNMA",
    "FHLMC",
    "GNMA",
    "FHA",
    "HUD",
    "VOE",
    "VOD",
    "VOM",
    "QM",
    "ATR",
    "DU",
    "LP",
    "AUS",
    "GFE",
    "APR",
    "MERS",
    "MLS",
    "HOA",
    "Fannie Mae",
    "Freddie Mac",
    "Ginnie Mae",
]


# "Roth" as a retirement product. Product context is a product word right after
# ("Roth IRA", "Roth conversion", "Roth vs traditional") or a planning verb or
# "backdoor" right before ("convert to Roth", "max out the Roth", "backdoor
# Roth"). "contribute(d) to" is not product context on its own: "we contributed
# to Roth last year" and "campaign contributions to Roth" are people. With an
# account word after it ("contribute to a Roth IRA", "Roth contribution
# limits") the product word already decides. An article or possessive alone
# is not product context: "the Roth family", "the Roth estate documents" are
# people. When in doubt the detection is kept, i.e. "Roth" is redacted: "I
# asked Roth options he prefers" could be either, so "options" is deliberately
# not a product word.
_ROTH_WORD = re.compile(r"(?i)roth")
_ROTH_PRODUCT_AFTER = re.compile(
    r"(?i)\s*+(?:IRA|401\(?k\)?|403\(?b\)?|457\(?b\)?|TSP|conversions?|"
    r"contributions?|accounts?|ladder|strategy|rollovers?|elections?|limits?|"
    r"deferrals?|assets|balances?|money|funds?|dollars|savings|recharacterization|"
    r"(?:vs\.?|versus|or)\s++(?:a\s++)?traditional)\b"
)
_DETERMINER = r"(?:a|an|the|my|your|his|her|their|our)\s++"
_ROTH_PRODUCT_BEFORE = re.compile(
    r"(?i)\b(?:"
    r"(?:mega\s++)?backdoor"
    r"|conver(?:t|ts|ted|ting|sion)\s++(?:it\s++|them\s++)?(?:to|into)"
    r"|max(?:es|ed|ing)?\s++(?:it\s++)?out"
    r")\s++(?:" + _DETERMINER + r")?$"
)
# An honorific or title right before "Roth" means a person, whatever follows.
_ROTH_PERSON_BEFORE = re.compile(
    r"(?i)\b(?:Mr|Mrs|Ms|Mx|Miss|Dr|Prof|Professor|Judge|Sen|Senator|Rep|Rev|Rabbi|"
    r"Officer|Grandpa|Grandma)\.?\s++$"
)


def is_roth_account(text: str, start: int, end: int) -> bool:
    """True if ``text[start:end]`` is "Roth" used as a retirement product.

    "Roth IRA", "Roth 401(k)", "a Roth conversion", "backdoor Roth" and
    "convert to Roth" are the product; "Mr. Roth", "Judge Roth" and "the Roth
    family" are people and stay detected. ("Jane Roth" never
    reaches this check: the detection is the whole name, not "Roth".)
    A span longer than the word itself (e.g. Presidio's "Roth IRA") is the
    product if it is "Roth" plus a product word.
    """
    span = text[start:end]
    head = _ROTH_WORD.match(span)
    if head is None:
        return False
    rest = span[head.end() :]
    if rest and not _ROTH_PRODUCT_AFTER.fullmatch(rest):
        return False
    before = text[max(0, start - 40) : start]
    if _ROTH_PERSON_BEFORE.search(before):
        return False
    if rest:
        return True
    return bool(_ROTH_PRODUCT_AFTER.match(text, end) or _ROTH_PRODUCT_BEFORE.search(before))


def compile_allow_patterns() -> list[re.Pattern[str]]:
    """Compile allow-list regex patterns for fullmatch checking."""
    return [re.compile(p) for p in ALLOW_PATTERNS]


def get_allow_terms() -> list[str]:
    """Return literal strings for Presidio's built-in allow_list parameter."""
    return list(ALLOW_TERMS)
