# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact-core

"""Prompt injection detection — flag suspicious input for caller review.

IMPORTANT: This module DETECTS, it does not BLOCK. Financial advisors may
legitimately paste client emails or documents that contain unusual text.
We flag it and let the caller decide policy.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

INJECTION_THRESHOLD = 0.7


@dataclass
class InjectionResult:
    """Result of prompt injection detection."""

    is_suspicious: bool
    injection_score: float
    detected_patterns: list[str] = field(default_factory=list)


# Each pattern: (compiled regex, label, weight 0.0-1.0)
_PATTERNS: list[tuple[re.Pattern[str], str, float]] = []


def _p(pattern: str, label: str, weight: float, flags: int = re.IGNORECASE) -> None:
    """Register a detection pattern."""
    _PATTERNS.append((re.compile(pattern, flags), label, weight))


# -- Instruction override attempts ------------------------------------------
# Real phrasings put filler words between the verb and the target ("ignore all
# the previous instructions", "disregard any of your prior rules"). Up to four
# filler words are allowed, but at least one must point at earlier or
# model-side instructions (a qualifier like "previous", or "your"/"all"), so
# "ignore the instructions on the form" is not flagged.
_OVERRIDE_VERB = (
    r"(?:ignore|disregard|forget|drop|dismiss|discard|abandon|overlook|skip|set\s+aside)"
)
_FILLER = r"(?:all|any|each|every|the|these|those|of|my|our|its|this|that|above|below)"
_QUALIFIER = (
    r"(?:previous|previously|prior|above|earlier|preceding|foregoing|former|original|"
    r"initial|system|developer|safety|your|all)"
)
_TARGET = (
    r"(?:instructions?|rules?|guidelines?|directions?|directives?|prompts?|commands?|"
    r"context|constraints?|guardrails?)"
)
_WORDS = rf"(?:(?:{_FILLER}|{_QUALIFIER})\s+){{0,3}}"
_OVERRIDE_PHRASE = rf"{_WORDS}{_QUALIFIER}\s+{_WORDS}{_TARGET}\b(?!\s+of\s+thumb)"

_p(rf"\bignore\s+{_OVERRIDE_PHRASE}", "ignore_previous_instructions", 0.95)
_p(r"ignore\s+your\s+instructions?", "ignore_your_instructions", 0.95)
_p(rf"\bdisregard\s+{_OVERRIDE_PHRASE}", "disregard_instructions", 0.90)
_p(
    rf"\b(?!ignore|disregard){_OVERRIDE_VERB}\s+{_OVERRIDE_PHRASE}",
    "forget_instructions",
    0.90,
)
_p(
    rf"\b(?:do\s+not|don'?t|never|stop)\s+(?:follow|obey|listen\s+to)(?:ing)?\s+{_OVERRIDE_PHRASE}",
    "do_not_follow",
    0.90,
)
_p(
    rf"\b{_OVERRIDE_VERB}\s+(?:everything|anything|all)\s+"
    r"(?:(?:that\s+)?(?:was\s+|you\s+were\s+)?(?:said|told|written|stated)\s+)?"
    r"(?:above|before|previously|earlier|so\s+far)\b",
    "ignore_everything_above",
    0.90,
)
_p(
    r"\byou\s+(?:are|'re)\s+no\s+longer\s+(?:bound|restricted|limited)\s+by\b",
    "no_longer_bound",
    0.85,
)

# -- Identity manipulation -------------------------------------------------
_p(r"(?:act|behave|respond)\s+as\s+if\s+you", "act_as_if", 0.80)
_p(r"(?:pretend|imagine|suppose)\s+(?:that\s+)?you\s+are", "pretend_you_are", 0.80)
_p(r"you\s+are\s+now\s+(?:a\s+)?(?:new|different|unrestricted)", "you_are_now", 0.85)
_p(r"\bDAN\b", "dan_jailbreak", 0.60)
_p(r"do\s+anything\s+now", "do_anything_now", 0.85)

# -- Prompt extraction attempts ---------------------------------------------
_p(
    r"(?:reveal|show|display|print|output|repeat)\s+(?:your|the|my)\s+(?:system\s+)?(?:prompt|instructions?|rules?)",
    "reveal_prompt",
    0.85,
)
_p(
    r"what\s+(?:are|were)\s+your\s+(?:original\s+)?(?:instructions?|rules?|guidelines?)",
    "extract_instructions",
    0.80,
)
_p(
    r"(?:show|give|tell)\s+me\s+your\s+(?:system\s+)?(?:prompt|instructions?|rules?)",
    "show_me_instructions",
    0.85,
)

# -- Keyword markers --------------------------------------------------------
_p(r"\b(?:system\s*prompt|override|bypass|jailbreak)\b", "injection_keyword", 0.50)
_p(r"\b(?:injection|exploit|payload)\s*(?:test|attempt|attack)\b", "injection_test_keyword", 0.40)

# -- Encoded / obfuscated variants -----------------------------------------
_p(r"i\s+g\s+n\s+o\s+r\s+e", "spaced_ignore", 0.75)
_p(r"(?:1gn0r3|ign0re|1gnore)\s+(?:previous|prior|your|all)", "leetspeak_ignore", 0.80)
_p(r"(?:s\s*y\s*s\s*t\s*e\s*m|p\s*r\s*o\s*m\s*p\s*t)", "spaced_system_prompt", 0.65)

# -- Role-play / persona injection -----------------------------------------
_p(r"new\s+(?:session|conversation|chat|context)\s*[:\-]", "new_session_marker", 0.70)
_p(r"(?:###|===)\s*(?:system|instruction|new\s+prompt)", "fake_system_delimiter", 0.85)
_p(r"\[(?:system|instruction|INST)\]", "fake_system_tag", 0.80)

# -- Delimiter / context manipulation --------------------------------------
_p(r"<\|(?:im_start|im_end|system|endoftext)\|>", "fake_special_token", 0.90)
_p(r"```\s*system\b", "code_block_system", 0.70)


def detect_injection(text: str) -> InjectionResult:
    """Scan text for prompt injection patterns.

    Returns detection result with confidence score and matched patterns.
    Score > INJECTION_THRESHOLD means suspicious (but NOT blocked).
    """
    detected: list[str] = []
    max_weight = 0.0

    text_lower = text.lower()

    for pattern, label, weight in _PATTERNS:
        if pattern.search(text_lower if pattern.flags & re.IGNORECASE else text):
            detected.append(label)
            if weight > max_weight:
                max_weight = weight

    return InjectionResult(
        is_suspicious=max_weight >= INJECTION_THRESHOLD,
        injection_score=round(max_weight, 2),
        detected_patterns=detected,
    )
