# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact-core

"""Output validation — verify no PII leaks in the redaction response."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Valid placeholder format: <TYPE_N> where TYPE is uppercase/underscore, N is digits
_VALID_PLACEHOLDER = re.compile(r"<[A-Z][A-Z_]*_\d+>")

# Minimum original length to check for leaks (avoids false positives on short
# strings like "Mr", "Dr", "TX" that appear naturally in text)
_MIN_LEAK_CHECK_LENGTH = 5


@dataclass
class OutputValidationResult:
    """Result of output validation.

    ``is_valid`` is False on any warning. ``safe_to_return`` is False only when
    the output must be withheld: an original value is still in the text, the
    manifest is malformed, or the check itself failed. A placeholder-format
    warning alone stays advisory, since caller text may contain ``<...>``.
    """

    is_valid: bool = True
    warnings: list[str] = field(default_factory=list)
    safe_to_return: bool = True


def _leak_pattern(original: str) -> str:
    """Match ``original`` as a whole token.

    The word-boundary guards apply only at ends that are word characters, so a
    value starting or ending with punctuation, like "(212) 555-0199", is still
    found ("\b(" never matches after a space).
    """
    prefix = r"(?<!\w)" if re.match(r"\w", original[0]) else ""
    suffix = r"(?!\w)" if re.match(r"\w", original[-1]) else ""
    return prefix + re.escape(original) + suffix


def validate_output(
    sanitized_text: str,
    manifest: dict,
) -> OutputValidationResult:
    """Validate the redaction output for PII leaks and structural integrity.

    Checks:
    1. No original PII values appear in sanitized_text
    2. All placeholders in sanitized_text match the <TYPE_N> format
    3. Manifest has required structure

    Fails closed: if the check cannot run to completion, the result says the
    output is not safe to return.
    """
    try:
        return _validate_output(sanitized_text, manifest)
    except Exception:  # noqa: BLE001 - any failure here must withhold the output
        return OutputValidationResult(
            is_valid=False, warnings=["output_validation_error"], safe_to_return=False
        )


def _validate_output(sanitized_text: str, manifest: dict) -> OutputValidationResult:
    warnings: list[str] = []
    unsafe = False

    if not isinstance(sanitized_text, str) or not isinstance(manifest, dict):
        raise TypeError("sanitized_text must be str and manifest must be dict")

    # Check manifest structure
    if "placeholders" not in manifest:
        warnings.append("manifest_missing_placeholders")
        unsafe = True
    if "version" not in manifest:
        warnings.append("manifest_missing_version")
    if "redaction_id" not in manifest:
        warnings.append("manifest_missing_redaction_id")

    placeholders = manifest.get("placeholders", [])

    if not isinstance(placeholders, list):
        warnings.append("manifest_placeholders_not_list")
        return OutputValidationResult(is_valid=False, warnings=warnings, safe_to_return=False)

    # Check no original values leaked into sanitized text
    for i, entry in enumerate(placeholders):
        if not isinstance(entry, dict):
            warnings.append(f"manifest_entry_{i}_not_dict")
            unsafe = True
            continue

        original = entry.get("original", "")
        entity_type = entry.get("entity_type", "UNKNOWN")
        if not isinstance(original, str):
            raise TypeError(f"manifest entry {i} original is not a string")

        # Only check strings long enough to be meaningful
        if len(original) >= _MIN_LEAK_CHECK_LENGTH:
            # Word-boundary-aware search to reduce false positives
            # (e.g. "Smith" in "Blacksmith" should not flag)
            if re.search(_leak_pattern(original), sanitized_text):
                warnings.append(f"pii_leak:{entity_type}")
                unsafe = True

    # Check all placeholders in text match valid format
    found_placeholders = re.findall(r"<[^>]+>", sanitized_text)
    for ph in found_placeholders:
        if not _VALID_PLACEHOLDER.fullmatch(ph):
            warnings.append(f"invalid_placeholder_format:{ph}")

    return OutputValidationResult(
        is_valid=len(warnings) == 0,
        warnings=warnings,
        safe_to_return=not unsafe,
    )
