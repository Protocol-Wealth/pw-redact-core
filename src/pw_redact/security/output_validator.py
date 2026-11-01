# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact-core

"""Output validation — verify no PII leaks in the redaction response."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..redactor.occurrences import MIN_MATCH_LENGTH, find_occurrences, fold

# Valid placeholder format: <TYPE_N> where TYPE is uppercase/underscore, N is digits
_VALID_PLACEHOLDER = re.compile(r"<[A-Z][A-Z_]*_\d+>")

# An entity type is echoed in a warning only if it looks like one of ours, so a
# warning never carries caller content.
_ENTITY_TYPE = re.compile(r"[A-Z][A-Z0-9_]{0,63}")


@dataclass
class OutputValidationResult:
    """Result of output validation.

    ``is_valid`` is False on any warning. ``safe_to_return`` is False only when
    the output must be withheld: an original value is still in the text, the
    manifest is malformed, or the check itself failed. A placeholder-format
    warning alone stays advisory, since caller text may contain ``<...>``.

    Warnings are fixed codes (``pii_leak:US_SSN``, ``invalid_placeholder_format``).
    They never contain text from the input or the manifest originals.
    """

    is_valid: bool = True
    warnings: list[str] = field(default_factory=list)
    safe_to_return: bool = True


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

    # Look for originals in the text with its own placeholders blanked out, so
    # "<PERSON_1>" itself never counts as an occurrence of "person".
    masked = _VALID_PLACEHOLDER.sub(lambda m: " " * len(m.group()), sanitized_text)
    folded = fold(masked)

    # Check no original values leaked into sanitized text. The comparison
    # ignores case, look-alike dashes and spaces, invisible characters and
    # whitespace runs (see redactor/occurrences.py), so "JOHN SMITH" or
    # "ab123456" counts as a leak of "John Smith" or "AB123456".
    for i, entry in enumerate(placeholders):
        if not isinstance(entry, dict):
            warnings.append(f"manifest_entry_{i}_not_dict")
            unsafe = True
            continue

        original = entry.get("original", "")
        entity_type = entry.get("entity_type", "UNKNOWN")
        if not isinstance(original, str):
            raise TypeError(f"manifest entry {i} original is not a string")
        if not isinstance(entity_type, str) or not _ENTITY_TYPE.fullmatch(entity_type):
            entity_type = "UNKNOWN"

        # Only check values long enough to be meaningful
        if len(fold(original)[0].strip(" ")) >= MIN_MATCH_LENGTH:
            if find_occurrences(original, masked, folded):
                warnings.append(f"pii_leak:{entity_type}")
                unsafe = True

    # Check all placeholders in text match valid format. The code carries no
    # text: the "<...>" found is caller content and may hold PII.
    for ph in re.findall(r"<[^>]+>", sanitized_text):
        if not _VALID_PLACEHOLDER.fullmatch(ph):
            warnings.append("invalid_placeholder_format")

    # One entry per code
    warnings = list(dict.fromkeys(warnings))

    return OutputValidationResult(
        is_valid=len(warnings) == 0,
        warnings=warnings,
        safe_to_return=not unsafe,
    )
