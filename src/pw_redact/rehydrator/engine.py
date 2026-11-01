# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact-core

"""Manifest-based placeholder restoration (rehydration) with input validation."""

from __future__ import annotations

import re

# Placeholders must match <UPPER_CASE_N> format
_VALID_PLACEHOLDER = re.compile(r"<[A-Z][A-Z_]*_\d+>")

# Safety limits
MAX_PLACEHOLDERS = 10_000
MAX_ORIGINAL_LENGTH = 1_000


class PWRehydrator:
    """Restores original PII values from placeholders using a redaction manifest."""

    @staticmethod
    def rehydrate(text: str, manifest: dict) -> str:
        """
        Replace placeholders in text with original values from the manifest.

        Args:
            text: Text containing placeholders (e.g. AI model output).
            manifest: Redaction manifest dict with 'placeholders' list.

        Returns:
            Text with placeholders replaced by original values.

        Raises:
            ValueError: If manifest contains invalid placeholder formats or
                        exceeds safety limits.
        """
        if not isinstance(manifest, dict):
            raise ValueError("manifest must be an object")
        placeholders = manifest.get("placeholders", [])

        if not isinstance(placeholders, list):
            raise ValueError("manifest.placeholders must be a list")

        if len(placeholders) > MAX_PLACEHOLDERS:
            raise ValueError(f"manifest contains too many placeholders ({len(placeholders)})")

        result = text
        for entry in placeholders:
            if not isinstance(entry, dict):
                continue

            placeholder = entry.get("placeholder", "")
            original = entry.get("original", "")
            if not isinstance(placeholder, str) or not isinstance(original, str):
                raise ValueError("manifest placeholder and original values must be strings")

            # Validate placeholder format
            if not _VALID_PLACEHOLDER.fullmatch(placeholder):
                raise ValueError(f"invalid placeholder format: {placeholder!r}")

            # Cap original value length
            if len(original) > MAX_ORIGINAL_LENGTH:
                raise ValueError("original value exceeds maximum length")

            result = result.replace(placeholder, original)

        return result
