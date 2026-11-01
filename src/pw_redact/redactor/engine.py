# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact-core

"""PWRedactor engine — orchestrates four-layer PII redaction."""

from __future__ import annotations

import unicodedata
import uuid
from dataclasses import dataclass

from .allow_list import compile_allow_patterns, get_allow_terms
from .manifest import PlaceholderEntry, RedactionManifest
from .presidio_config import create_analyzer
from .regex_patterns import DetectedEntity, detect_regex
from .unicode_canon import canonicalize, to_original_span

# Map Presidio entity type names to canonical names
_TYPE_MAP: dict[str, str] = {
    "EMAIL_ADDRESS": "EMAIL",
    "PHONE_NUMBER": "US_PHONE",
}

# Entity types to request from Presidio per document context
_CONTEXT_ENTITIES: dict[str, list[str]] = {
    "meeting_transcript": [
        "PERSON",
        "LOCATION",
        "PHONE_NUMBER",
        "EMAIL_ADDRESS",
        "US_SSN",
        "CREDIT_CARD",
        "NRP",
        "ACCOUNT_REF",
        "POLICY_NUMBER",
    ],
    "tax_return": [
        "PERSON",
        "LOCATION",
        "PHONE_NUMBER",
        "EMAIL_ADDRESS",
        "US_SSN",
        "CREDIT_CARD",
        "ACCOUNT_REF",
    ],
    "financial_notes": [
        "PERSON",
        "LOCATION",
        "PHONE_NUMBER",
        "EMAIL_ADDRESS",
        "US_SSN",
        "CREDIT_CARD",
        "CUSIP",
        "ACCOUNT_REF",
        "POLICY_NUMBER",
    ],
    "general": [
        "PERSON",
        "LOCATION",
        "PHONE_NUMBER",
        "EMAIL_ADDRESS",
        "US_SSN",
        "CREDIT_CARD",
    ],
    "mortgage": [
        "PERSON",
        "LOCATION",
        "PHONE_NUMBER",
        "EMAIL_ADDRESS",
        "US_SSN",
        "CREDIT_CARD",
        "NRP",
        "ACCOUNT_REF",
        "POLICY_NUMBER",
    ],
    "real_estate": [
        "PERSON",
        "LOCATION",
        "PHONE_NUMBER",
        "EMAIL_ADDRESS",
        "US_SSN",
        "CREDIT_CARD",
        "ACCOUNT_REF",
        "POLICY_NUMBER",
    ],
}


@dataclass
class RedactionResult:
    """Result of PII redaction."""

    sanitized_text: str
    manifest: RedactionManifest


class PWRedactor:
    """
    Protocol Wealth PII Redactor.

    Orchestrates four-layer redaction:
    1. Deterministic regex (high-confidence structured PII)
    2. Presidio NLP (names, addresses, contextual PII)
    3. Custom financial recognizers (CUSIP, account refs, policy numbers)
    4. Allow-list filtering (preserve financial data)
    """

    def __init__(self) -> None:
        self._analyzer = create_analyzer()
        self._allow_patterns = compile_allow_patterns()
        self._allow_terms = get_allow_terms()

    def redact(
        self,
        text: str,
        context: str = "general",
        options: dict | None = None,
    ) -> RedactionResult:
        """
        Redact PII from text.

        Args:
            text: Raw input text potentially containing PII.
            context: One of meeting_transcript, tax_return, financial_notes, general.
            options: Reserved for future use (redaction_style, preserve flags).

        Returns:
            RedactionResult with sanitized_text and manifest.
        """
        # NFC composes decomposed forms (NFD "e" + combining acute -> "é").
        # It does NOT remove soft hyphens or zero-width characters, nor map
        # look-alike dashes and spaces; detection handles those on a
        # canonical copy (see _find_entities). Offsets below are in this
        # NFC text, which is also the text the sanitized output is built from.
        text = unicodedata.normalize("NFC", text)

        # Per-request state for placeholder consistency
        placeholder_map: dict[str, str] = {}
        type_counters: dict[str, int] = {}

        # Steps 1-4: regex, Presidio, merge, allow-list
        filtered = self._find_entities(text, context)

        # Step 5: Generate placeholders and build manifest entries
        filtered.sort(key=lambda e: e.start)

        manifest_entries: list[PlaceholderEntry] = []
        for entity in filtered:
            if entity.text in placeholder_map:
                placeholder = placeholder_map[entity.text]
            else:
                type_counters[entity.entity_type] = type_counters.get(entity.entity_type, 0) + 1
                placeholder = f"<{entity.entity_type}_{type_counters[entity.entity_type]}>"
                placeholder_map[entity.text] = placeholder

            manifest_entries.append(
                PlaceholderEntry(
                    placeholder=placeholder,
                    original=entity.text,
                    entity_type=entity.entity_type,
                    start=entity.start,
                    end=entity.end,
                )
            )

        # Step 6: Build sanitized text (replace end-to-start to preserve positions)
        sanitized = text
        for entry in reversed(manifest_entries):
            sanitized = sanitized[: entry.start] + entry.placeholder + sanitized[entry.end :]

        # Step 7: Build result
        manifest = RedactionManifest(
            redaction_id=f"red_{uuid.uuid4().hex[:8]}",
            placeholders=manifest_entries,
            original_length=len(text),
            sanitized_length=len(sanitized),
        )

        return RedactionResult(sanitized_text=sanitized, manifest=manifest)

    def detect(self, text: str, context: str = "general") -> list[DetectedEntity]:
        """Detect PII locations without redacting. For UI highlighting."""
        text = unicodedata.normalize("NFC", text)
        return self._find_entities(text, context)

    def _find_entities(self, text: str, context: str) -> list[DetectedEntity]:
        """Run Layers 1-4 on a canonical copy of ``text``; return spans of ``text``.

        Detection runs on ``canonicalize(text)``: look-alike dashes become
        "-", look-alike spaces become " ", and invisible characters (zero-width,
        soft hyphen, bidi controls) are dropped, so an SSN written with U+2011
        non-breaking hyphens, or with a zero-width space inside it, matches the
        SSN pattern. Every returned span and ``text`` value is mapped back to
        ``text`` itself, so the manifest keeps the caller's exact original for
        rehydration and replacement covers the whole value, hidden characters
        included.
        """
        canon, index_map = canonicalize(text)

        # Layer 1: deterministic regex
        regex_entities = detect_regex(canon)

        # Layers 2 + 3: Presidio NLP and custom recognizers
        entities_to_detect = _CONTEXT_ENTITIES.get(context, _CONTEXT_ENTITIES["general"])
        presidio_results = self._analyzer.analyze(
            text=canon,
            entities=entities_to_detect,
            language="en",
            allow_list=self._allow_terms,
        )
        nlp_entities = [
            DetectedEntity(
                entity_type=_TYPE_MAP.get(r.entity_type, r.entity_type),
                start=r.start,
                end=r.end,
                score=r.score,
                text=canon[r.start : r.end],
            )
            for r in presidio_results
        ]

        # Merge and deduplicate (regex preferred on ties)
        merged = _merge_entities(regex_entities, nlp_entities)

        # Layer 4: allow-list, judged on the canonical text the patterns expect
        kept = [e for e in merged if not any(p.fullmatch(e.text) for p in self._allow_patterns)]

        mapped: list[DetectedEntity] = []
        for e in kept:
            start, end = to_original_span(index_map, e.start, e.end)
            mapped.append(
                DetectedEntity(
                    entity_type=e.entity_type,
                    start=start,
                    end=end,
                    score=e.score,
                    text=text[start:end],
                )
            )
        return mapped


def _merge_entities(
    regex_entities: list[DetectedEntity],
    nlp_entities: list[DetectedEntity],
) -> list[DetectedEntity]:
    """Merge regex and NLP entities, deduplicating overlaps.

    When two detections overlap, the higher-scoring one wins.
    Regex wins ties (lower source priority value).
    """
    # Tag with source: 0 = regex (preferred), 1 = NLP
    tagged: list[tuple[DetectedEntity, int]] = []
    for e in regex_entities:
        tagged.append((e, 0))
    for e in nlp_entities:
        tagged.append((e, 1))

    # Sort by start position, then score descending, then source (regex first)
    tagged.sort(key=lambda t: (t[0].start, -t[0].score, t[1]))

    merged: list[DetectedEntity] = []
    for entity, _source in tagged:
        if merged and entity.start < merged[-1].end:
            # Overlapping — keep the better detection
            prev = merged[-1]
            if entity.score > prev.score:
                merged[-1] = entity
            elif entity.score == prev.score and (entity.end - entity.start) > (
                prev.end - prev.start
            ):
                # Same score, prefer longer span
                merged[-1] = entity
        else:
            merged.append(entity)

    return merged
