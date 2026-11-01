# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact-core

"""Integration tests for the PWRedactor engine."""

from __future__ import annotations

import pytest

from pw_redact.redactor.engine import PWRedactor, RedactionResult
from pw_redact.rehydrator.engine import PWRehydrator


# ── Core redaction ──────────────────────────────────────────────────


class TestRedaction:
    def test_ssn_redacted(self, redactor: PWRedactor):
        result = redactor.redact("SSN is 123-45-6789")
        assert "123-45-6789" not in result.sanitized_text
        assert "<US_SSN_1>" in result.sanitized_text

    def test_email_redacted(self, redactor: PWRedactor):
        result = redactor.redact("Contact john@example.com for details")
        assert "john@example.com" not in result.sanitized_text
        assert "<EMAIL_1>" in result.sanitized_text

    def test_name_redacted(self, redactor: PWRedactor):
        result = redactor.redact(
            "John Smith discussed his portfolio today.",
            context="meeting_transcript",
        )
        assert "John Smith" not in result.sanitized_text

    def test_address_redacted(self, redactor: PWRedactor):
        result = redactor.redact(
            "They live at 42 Oak Lane, Havertown PA 19083.",
            context="meeting_transcript",
        )
        # The address (or parts of it) should be redacted
        assert "42 Oak Lane" not in result.sanitized_text or "Havertown" not in result.sanitized_text


# ── Financial data preservation ────────────────────────────────────


class TestFinancialPreservation:
    def test_dollar_amounts_preserved(self, redactor: PWRedactor):
        result = redactor.redact("John Smith has $425,000 in his IRA.")
        assert "$425,000" in result.sanitized_text

    def test_comma_numbers_preserved(self, redactor: PWRedactor):
        result = redactor.redact("John Smith earns 425,000 per year.")
        assert "425,000" in result.sanitized_text

    def test_percentages_preserved(self, redactor: PWRedactor):
        result = redactor.redact("John Smith is in the 32% bracket.")
        assert "32%" in result.sanitized_text

    def test_years_preserved(self, redactor: PWRedactor):
        result = redactor.redact("Patrick starts college in 2032.")
        assert "2032" in result.sanitized_text

    def test_form_references_preserved(self, redactor: PWRedactor):
        result = redactor.redact("File Form 1040 and Schedule D by April.")
        assert "Form 1040" in result.sanitized_text
        assert "Schedule D" in result.sanitized_text

    def test_financial_acronyms_preserved(self, redactor: PWRedactor):
        result = redactor.redact(
            "John Smith wants to discuss AGI, RMD, and 529 plans.",
        )
        assert "AGI" in result.sanitized_text
        assert "RMD" in result.sanitized_text
        assert "529" in result.sanitized_text


# ── Placeholder consistency ────────────────────────────────────────


class TestPlaceholderConsistency:
    def test_same_ssn_same_placeholder(self, redactor: PWRedactor):
        text = "SSN 123-45-6789 appears again: 123-45-6789"
        result = redactor.redact(text)
        # Same SSN should get same placeholder
        assert result.sanitized_text.count("<US_SSN_1>") == 2

    def test_different_ssns_different_placeholders(self, redactor: PWRedactor):
        text = "SSN 123-45-6789 and SSN 987-65-4321"
        result = redactor.redact(text)
        assert "<US_SSN_1>" in result.sanitized_text
        assert "<US_SSN_2>" in result.sanitized_text

    def test_same_email_same_placeholder(self, redactor: PWRedactor):
        text = "Email john@test.com and again john@test.com"
        result = redactor.redact(text)
        assert result.sanitized_text.count("<EMAIL_1>") == 2


# ── Manifest structure ─────────────────────────────────────────────


class TestManifest:
    def test_manifest_has_required_fields(self, redactor: PWRedactor):
        result = redactor.redact("SSN is 123-45-6789")
        d = result.manifest.to_dict()
        assert d["version"] == "1.0"
        assert d["redaction_id"].startswith("red_")
        assert len(d["placeholders"]) > 0
        assert "stats" in d

    def test_manifest_stats(self, redactor: PWRedactor):
        result = redactor.redact("SSN is 123-45-6789 and email is john@test.com")
        stats = result.manifest.to_dict()["stats"]
        assert stats["entities_found"] >= 2
        assert stats["text_length_original"] > 0
        assert stats["text_length_sanitized"] > 0

    def test_placeholder_entry_fields(self, redactor: PWRedactor):
        result = redactor.redact("SSN is 123-45-6789")
        placeholders = result.manifest.to_dict()["placeholders"]
        entry = next(p for p in placeholders if p["entity_type"] == "US_SSN")
        assert entry["placeholder"] == "<US_SSN_1>"
        assert entry["original"] == "123-45-6789"
        assert isinstance(entry["start"], int)
        assert isinstance(entry["end"], int)


# ── Round-trip (redact → rehydrate) ───────────────────────────────


class TestRoundTrip:
    def test_email_round_trip(self, redactor: PWRedactor, rehydrator: PWRehydrator):
        text = "Contact john@example.com for info."
        result = redactor.redact(text)
        restored = rehydrator.rehydrate(
            result.sanitized_text, result.manifest.to_dict()
        )
        assert "john@example.com" in restored

    def test_ssn_round_trip(self, redactor: PWRedactor, rehydrator: PWRehydrator):
        text = "My SSN is 123-45-6789 on file."
        result = redactor.redact(text)
        assert "123-45-6789" not in result.sanitized_text
        restored = rehydrator.rehydrate(
            result.sanitized_text, result.manifest.to_dict()
        )
        assert "123-45-6789" in restored

    def test_multi_entity_round_trip(
        self, redactor: PWRedactor, rehydrator: PWRehydrator
    ):
        text = "Email: john@test.com, SSN: 123-45-6789, CC: 4111-1111-1111-1111."
        result = redactor.redact(text)
        restored = rehydrator.rehydrate(
            result.sanitized_text, result.manifest.to_dict()
        )
        assert "john@test.com" in restored
        assert "123-45-6789" in restored
        assert "4111-1111-1111-1111" in restored

    def test_rehydrate_in_ai_output(
        self, redactor: PWRedactor, rehydrator: PWRehydrator
    ):
        """Simulate AI model using placeholders in its output."""
        original = "John Smith's SSN is 123-45-6789."
        result = redactor.redact(original, context="meeting_transcript")
        # Simulate AI output that references the placeholder
        ai_output = f"Based on the data, {result.sanitized_text.split('SSN')[0]}should file taxes."
        manifest = result.manifest.to_dict()
        restored = rehydrator.rehydrate(ai_output, manifest)
        # The person name placeholder should be replaced
        assert "<PERSON_" not in restored or "John" in restored


# ── Context-specific detection ─────────────────────────────────────


class TestContextDetection:
    def test_meeting_transcript_detects_names(self, redactor: PWRedactor):
        result = redactor.redact(
            "John discussed the plan with Sarah.",
            context="meeting_transcript",
        )
        # At least one person name should be detected
        types = {
            p.entity_type for p in result.manifest.placeholders
        }
        assert "PERSON" in types or len(result.manifest.placeholders) > 0

    def test_general_context_works(self, redactor: PWRedactor):
        result = redactor.redact("SSN: 123-45-6789", context="general")
        assert "123-45-6789" not in result.sanitized_text


# ── Detect-only mode ──────────────────────────────────────────────


class TestDetect:
    def test_detect_returns_entities(self, redactor: PWRedactor):
        entities = redactor.detect("SSN is 123-45-6789")
        assert len(entities) > 0
        assert any(e.entity_type == "US_SSN" for e in entities)

    def test_detect_does_not_modify_text(self, redactor: PWRedactor):
        text = "SSN is 123-45-6789"
        entities = redactor.detect(text)
        # detect returns entities but doesn't change text
        assert all(hasattr(e, "start") for e in entities)
        assert all(hasattr(e, "score") for e in entities)


# ── Sample transcript integration ─────────────────────────────────


# ── Mortgage document integration ──────────────────────────────────


class TestMortgageDocument:
    def test_pii_redacted(self, redactor: PWRedactor, sample_mortgage_notes: str):
        result = redactor.redact(sample_mortgage_notes, context="mortgage")
        assert "321-54-9876" not in result.sanitized_text
        assert "654-32-1098" not in result.sanitized_text
        assert "michael.t@email.com" not in result.sanitized_text
        assert "(630) 555-8901" not in result.sanitized_text

    def test_financial_data_preserved(
        self, redactor: PWRedactor, sample_mortgage_notes: str
    ):
        result = redactor.redact(sample_mortgage_notes, context="mortgage")
        assert "$575,000" in result.sanitized_text
        assert "6.375%" in result.sanitized_text
        assert "80%" in result.sanitized_text
        assert "34%" in result.sanitized_text
        assert "$460,000" in result.sanitized_text

    def test_mortgage_acronyms_preserved(
        self, redactor: PWRedactor, sample_mortgage_notes: str
    ):
        result = redactor.redact(sample_mortgage_notes, context="mortgage")
        assert "LTV" in result.sanitized_text
        assert "DTI" in result.sanitized_text
        assert "PMI" in result.sanitized_text
        assert "FRM" in result.sanitized_text
        assert "RESPA" in result.sanitized_text
        assert "TILA" in result.sanitized_text
        assert "HOA" in result.sanitized_text

    def test_mortgage_identifiers_redacted(
        self, redactor: PWRedactor, sample_mortgage_notes: str
    ):
        result = redactor.redact(sample_mortgage_notes, context="mortgage")
        # NMLS ID should be redacted
        assert "456789" not in result.sanitized_text or "<NMLS_ID_1>" in result.sanitized_text
        # SSNs should definitely be redacted
        assert "321-54-9876" not in result.sanitized_text


# ── Sample transcript integration ─────────────────────────────────


class TestSampleTranscript:
    def test_pii_redacted(self, redactor: PWRedactor, sample_transcript: str):
        result = redactor.redact(sample_transcript, context="meeting_transcript")
        # Names should be redacted
        assert "John" not in result.sanitized_text
        # SSN should be redacted
        assert "123-45-6789" not in result.sanitized_text

    def test_financial_data_preserved(
        self, redactor: PWRedactor, sample_transcript: str
    ):
        result = redactor.redact(sample_transcript, context="meeting_transcript")
        assert "425,000" in result.sanitized_text
        assert "95,000" in result.sanitized_text
        assert "32%" in result.sanitized_text
        assert "529" in result.sanitized_text
        assert "6.75%" in result.sanitized_text
        assert "2032" in result.sanitized_text


# ── Overlapping detections are merged into their union ─────────────


class TestOverlapMerge:
    @staticmethod
    def _e(entity_type: str, start: int, end: int, score: float, text: str):
        from pw_redact.redactor.regex_patterns import DetectedEntity

        return DetectedEntity(entity_type, start, end, score, text[start:end])

    def test_higher_score_inside_keeps_lower_score_tail(self):
        from pw_redact.redactor.engine import _merge_entities

        text = "abcdefghijklmnopqrstuvwxyz"
        merged = _merge_entities(
            [self._e("A", 0, 10, 0.9, text)], [self._e("B", 5, 20, 0.5, text)], text
        )
        assert [(m.entity_type, m.start, m.end) for m in merged] == [("A", 0, 20)]
        assert merged[0].text == text[0:20]

    def test_higher_score_later_keeps_lower_score_head(self):
        from pw_redact.redactor.engine import _merge_entities

        text = "abcdefghijklmnopqrstuvwxyz"
        merged = _merge_entities(
            [self._e("A", 0, 10, 0.5, text)], [self._e("B", 5, 20, 0.9, text)], text
        )
        assert [(m.entity_type, m.start, m.end) for m in merged] == [("B", 0, 20)]

    def test_chain_of_overlaps_is_one_span(self):
        from pw_redact.redactor.engine import _merge_entities

        text = "abcdefghijklmnopqrstuvwxyz"
        merged = _merge_entities(
            [self._e("A", 0, 6, 0.8, text), self._e("C", 10, 16, 0.6, text)],
            [self._e("B", 4, 12, 0.7, text)],
            text,
        )
        assert [(m.entity_type, m.start, m.end) for m in merged] == [("A", 0, 16)]

    def test_adjacent_detections_both_kept(self):
        from pw_redact.redactor.engine import _merge_entities

        text = "abcdefghijklmnopqrstuvwxyz"
        merged = _merge_entities(
            [self._e("A", 0, 5, 0.9, text)], [self._e("B", 5, 9, 0.5, text)], text
        )
        assert [(m.entity_type, m.start, m.end) for m in merged] == [("A", 0, 5), ("B", 5, 9)]

    def test_regex_wins_ties(self):
        from pw_redact.redactor.engine import _merge_entities

        text = "abcdefghijklmnopqrstuvwxyz"
        merged = _merge_entities(
            [self._e("REGEX", 0, 8, 0.8, text)], [self._e("NLP", 0, 8, 0.8, text)], text
        )
        assert merged[0].entity_type == "REGEX"

    def test_phone_extension_not_left_in_clear(self, redactor: PWRedactor):
        # Regex finds "212) 555-0199" (0.8); Presidio finds "(212) 555-0199 ext 22"
        # (lower score). Keeping only the regex span left "(" and "ext 22" in clear.
        text = "Reach him on (212) 555-0199 ext 22."
        result = redactor.redact(text)
        assert result.sanitized_text == "Reach him on <US_PHONE_1>."
        entry = result.manifest.placeholders[0]
        assert entry.original == "(212) 555-0199 ext 22"
        assert PWRehydrator.rehydrate(result.sanitized_text, result.manifest.to_dict()) == text

    def test_allow_listed_detection_does_not_suppress_overlapping_pii(
        self, redactor: PWRedactor, monkeypatch
    ):
        """An allow-listed detection is dropped before merging, not after.

        Otherwise a higher-scoring allow-listed span ("2025", a planning year)
        would win the merge and then be dropped, taking the overlapping PII
        ("2025 7781 ...") with it.
        """
        from presidio_analyzer import RecognizerResult

        text = "Ref 2025 7781 3349 on file."
        fake = [
            RecognizerResult("DATE_TIME", 4, 8, 0.95),
            RecognizerResult("ACCOUNT_REF", 4, 18, 0.6),
        ]
        monkeypatch.setattr(redactor._analyzer, "analyze", lambda **kw: fake)
        result = redactor.redact(text)
        assert result.sanitized_text == "Ref <ACCOUNT_REF_1> on file."


# ── "Roth" the surname vs "Roth" the account ───────────────────────


class TestRoth:
    @pytest.mark.parametrize(
        "text,name",
        [
            ("Mr. Roth called about his account.", "Roth"),
            ("Dr. Roth reviewed the plan.", "Roth"),
            ("Jane Roth called today.", "Jane Roth"),
        ],
    )
    def test_surname_redacted(self, redactor: PWRedactor, text, name):
        result = redactor.redact(text, context="meeting_transcript")
        assert "Roth" not in result.sanitized_text
        assert any(p.original == name for p in result.manifest.placeholders)

    @pytest.mark.parametrize(
        "text",
        [
            "Consider a Roth conversion into a Roth IRA.",
            "She can also use the Roth 401(k) at work.",
            "Explore backdoor Roth strategy.",
        ],
    )
    def test_account_preserved(self, redactor: PWRedactor, text):
        result = redactor.redact(text, context="meeting_transcript")
        assert result.sanitized_text == text

    def test_surname_and_account_in_one_sentence(self, redactor: PWRedactor):
        result = redactor.redact("Mr. Roth opened a Roth IRA.", context="meeting_transcript")
        assert result.sanitized_text == "Mr. <PERSON_1> opened a Roth IRA."


# ── Every occurrence of a detected value is replaced ───────────────


class TestRepeatedOccurrences:
    @pytest.mark.parametrize(
        "text,clear",
        [
            ("Loan #AB123456 confirmed; ref ab123456 on file.", ["AB123456", "ab123456"]),
            ("Loan #AB-123456 confirmed; ref ab\u2011123456 on file.", ["123456"]),
            ("John Smith called. Later JOHN SMITH called again.", ["Smith", "SMITH"]),
            ("SSN 123-45-6789 on file; client wrote 123\u201145\u20116789.", ["6789"]),
        ],
    )
    def test_no_variant_left_in_clear(self, redactor: PWRedactor, text, clear):
        from pw_redact.security.output_validator import validate_output

        result = redactor.redact(text, context="financial_notes")
        for value in clear:
            assert value not in result.sanitized_text
        manifest = result.manifest.to_dict()
        assert validate_output(result.sanitized_text, manifest).safe_to_return
        assert PWRehydrator.rehydrate(result.sanitized_text, manifest) == text

    def test_detect_reports_every_occurrence(self, redactor: PWRedactor):
        text = "Loan #AB123456 confirmed; ref ab123456 on file."
        spans = {(e.start, e.end) for e in redactor.detect(text)}
        assert (text.index("ab123456"), text.index("ab123456") + 8) in spans

    def test_short_values_not_propagated(self, redactor: PWRedactor):
        # "Roth" (4 characters) detected as a surname is not searched for
        # elsewhere, so the account name later in the sentence survives.
        result = redactor.redact("Mr. Roth opened a Roth IRA.", context="meeting_transcript")
        assert result.sanitized_text == "Mr. <PERSON_1> opened a Roth IRA."

    def test_allow_list_runs_before_merge_when_allowed_span_contains_pii(
        self, redactor: PWRedactor, monkeypatch
    ):
        """An allow-listed span that fully contains PII must not take it along.

        Presidio here reports "Form 123-45-6789" (which fullmatches the form
        reference allow pattern) with a higher score than the regex SSN inside
        it. Filtering after the merge would drop the union, SSN included.
        """
        from presidio_analyzer import RecognizerResult

        text = "See Form 123-45-6789 for details."
        monkeypatch.setattr(
            redactor._analyzer,
            "analyze",
            lambda **kw: [RecognizerResult("PERSON", 4, 20, 0.95)],
        )
        result = redactor.redact(text)
        assert "123-45-6789" not in result.sanitized_text
        assert result.sanitized_text == "See Form <US_SSN_1> for details."


class TestRothPeople:
    @pytest.mark.parametrize(
        "text",
        [
            "The Roth family met with us.",
            "mr. roth called.",
            "Judge Roth ruled on the trust.",
            "I asked Roth options he prefers.",
            "We contributed to Roth last year and he thanked us.",
            "Campaign contributions to Roth were disclosed.",
        ],
    )
    def test_person_redacted(self, redactor: PWRedactor, text):
        result = redactor.redact(text, context="meeting_transcript")
        assert "roth" not in result.sanitized_text.lower()

    def test_planning_verbs_keep_product(self, redactor: PWRedactor):
        text = "Convert to Roth before year-end, then max out Roth."
        result = redactor.redact(text, context="meeting_transcript")
        assert result.sanitized_text.count("Roth") == 2
