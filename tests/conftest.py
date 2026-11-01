# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact-core

"""Shared test fixtures."""

from __future__ import annotations

from pathlib import Path

import pytest

from pw_redact.config import settings
from pw_redact.redactor.engine import PWRedactor
from pw_redact.rehydrator.engine import PWRehydrator

FIXTURES_DIR = Path(__file__).parent / "fixtures"

# Test-only key. Not a secret: it exists so the API tests run with a configured
# key, now that an unset key or the .env.example placeholder is refused.
TEST_API_KEY = "test-only-key-not-a-secret-0123456789"


@pytest.fixture(autouse=True, scope="session")
def _configured_api_key():
    """Configure a usable API key for the whole session; restore it afterwards."""
    previous = settings.pw_redact_api_key
    settings.pw_redact_api_key = TEST_API_KEY
    yield
    settings.pw_redact_api_key = previous


@pytest.fixture(scope="session")
def redactor() -> PWRedactor:
    """Session-scoped PWRedactor (loads spaCy model once)."""
    return PWRedactor()


@pytest.fixture(scope="session")
def rehydrator() -> PWRehydrator:
    return PWRehydrator()


@pytest.fixture()
def sample_transcript() -> str:
    return (FIXTURES_DIR / "sample_transcript.txt").read_text()


@pytest.fixture()
def sample_tax_notes() -> str:
    return (FIXTURES_DIR / "sample_tax_notes.txt").read_text()


@pytest.fixture()
def sample_meeting_notes() -> str:
    return (FIXTURES_DIR / "sample_meeting_notes.txt").read_text()


@pytest.fixture()
def sample_mortgage_notes() -> str:
    return (FIXTURES_DIR / "sample_mortgage_notes.txt").read_text()


@pytest.fixture(autouse=True)
def _reset_auth_failure_limiter():
    """Each test starts with a fresh failed-auth budget for the test client IP."""
    from pw_redact.auth import auth_failure_limiter

    auth_failure_limiter._buckets.clear()
    yield
    auth_failure_limiter._buckets.clear()
