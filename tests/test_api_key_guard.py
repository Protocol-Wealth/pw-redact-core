# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact-core

"""The service must not run, or accept a request, with an unusable API key.

Before this guard the key defaulted to the placeholder shipped in .env.example,
so a deployment that forgot to set it accepted a value anyone can read in this
public repository.
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

import pw_redact.main as main_module
from pw_redact.config import (
    MIN_API_KEY_LENGTH,
    PLACEHOLDER_API_KEY,
    PLACEHOLDER_API_KEYS,
    Settings,
    api_key_problem,
    settings,
)
from pw_redact.main import app, lifespan
from pw_redact.security.rate_limiter import RateLimiter

UNUSABLE = {
    "empty": "",
    "whitespace": "   ",
    "placeholder": PLACEHOLDER_API_KEY,
    "placeholder with spaces": f"  {PLACEHOLDER_API_KEY}\n",
    "doc placeholder": "your-secret-key",
    "short": "k" * (MIN_API_KEY_LENGTH - 1),
}
# Every example key the README, docs/deployment.md and the landing page have shown.
DOC_PLACEHOLDERS = [
    "your-secret-key",
    "your-key",
    "your-strong-random-key",
    "new-strong-random-key",
    "new-key",
    "YOUR_API_KEY",
]
BODY = {"text": "SSN 123-45-6789", "context": "general"}


@pytest.fixture()
def key(request):
    """Temporarily set the configured key to the parametrized value."""
    previous = settings.pw_redact_api_key
    settings.pw_redact_api_key = request.param
    yield request.param
    settings.pw_redact_api_key = previous


@pytest.fixture(autouse=True, scope="module")
def _init_app_state(redactor):
    main_module._redactor = redactor
    main_module._rate_limiter = RateLimiter(rpm=6000, burst=100)
    yield
    main_module._redactor = None
    main_module._rate_limiter = None


def test_unset_env_means_empty_key(monkeypatch):
    monkeypatch.delenv("PW_REDACT_API_KEY", raising=False)
    assert Settings(_env_file=None).pw_redact_api_key == ""
    assert api_key_problem(Settings(_env_file=None).pw_redact_api_key)


@pytest.mark.parametrize("value", list(UNUSABLE.values()), ids=list(UNUSABLE))
def test_unusable_keys_are_named(value):
    assert api_key_problem(value) is not None


@pytest.mark.parametrize("value", DOC_PLACEHOLDERS)
def test_documented_placeholders_are_refused(value):
    assert value in PLACEHOLDER_API_KEYS
    assert "placeholder" in api_key_problem(value)


def test_keys_shorter_than_minimum_are_refused():
    assert "shorter" in api_key_problem("k" * (MIN_API_KEY_LENGTH - 1))
    assert api_key_problem("k" * MIN_API_KEY_LENGTH) is None


def test_docs_no_longer_show_a_literal_key():
    """README and deployment docs generate a key or read it from the env var."""
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent
    for doc in ("README.md", "docs/deployment.md", "src/pw_redact/main.py"):
        text = (root / doc).read_text()
        for value in PLACEHOLDER_API_KEYS - {PLACEHOLDER_API_KEY}:
            assert f"PW_REDACT_API_KEY={value}" not in text, (doc, value)
            assert f"Bearer {value}" not in text, (doc, value)


def test_a_real_key_is_usable():
    assert api_key_problem("x9Q2-strong-random-value-for-tests") is None


@pytest.mark.asyncio
@pytest.mark.parametrize("key", list(UNUSABLE.values()), ids=list(UNUSABLE), indirect=True)
async def test_startup_refuses_unusable_key(key):
    with pytest.raises(RuntimeError, match="PW_REDACT_API_KEY"):
        async with lifespan(app):
            pass


@pytest.mark.asyncio
@pytest.mark.parametrize("key", list(UNUSABLE.values()), ids=list(UNUSABLE), indirect=True)
@pytest.mark.parametrize("path", ["/v1/redact", "/v1/detect"])
async def test_requests_refused_even_with_matching_bearer(key, path):
    """Fail closed per request too, in case the app runs without its lifespan."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.post(path, json=BODY, headers={"Authorization": f"Bearer {key}"})
    assert resp.status_code == 503
    assert "123-45-6789" not in resp.text


@pytest.mark.asyncio
async def test_placeholder_bearer_rejected_when_a_real_key_is_set():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.post(
            "/v1/redact", json=BODY, headers={"Authorization": f"Bearer {PLACEHOLDER_API_KEY}"}
        )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_landing_page_states_the_mit_license():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        resp = await c.get("/")
    assert ">MIT<" in resp.text
    assert "Apache" not in resp.text


@pytest.mark.asyncio
@pytest.mark.parametrize("configured", ["KEY\n", "  KEY  ", "\tKEY\r\n"])
async def test_configured_key_is_compared_stripped(configured):
    """api_key_problem() judges the stripped key, so verification uses it too.

    A key read from a file usually ends in a newline; before, it passed the
    startup check but no bearer could ever match it.
    """
    real = "x9Q2-strong-random-value-for-tests"
    previous = settings.pw_redact_api_key
    settings.pw_redact_api_key = configured.replace("KEY", real)
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
            ok = await c.post("/v1/detect", json=BODY, headers={"Authorization": f"Bearer {real}"})
            padded = await c.post(
                "/v1/detect", json=BODY, headers={"Authorization": f"Bearer {real} "}
            )
    finally:
        settings.pw_redact_api_key = previous
    assert ok.status_code == 200
    assert padded.status_code == 403
