# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact-core

"""Application configuration via environment variables."""

from pydantic_settings import BaseSettings

# The value shipped in .env.example. A key anyone can read in this public
# repository is no key, so it is refused exactly like an unset one.
PLACEHOLDER_API_KEY = "change-me-to-a-strong-random-key"

# Every example key this repository's docs have shown. Each is public for the
# same reason, so each is refused.
PLACEHOLDER_API_KEYS = frozenset(
    {
        PLACEHOLDER_API_KEY,
        "your-secret-key",
        "your-key",
        "your-strong-random-key",
        "new-strong-random-key",
        "new-key",
        "YOUR_API_KEY",
    }
)

# A shorter key is too easy to guess; secrets.token_urlsafe(48) gives 64 characters.
MIN_API_KEY_LENGTH = 32


class Settings(BaseSettings):
    # No default: an unset key must fail closed, not fall back to a public value.
    pw_redact_api_key: str = ""
    log_level: str = "info"
    spacy_model: str = "en_core_web_lg"
    environment: str = "development"
    max_request_size_mb: int = 1
    rate_limit_rpm: int = 60
    rate_limit_burst: int = 10

    model_config = {"env_prefix": "", "case_sensitive": False}


def api_key_problem(key: str | None) -> str | None:
    """Return why ``key`` must not be used as the service API key, or None if usable."""
    if key is None or not key.strip():
        return "PW_REDACT_API_KEY is unset or empty"
    if key.strip() in PLACEHOLDER_API_KEYS:
        return "PW_REDACT_API_KEY is still a placeholder from this repository's docs"
    if len(key.strip()) < MIN_API_KEY_LENGTH:
        return f"PW_REDACT_API_KEY is shorter than {MIN_API_KEY_LENGTH} characters"
    return None


settings = Settings()
