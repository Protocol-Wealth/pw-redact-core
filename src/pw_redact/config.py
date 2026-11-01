# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact-core

"""Application configuration via environment variables."""

from pydantic_settings import BaseSettings

# The value shipped in .env.example. A key anyone can read in this public
# repository is no key, so it is refused exactly like an unset one.
PLACEHOLDER_API_KEY = "change-me-to-a-strong-random-key"


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
    if key.strip() == PLACEHOLDER_API_KEY:
        return "PW_REDACT_API_KEY is still the placeholder from .env.example"
    return None


settings = Settings()
