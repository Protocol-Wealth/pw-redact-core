# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact-core

"""API key authentication for service-to-service calls."""

from __future__ import annotations

import hmac

from fastapi import Header, HTTPException

from .config import api_key_problem, settings


async def verify_api_key(authorization: str = Header(...)) -> None:
    """Verify internal service API key from Authorization header.

    Fails closed: with no usable key configured, every request is refused,
    even if the app was started without its lifespan check.
    """
    if api_key_problem(settings.pw_redact_api_key):
        raise HTTPException(status_code=503, detail="Service API key is not configured")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid auth format")
    token = authorization.removeprefix("Bearer ")
    # Constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(token, settings.pw_redact_api_key):
        raise HTTPException(status_code=403, detail="Invalid API key")
