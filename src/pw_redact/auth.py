# Copyright 2026 Protocol Wealth LLC
# Licensed under the MIT License
# https://github.com/Protocol-Wealth/pw-redact-core

"""API key authentication for service-to-service calls."""

from __future__ import annotations

import hmac

from fastapi import Header, HTTPException, Request

from .config import api_key_problem, settings
from .security.rate_limiter import RateLimiter

# Failed authentication (401/403) is limited per client IP, separately from the
# per-key limit on authenticated requests. Only failures spend this budget, and
# a correct key is never refused by it: behind a shared proxy every client has
# the proxy's IP, and one consumer with a stale key during rotation must not
# lock out the others. Against guessing, the defence is the key itself
# (at least 32 characters, see config.api_key_problem).
AUTH_FAILURE_RPM = 10
AUTH_FAILURE_BURST = 5
auth_failure_limiter = RateLimiter(rpm=AUTH_FAILURE_RPM, burst=AUTH_FAILURE_BURST)


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _refuse(request: Request, status_code: int, detail: str) -> HTTPException:
    """Return the auth error, or 429 once this IP has used its failure budget."""
    allowed, retry_after = auth_failure_limiter.check(_client_ip(request))
    if not allowed:
        return HTTPException(
            status_code=429,
            detail="Too many failed authentication attempts",
            headers={"Retry-After": str(retry_after)},
        )
    return HTTPException(status_code=status_code, detail=detail)


async def verify_api_key(request: Request, authorization: str = Header(...)) -> None:
    """Verify internal service API key from Authorization header.

    Fails closed: with no usable key configured, every request is refused,
    even if the app was started without its lifespan check.
    """
    if api_key_problem(settings.pw_redact_api_key):
        raise HTTPException(status_code=503, detail="Service API key is not configured")
    if not authorization.startswith("Bearer "):
        raise _refuse(request, 401, "Invalid auth format")
    token = authorization.removeprefix("Bearer ")
    # Compare against the key as api_key_problem() judged it: stripped, so a
    # key read from a file with a trailing newline works and is checked as is.
    expected = settings.pw_redact_api_key.strip()
    # Constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(token.encode(), expected.encode()):
        raise _refuse(request, 403, "Invalid API key")
