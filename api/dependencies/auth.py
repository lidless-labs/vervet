"""
API authentication dependency for Vervet.
Provides API key-based authentication for sensitive endpoints.
"""
from fastapi import HTTPException, Security, status
from fastapi.security import APIKeyHeader
from typing import Annotated

from api.config import settings

# API key header configuration
api_key_header = APIKeyHeader(
    name="X-API-Key",
    auto_error=False,
    description="API key for authentication. Set via VERVET_API_KEY environment variable.",
)


async def api_key_auth(
    api_key: Annotated[str | None, Security(api_key_header)]
) -> str:
    """
    Validate API key from request header.

    If VERVET_API_KEY is not set, authentication is disabled (development mode).
    In production, always set VERVET_API_KEY to a secure random value.

    Args:
        api_key: API key from X-API-Key header

    Returns:
        The validated API key

    Raises:
        HTTPException: 401 if API key is missing or invalid
    """
    # If no API key configured, skip authentication (dev mode)
    if not settings.api_key:
        return "dev-mode"

    # API key required in production
    if not api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Provide X-API-Key header.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    # Validate API key (constant-time comparison to prevent timing attacks)
    if not _secure_compare(api_key, settings.api_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return api_key


def _secure_compare(a: str, b: str) -> bool:
    """
    Constant-time string comparison to prevent timing attacks.

    Args:
        a: First string
        b: Second string

    Returns:
        True if strings are equal
    """
    import hmac
    return hmac.compare_digest(a.encode(), b.encode())
