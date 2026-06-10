"""
Simple in-memory IP-based rate limiter.

Configure via environment variables:
  VERVET_RATE_LIMIT_ENABLED=true    (default: true)
  VERVET_RATE_LIMIT_HOURLY=5        (max uploads per hour per IP, default: 5)
  VERVET_RATE_LIMIT_DAILY=15        (max uploads per day per IP, default: 15)

To disable rate limiting (e.g. self-hosted / cloned deployments):
  Set VERVET_RATE_LIMIT_ENABLED=false
"""
import os
import time
from collections import defaultdict
from typing import Optional
from fastapi import Request, HTTPException


# Configuration from environment
RATE_LIMIT_ENABLED = os.environ.get("VERVET_RATE_LIMIT_ENABLED", "true").lower() == "true"
RATE_LIMIT_HOURLY = int(os.environ.get("VERVET_RATE_LIMIT_HOURLY", "5"))
RATE_LIMIT_DAILY = int(os.environ.get("VERVET_RATE_LIMIT_DAILY", "15"))

# Trusted proxy IPs that are allowed to set X-Forwarded-For (parsed once at import)
_trusted_proxies_raw = os.environ.get("TRUSTED_PROXIES", "").split(",")
TRUSTED_PROXIES: set[str] = {p.strip() for p in _trusted_proxies_raw if p.strip()}

# In-memory store: IP -> list of timestamps
_upload_log: dict[str, list[float]] = defaultdict(list)


def _get_client_ip(request: Request) -> str:
    """Extract client IP. Only trusts X-Forwarded-For when TRUSTED_PROXIES is set."""
    client_host = request.client.host if request.client else "unknown"
    if TRUSTED_PROXIES and client_host in TRUSTED_PROXIES:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return client_host


def _cleanup(entries: list[float], window: float) -> list[float]:
    """Remove entries older than window seconds."""
    cutoff = time.time() - window
    return [t for t in entries if t > cutoff]


def check_rate_limit(request: Request) -> Optional[dict]:
    """
    Check if the request is within rate limits.
    Returns None if allowed, or a dict with error details if blocked.
    """
    if not RATE_LIMIT_ENABLED:
        return None

    ip = _get_client_ip(request)
    now = time.time()

    # Clean up old entries
    _upload_log[ip] = _cleanup(_upload_log[ip], 86400)  # keep 24h window

    # Count recent uploads
    hour_ago = now - 3600
    hourly_count = sum(1 for t in _upload_log[ip] if t > hour_ago)
    daily_count = len(_upload_log[ip])

    if hourly_count >= RATE_LIMIT_HOURLY:
        return {
            "detail": f"Rate limit exceeded: {RATE_LIMIT_HOURLY} uploads per hour. Try again later.",
            "retry_after": int(min(t for t in _upload_log[ip] if t > hour_ago) + 3600 - now),
        }

    if daily_count >= RATE_LIMIT_DAILY:
        return {
            "detail": f"Rate limit exceeded: {RATE_LIMIT_DAILY} uploads per day. Try again tomorrow.",
            "retry_after": int(min(_upload_log[ip]) + 86400 - now),
        }

    return None


def record_upload(request: Request):
    """Record a successful upload for rate limiting."""
    if not RATE_LIMIT_ENABLED:
        return
    ip = _get_client_ip(request)
    _upload_log[ip].append(time.time())
