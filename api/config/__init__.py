"""
Configuration package for Vervet API.
"""
import os
import warnings
from typing import Optional
from pydantic_settings import BaseSettings


def _migrate_legacy_env_prefix() -> None:
    """Back-compat: map deprecated BROHUNTER_* env vars onto VERVET_* for one release.

    Vervet was formerly named "Bro Hunter". Existing deployments may still set
    BROHUNTER_API_KEY / BROHUNTER_LOG_ROOT / etc. Honor them unless the VERVET_
    equivalent is already set, and warn so operators migrate before the next release.
    """
    legacy = {k: v for k, v in os.environ.items() if k.startswith("BROHUNTER_")}
    if not legacy:
        return
    for old_key, value in legacy.items():
        new_key = "VERVET_" + old_key[len("BROHUNTER_"):]
        os.environ.setdefault(new_key, value)
    warnings.warn(
        "BROHUNTER_* environment variables are deprecated; rename them to VERVET_* "
        "(this shim will be removed in a future release).",
        DeprecationWarning,
        stacklevel=2,
    )


_migrate_legacy_env_prefix()


class Settings(BaseSettings):
    """Application settings and configuration."""

    app_name: str = "Vervet - Network Threat Hunting Platform"
    app_version: str = "0.2.0"
    api_prefix: str = "/api/v1"
    api_key: str | None = None
    log_root: str | None = None
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]
    demo_mode: bool = False
    # When set (e.g. VERVET_DATA_DIR=/data on a mounted volume), ingested logs are
    # persisted to <data_dir>/vervet.db and reloaded on startup so they survive a
    # restart. Unset (the default) keeps the store in-memory only. Demo mode never
    # persists (its sample data is re-seeded on every boot).
    data_dir: str | None = None
    cases_dir: str = "data/cases"
    max_file_size: int = 100 * 1024 * 1024
    chunk_size: int = 8192
    high_threat_threshold: float = 0.75
    medium_threat_threshold: float = 0.50
    low_threat_threshold: float = 0.25
    suspicious_port_threshold: int = 1024
    failed_connection_threshold: int = 10
    dns_query_threshold: int = 100

    class Config:
        env_prefix = "VERVET_"
        case_sensitive = False


settings = Settings()

from api.config.allowlists import BeaconAllowlist

__all__ = ["BeaconAllowlist", "Settings", "settings"]
