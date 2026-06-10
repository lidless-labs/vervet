"""
Settings Router: GET/PUT application settings stored in a JSON file.
"""
import copy
import os
import json
import logging
from typing import Annotated, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from api.dependencies.auth import api_key_auth

from api.config import settings as runtime_settings
from api.services.log_store import log_store
from api.services.demo_data import DemoDataService

router = APIRouter()
logger = logging.getLogger(__name__)

SETTINGS_FILE = os.environ.get("VERVET_SETTINGS_FILE", "vervet_settings.json")

DEFAULT_SETTINGS = {
    "threat_intel": {
        "otx_key": "",
        "abuseipdb_key": "",
        "enabled_sources": ["local_blocklist"],
    },
    "scoring": {
        "beacon_weight": 1.0,
        "dns_weight": 1.0,
        "threat_weight": 1.0,
        "connection_weight": 1.0,
        "high_threshold": 75,
        "medium_threshold": 50,
        "low_threshold": 25,
    },
    "export": {
        "default_format": "json",
        "include_evidence": True,
    },
    "display": {
        "theme": "v3",
        "rows_per_page": 50,
        "auto_refresh_seconds": 30,
        "data_mode": "demo" if getattr(runtime_settings, "demo_mode", False) else "live",
    },
}


class SettingsUpdate(BaseModel):
    """Partial settings update payload."""
    threat_intel: Optional[dict] = None
    scoring: Optional[dict] = None
    export: Optional[dict] = None
    display: Optional[dict] = None


def _load_settings() -> dict:
    """Load settings from file, merging with defaults."""
    settings = copy.deepcopy(DEFAULT_SETTINGS)
    if os.path.exists(SETTINGS_FILE):
        try:
            with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
                stored = json.load(f)
            for section in settings:
                if section in stored and isinstance(stored[section], dict):
                    settings[section].update(stored[section])
        except (OSError, json.JSONDecodeError) as e:
            logger.warning(f"Failed to load settings file: {e}")
    return settings


def _save_settings(settings: dict):
    """Write settings to JSON file."""
    with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
        json.dump(settings, f, indent=2)


def _mask_key(key: str) -> str:
    """Mask API key for display (show first 4 and last 4 chars)."""
    if not key or len(key) < 10:
        return "***" if key else ""
    return f"{key[:4]}...{key[-4:]}"


@router.get("")
async def get_settings():
    """Get current settings with masked API keys."""
    settings = _load_settings()
    # Mask sensitive values
    masked = dict(settings)
    if "threat_intel" in masked:
        ti = dict(masked["threat_intel"])
        ti["otx_key"] = _mask_key(ti.get("otx_key", ""))
        ti["abuseipdb_key"] = _mask_key(ti.get("abuseipdb_key", ""))
        masked["threat_intel"] = ti
    return masked


@router.put("")
async def update_settings(update: SettingsUpdate, _: Annotated[str, Depends(api_key_auth)] = ""):
    """Update settings (partial merge)."""
    settings = _load_settings()

    if update.threat_intel:
        for k, v in update.threat_intel.items():
            # Don't overwrite keys with masked values
            if k.endswith("_key"):
                existing = settings["threat_intel"].get(k, "")
                if v and v == _mask_key(existing):
                    continue
            settings["threat_intel"][k] = v

    if update.scoring:
        settings["scoring"].update(update.scoring)

    if update.export:
        settings["export"].update(update.export)

    if update.display:
        settings["display"].update(update.display)

    _save_settings(settings)
    return {"status": "saved"}


@router.get("/mode")
async def get_data_mode() -> dict:
    """Get current runtime data mode."""
    return {"demo_mode": getattr(runtime_settings, "demo_mode", False)}


@router.put("/mode")
async def set_data_mode(payload: dict, _: Annotated[str, Depends(api_key_auth)] = "") -> dict:
    """Switch runtime data mode between demo/live without restart."""
    demo_mode = bool(payload.get("demo_mode", False))
    try:
        runtime_settings.demo_mode = demo_mode
    except (AttributeError, ValueError):
        pass  # pydantic frozen model

    persisted = _load_settings()
    persisted.setdefault("display", {})["data_mode"] = "demo" if demo_mode else "live"
    _save_settings(persisted)

    if demo_mode:
        stats = DemoDataService().load_into_store(log_store)
        return {"status": "ok", "demo_mode": True, "stats": stats}

    log_store.clear()
    return {"status": "ok", "demo_mode": False}
