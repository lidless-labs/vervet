"""
Scoring Tuner Router - Adjust threat scoring weights and recalculate.
"""
import json
import os
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from api.dependencies.auth import api_key_auth

from api.services.log_store import LogStore, log_store as _log_store
from api.services.unified_threat_engine import UnifiedThreatEngine

router = APIRouter()

WEIGHTS_FILE = os.environ.get(
    "VERVET_SCORING_WEIGHTS_FILE",
    os.path.join(os.path.dirname(__file__), "..", "config", "scoring_weights.json"),
)

DEFAULT_WEIGHTS = {
    "beacon": 0.30,
    "dns_threat": 0.25,
    "ids_alert": 0.25,
    "long_connection": 0.20,
}


class WeightsUpdate(BaseModel):
    beacon: float = Field(..., ge=0.0, le=1.0)
    dns_threat: float = Field(..., ge=0.0, le=1.0)
    ids_alert: float = Field(..., ge=0.0, le=1.0)
    long_connection: float = Field(..., ge=0.0, le=1.0)


def _load_weights() -> dict:
    """Load weights from file or return defaults."""
    if os.path.exists(WEIGHTS_FILE):
        try:
            with open(WEIGHTS_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    return DEFAULT_WEIGHTS.copy()


def _save_weights(weights: dict):
    """Save weights to file."""
    os.makedirs(os.path.dirname(WEIGHTS_FILE), exist_ok=True)
    with open(WEIGHTS_FILE, "w") as f:
        json.dump(weights, f, indent=2)


def _normalize_weights(weights: dict) -> dict:
    """Normalize weights to sum to 1.0."""
    total = sum(weights.values())
    if total == 0:
        return DEFAULT_WEIGHTS.copy()
    return {k: round(v / total, 4) for k, v in weights.items()}


@router.get("/weights")
async def get_weights():
    """Get current scoring weights."""
    weights = _load_weights()
    return {
        "weights": weights,
        "defaults": DEFAULT_WEIGHTS,
        "sum": round(sum(weights.values()), 4),
    }


@router.put("/weights")
async def update_weights(update: WeightsUpdate, _: Annotated[str, Depends(api_key_auth)] = ""):
    """Update scoring weights (auto-normalizes to sum to 1.0)."""
    raw = {
        "beacon": update.beacon,
        "dns_threat": update.dns_threat,
        "ids_alert": update.ids_alert,
        "long_connection": update.long_connection,
    }
    normalized = _normalize_weights(raw)
    _save_weights(normalized)
    return {
        "weights": normalized,
        "message": "Weights updated and normalized",
        "sum": round(sum(normalized.values()), 4),
    }


@router.post("/recalculate")
async def recalculate_scores(_: Annotated[str, Depends(api_key_auth)] = ""):
    """Re-score all threats with current weights and return top 10 comparison."""
    weights = _load_weights()

    if not _log_store.connections and not _log_store.dns_queries and not _log_store.alerts:
        raise HTTPException(status_code=400, detail="No data loaded. Ingest logs first.")

    engine = UnifiedThreatEngine(_log_store)
    profiles = engine.analyze_all()

    # Apply custom weights to each profile
    results = []
    for ip, profile in profiles.items():
        # Original score (from engine's built-in scoring)
        original_score = profile.score

        # Recalculate with custom weights
        component_scores = {
            "beacon": max((b.score / 100.0 for b in profile.beacons), default=0.0),
            "dns_threat": max((t["data"].score / 100.0 for t in profile.dns_threats), default=0.0),
            "ids_alert": max((a.score / 100.0 for a in profile.alerts), default=0.0),
            "long_connection": max((l.score / 100.0 for l in profile.long_connections), default=0.0),
        }

        weighted_score = sum(
            component_scores[k] * weights.get(k, 0.0)
            for k in component_scores
        )
        weighted_score = min(weighted_score, 1.0)

        results.append({
            "ip": ip,
            "original_score": round(original_score, 3),
            "weighted_score": round(weighted_score, 3),
            "delta": round(weighted_score - original_score, 3),
            "components": {k: round(v, 3) for k, v in component_scores.items()},
            "threat_level": profile.threat_level.value,
        })

    # Sort by weighted score, return top 10
    results.sort(key=lambda r: r["weighted_score"], reverse=True)

    return {
        "weights": weights,
        "total_hosts": len(results),
        "top_threats": results[:10],
    }


@router.post("/reset")
async def reset_weights(_: Annotated[str, Depends(api_key_auth)] = ""):
    """Reset weights to defaults."""
    _save_weights(DEFAULT_WEIGHTS.copy())
    return {
        "weights": DEFAULT_WEIGHTS,
        "message": "Weights reset to defaults",
    }
