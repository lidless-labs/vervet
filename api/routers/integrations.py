from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException

from api.dependencies.auth import api_key_auth
from api.services.case_manager import CaseManager
from api.services.thehive_client import TheHiveClient, map_vervet_case_to_thehive
from api.services.wazuh_client import WazuhClient, normalize_wazuh_hits
from api.services.misp_client import MISPClient, normalize_misp_hits

router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])

case_manager = CaseManager()


@router.get("/status")
async def integration_status():
    thehive = TheHiveClient()
    wazuh = WazuhClient()
    misp = MISPClient()
    return {
        "thehive": {
            "configured": thehive.configured,
            "url": thehive.base_url or None,
        },
        "wazuh": {
            "configured": wazuh.configured,
            "url": wazuh.base_url or None,
            "alerts_path": wazuh.alerts_path,
        },
        "misp": {
            "configured": misp.configured,
            "url": misp.base_url or None,
            "search_path": misp.search_path,
        },
    }


@router.post("/thehive/cases/from-case/{case_id}")
async def create_thehive_case_from_case(
    case_id: str,
    _: Annotated[str, Depends(api_key_auth)] = "",
):
    try:
        case = case_manager.get_case(case_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e

    client = TheHiveClient()
    if not client.configured:
        raise HTTPException(
            status_code=400,
            detail="TheHive integration not configured. Set THEHIVE_URL and THEHIVE_API_KEY.",
        )

    payload = map_vervet_case_to_thehive(case)

    try:
        result = client.create_case(payload)
    except RuntimeError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e

    return {
        "status": "ok",
        "source_case_id": case_id,
        "thehive": result,
    }


@router.post("/wazuh/correlate/case/{case_id}")
async def correlate_case_iocs_with_wazuh(
    case_id: str,
    limit_per_ioc: int = 25,
    _: Annotated[str, Depends(api_key_auth)] = "",
):
    try:
        case = case_manager.get_case(case_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e

    iocs = case.get("iocs", [])
    if not iocs:
        return {
            "status": "ok",
            "source_case_id": case_id,
            "summary": {"ioc_count": 0, "matched_iocs": 0, "total_alert_hits": 0},
            "matches": [],
        }

    client = WazuhClient()
    if not client.configured:
        raise HTTPException(
            status_code=400,
            detail="Wazuh integration not configured. Set WAZUH_URL and WAZUH_API_KEY.",
        )

    matches = []
    total_hits = 0

    for ioc in iocs:
        value = str(ioc.get("value", "")).strip()
        if not value:
            continue

        try:
            payload = client.search_alerts_for_ioc(value, limit=limit_per_ioc)
            hit_count, hit_items = normalize_wazuh_hits(payload)
        except RuntimeError as e:
            raise HTTPException(status_code=502, detail=str(e)) from e

        if hit_count > 0:
            total_hits += hit_count
            matches.append(
                {
                    "ioc": {
                        "id": ioc.get("id"),
                        "type": ioc.get("type"),
                        "value": value,
                        "verdict": ioc.get("verdict"),
                    },
                    "hit_count": hit_count,
                    "sample_hits": hit_items[:5],
                }
            )

    return {
        "status": "ok",
        "source_case_id": case_id,
        "summary": {
            "ioc_count": len(iocs),
            "matched_iocs": len(matches),
            "total_alert_hits": total_hits,
        },
        "matches": matches,
    }


@router.post("/misp/enrich/case/{case_id}")
async def enrich_case_iocs_with_misp(
    case_id: str,
    limit_per_ioc: int = 25,
    _: Annotated[str, Depends(api_key_auth)] = "",
):
    try:
        case = case_manager.get_case(case_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e)) from e

    iocs = case.get("iocs", [])
    if not iocs:
        return {
            "status": "ok",
            "source_case_id": case_id,
            "summary": {"ioc_count": 0, "enriched_iocs": 0, "total_hits": 0},
            "enrichments": [],
        }

    client = MISPClient()
    if not client.configured:
        raise HTTPException(
            status_code=400,
            detail="MISP integration not configured. Set MISP_URL and MISP_API_KEY.",
        )

    enrichments = []
    total_hits = 0

    for ioc in iocs:
        value = str(ioc.get("value", "")).strip()
        if not value:
            continue

        try:
            payload = client.search_attribute(value, limit=limit_per_ioc)
            hit_count, hit_items = normalize_misp_hits(payload)
        except RuntimeError as e:
            raise HTTPException(status_code=502, detail=str(e)) from e

        if hit_count > 0:
            total_hits += hit_count
            enrichments.append(
                {
                    "ioc": {
                        "id": ioc.get("id"),
                        "type": ioc.get("type"),
                        "value": value,
                        "verdict": ioc.get("verdict"),
                    },
                    "hit_count": hit_count,
                    "sample_hits": hit_items[:5],
                }
            )

    return {
        "status": "ok",
        "source_case_id": case_id,
        "summary": {
            "ioc_count": len(iocs),
            "enriched_iocs": len(enrichments),
            "total_hits": total_hits,
        },
        "enrichments": enrichments,
    }
