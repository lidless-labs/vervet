"""Case bundle export API router."""
from __future__ import annotations

import json

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import HTMLResponse, Response

from api.services.bundle_exporter import bundle_exporter

router = APIRouter()


@router.post("/{case_id}/export")
async def export_case_bundle(case_id: str, format: str = Query(default="json", pattern="^(json|html|stix|evidence-record)$")):
    try:
        if format == "evidence-record":
            return bundle_exporter.export_evidence_record(case_id)
        if format == "json":
            return bundle_exporter.export_json(case_id)
        if format == "stix":
            return bundle_exporter.export_stix(case_id)
        html_content = bundle_exporter.export_html(case_id)
        return HTMLResponse(content=html_content)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/{case_id}/export/html")
async def preview_html_bundle(case_id: str):
    try:
        html_content = bundle_exporter.export_html(case_id)
        return HTMLResponse(content=html_content)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/{case_id}/export/download")
async def download_bundle(case_id: str, format: str = Query(default="json", pattern="^(json|stix)$")):
    try:
        if format == "stix":
            content = json.dumps(bundle_exporter.export_stix(case_id), indent=2)
            filename = f"case-{case_id}-bundle.stix.json"
        else:
            content = json.dumps(bundle_exporter.export_json(case_id), indent=2)
            filename = f"case-{case_id}-bundle.json"

        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
