"""
Report Generation Router - Threat assessment reports in JSON and HTML.
"""
import io
from datetime import datetime
from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse

from api.services.log_store import log_store
from api.services.report_generator import ReportGenerator

router = APIRouter()


def _ensure_data_available() -> None:
    if not log_store.connections and not log_store.dns_queries and not log_store.alerts:
        raise HTTPException(status_code=400, detail="No data loaded. Ingest logs first.")


@router.get("/json")
async def report_json():
    """Generate a JSON threat assessment report."""
    _ensure_data_available()
    generator = ReportGenerator(log_store)
    return generator.generate_json()


@router.get("/html")
async def report_html():
    """Generate an HTML threat assessment report (viewable in browser)."""
    _ensure_data_available()
    generator = ReportGenerator(log_store)
    html_content = generator.generate_html()
    return HTMLResponse(content=html_content)


@router.get("/pdf")
async def report_pdf():
    """Generate a PDF threat assessment report and stream it."""
    _ensure_data_available()
    generator = ReportGenerator(log_store)
    pdf_bytes = generator.generate_pdf()
    filename = f"vervet-report-{datetime.utcnow().date().isoformat()}.pdf"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(io.BytesIO(pdf_bytes), media_type="application/pdf", headers=headers)


@router.post("/generate")
async def generate_and_save_report():
    """Generate a full report set and save to report history."""
    _ensure_data_available()
    generator = ReportGenerator(log_store)
    return generator.save_report()


@router.get("/history")
async def report_history():
    """List saved report metadata."""
    generator = ReportGenerator(log_store)
    return {"reports": generator.list_reports()}


@router.get("/history/{report_id}")
async def report_history_item(report_id: str):
    """Get metadata for a specific saved report."""
    generator = ReportGenerator(log_store)
    metadata = generator.get_saved_report(report_id)
    if not metadata:
        raise HTTPException(status_code=404, detail="Report not found")
    return metadata


@router.get("/history/{report_id}/html")
async def report_history_html(report_id: str):
    """Render saved HTML report in browser."""
    generator = ReportGenerator(log_store)
    metadata = generator.get_saved_report(report_id)
    if not metadata:
        raise HTTPException(status_code=404, detail="Report not found")

    html_name = metadata.get("files", {}).get("html", f"{report_id}.html")
    html_path = generator.reports_dir / html_name
    if not html_path.exists():
        raise HTTPException(status_code=404, detail="Saved HTML file not found")

    return HTMLResponse(content=html_path.read_text(encoding="utf-8"))


@router.get("/history/{report_id}/download")
async def report_history_download(report_id: str):
    """Download a saved PDF report."""
    generator = ReportGenerator(log_store)
    metadata = generator.get_saved_report(report_id)
    if not metadata:
        raise HTTPException(status_code=404, detail="Report not found")

    pdf_name = metadata.get("files", {}).get("pdf", f"{report_id}.pdf")
    pdf_path = generator.reports_dir / pdf_name
    if not pdf_path.exists():
        raise HTTPException(status_code=404, detail="Saved PDF file not found")

    return FileResponse(path=pdf_path, media_type="application/pdf", filename=pdf_name)


@router.delete("/history/{report_id}")
async def report_history_delete(report_id: str):
    """Delete a saved report and all associated files."""
    generator = ReportGenerator(log_store)
    deleted = generator.delete_report(report_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"ok": True, "report_id": report_id}
