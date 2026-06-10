"""
Report Generator - Produces threat assessment reports in HTML and JSON formats.

Generates comprehensive reports including:
- Executive summary
- Top threats with evidence
- MITRE ATT&CK coverage
- IOC listing
- Network session analysis
- Scoring methodology
"""
import html
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional
from uuid import uuid4

from xhtml2pdf import pisa

from api.services.log_store import LogStore
from api.services.session_reconstructor import SessionReconstructor
from api.services.unified_threat_engine import UnifiedThreatEngine


class ReportGenerator:
    """Generates threat assessment reports."""

    def __init__(self, log_store: LogStore):
        self.log_store = log_store
        self.engine = UnifiedThreatEngine(log_store)
        self.session_reconstructor = SessionReconstructor(log_store)
        self.reports_dir = Path("data/reports")
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate_json(self) -> Dict:
        """Generate a structured JSON report."""
        profiles = self.engine.analyze_all()
        sessions = self.session_reconstructor.reconstruct_all()

        sorted_threats = sorted(profiles.values(), key=lambda p: p.score, reverse=True)
        top_threats = sorted_threats[:20]

        # MITRE coverage
        all_techniques = set()
        all_tactics = set()
        for p in profiles.values():
            all_techniques.update(p.mitre_techniques)
            for m in p.mitre_mappings:
                all_tactics.add(m.tactic)

        # Severity distribution
        severity_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for p in profiles.values():
            severity_dist[p.threat_level.value] = severity_dist.get(p.threat_level.value, 0) + 1

        # Session stats
        flagged_sessions = [s for s in sessions if s.threat_score > 0.2]

        return {
            "report_metadata": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "generator": "Vervet v0.2.0",
                "total_hosts_analyzed": len(profiles),
                "total_sessions": len(sessions),
                "data_sources": {
                    "connections": len(self.log_store.connections),
                    "dns_queries": len(self.log_store.dns_queries),
                    "alerts": len(self.log_store.alerts),
                },
            },
            "executive_summary": {
                "total_threats": len([p for p in profiles.values() if p.score > 0.2]),
                "critical_count": severity_dist["critical"],
                "high_count": severity_dist["high"],
                "medium_count": severity_dist["medium"],
                "severity_distribution": severity_dist,
                "mitre_techniques_observed": len(all_techniques),
                "mitre_tactics_observed": len(all_tactics),
                "suspicious_sessions": len(flagged_sessions),
            },
            "top_threats": [
                {
                    "ip": p.ip,
                    "score": round(p.score, 3),
                    "threat_level": p.threat_level.value,
                    "confidence": round(p.confidence, 3),
                    "beacon_count": p.beacon_count,
                    "dns_threat_count": p.dns_threat_count,
                    "alert_count": p.alert_count,
                    "long_connection_count": p.long_connection_count,
                    "mitre_techniques": sorted(p.mitre_techniques),
                    "summary": p.attack_summary,
                    "reasons": p.all_reasons,
                }
                for p in top_threats
            ],
            "mitre_coverage": {
                "techniques": sorted(all_techniques),
                "tactics": sorted(all_tactics),
            },
            "ioc_summary": {
                "malicious_ips": sorted([p.ip for p in profiles.values() if p.score >= 0.6]),
                "suspicious_ips": sorted([p.ip for p in profiles.values() if 0.2 <= p.score < 0.6]),
                "malicious_domains": sorted(
                    set(d for p in profiles.values() if p.score >= 0.6 for d in p.related_domains)
                ),
            },
        }

    def generate_html(self, data: Optional[Dict] = None) -> str:
        """Generate an HTML threat assessment report."""
        data = data or self.generate_json()
        meta = data["report_metadata"]
        summary = data["executive_summary"]

        threat_rows = ""
        for t in data["top_threats"]:
            level_color = {
                "critical": "#ef4444",
                "high": "#f97316",
                "medium": "#eab308",
                "low": "#22c55e",
                "info": "#6b7280",
            }.get(t["threat_level"], "#6b7280")

            threat_rows += f"""
            <tr>
                <td style=\"font-family:monospace;font-size:13px\">{html.escape(t['ip'])}</td>
                <td style=\"text-align:center\">
                    <span style=\"background:{level_color}22;color:{level_color};padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600\">
                        {html.escape(t['threat_level'].upper())}
                    </span>
                </td>
                <td style=\"text-align:center;font-weight:600\">{int(t['score']*100)}</td>
                <td style=\"font-size:12px;color:#9ca3af\">{html.escape(t['summary'][:120])}</td>
                <td style=\"font-size:11px;font-family:monospace;color:#9ca3af\">{', '.join(t['mitre_techniques'][:5])}</td>
            </tr>"""

        iocs = data["ioc_summary"]
        ioc_section = ""
        if iocs["malicious_ips"]:
            ioc_section += "<h3 style='color:#ef4444;margin-top:20px'>Malicious IPs</h3><ul>"
            for ip in iocs["malicious_ips"][:20]:
                ioc_section += f"<li style='font-family:monospace;font-size:13px'>{html.escape(ip)}</li>"
            ioc_section += "</ul>"
        if iocs["malicious_domains"]:
            ioc_section += "<h3 style='color:#f97316;margin-top:20px'>Malicious Domains</h3><ul>"
            for d in iocs["malicious_domains"][:20]:
                ioc_section += f"<li style='font-family:monospace;font-size:13px'>{html.escape(d)}</li>"
            ioc_section += "</ul>"

        return f"""<!DOCTYPE html>
<html lang=\"en\">
<head>
<meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">
<title>Vervet - Threat Assessment Report</title>
<style>
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#0f172a; color:#e2e8f0; padding:40px; line-height:1.6; }}
  .container {{ max-width:1000px; margin:0 auto; }}
  .header {{ border-bottom:2px solid #1e293b; padding-bottom:24px; margin-bottom:32px; }}
  .header h1 {{ font-size:28px; color:#f1f5f9; margin-bottom:4px; }}
  .header .subtitle {{ color:#64748b; font-size:14px; }}
  .stat-grid {{ display:grid; grid-template-columns:repeat(4,1fr); gap:16px; margin:24px 0; }}
  .stat-card {{ background:#1e293b; border-radius:8px; padding:16px; text-align:center; }}
  .stat-card .value {{ font-size:32px; font-weight:700; }}
  .stat-card .label {{ font-size:12px; color:#94a3b8; margin-top:4px; }}
  .critical {{ color:#ef4444; }}
  .high {{ color:#f97316; }}
  .medium {{ color:#eab308; }}
  .low {{ color:#22c55e; }}
  h2 {{ font-size:20px; color:#f1f5f9; margin:32px 0 16px; padding-bottom:8px; border-bottom:1px solid #1e293b; }}
  table {{ width:100%; border-collapse:collapse; margin:16px 0; }}
  th {{ text-align:left; padding:10px 12px; background:#1e293b; color:#94a3b8; font-size:12px; text-transform:uppercase; letter-spacing:0.5px; }}
  td {{ padding:10px 12px; border-bottom:1px solid #1e293b; color:#cbd5e1; }}
  tr:hover td {{ background:#1e293b44; }}
  ul {{ padding-left:20px; }}
  li {{ margin:4px 0; color:#cbd5e1; }}
  .footer {{ margin-top:40px; padding-top:20px; border-top:1px solid #1e293b; color:#475569; font-size:12px; text-align:center; }}
  .mitre-tag {{ display:inline-block; background:#1e293b; color:#60a5fa; padding:2px 8px; border-radius:4px; font-size:11px; font-family:monospace; margin:2px; }}
</style>
</head>
<body>
<div class=\"container\">
  <div class=\"header\">
    <h1>🎯 Threat Assessment Report</h1>
    <div class=\"subtitle\">Generated by Vervet on {html.escape(meta['generated_at'][:19])} UTC</div>
    <div class=\"subtitle\">{meta['total_hosts_analyzed']} hosts analyzed | {meta['data_sources']['connections']} connections | {meta['data_sources']['dns_queries']} DNS queries | {meta['data_sources']['alerts']} alerts</div>
  </div>

  <h2>Executive Summary</h2>
  <div class=\"stat-grid\">
    <div class=\"stat-card\">
      <div class=\"value critical\">{summary['critical_count']}</div>
      <div class=\"label\">Critical Threats</div>
    </div>
    <div class=\"stat-card\">
      <div class=\"value high\">{summary['high_count']}</div>
      <div class=\"label\">High Threats</div>
    </div>
    <div class=\"stat-card\">
      <div class=\"value medium\">{summary['medium_count']}</div>
      <div class=\"label\">Medium Threats</div>
    </div>
    <div class=\"stat-card\">
      <div class=\"value\" style=\"color:#60a5fa\">{summary['mitre_techniques_observed']}</div>
      <div class=\"label\">MITRE Techniques</div>
    </div>
  </div>

  <h2>Top Threats</h2>
  <table>
    <thead>
      <tr><th>Host</th><th>Level</th><th>Score</th><th>Summary</th><th>MITRE</th></tr>
    </thead>
    <tbody>{threat_rows}</tbody>
  </table>

  <h2>MITRE ATT&CK Coverage</h2>
  <p style=\"margin-bottom:12px;color:#94a3b8\">{len(data['mitre_coverage']['techniques'])} techniques across {len(data['mitre_coverage']['tactics'])} tactics observed</p>
  <div>
    {''.join(f'<span class="mitre-tag">{html.escape(t)}</span>' for t in data['mitre_coverage']['techniques'][:30])}
  </div>

  <h2>Indicators of Compromise</h2>
  {ioc_section if ioc_section else '<p style="color:#64748b">No high-confidence IOCs detected.</p>'}

  <div class=\"footer\">
    Vervet v0.2.0 | Automated Threat Assessment | {html.escape(meta['generated_at'][:10])}
  </div>
</div>
</body>
</html>"""

    def generate_pdf(self, html_content: Optional[str] = None) -> bytes:
        """Generate a PDF report from the HTML report."""
        html_content = html_content or self.generate_html()
        pdf_buffer = io.BytesIO()
        status = pisa.CreatePDF(html_content, dest=pdf_buffer)
        if status.err:
            raise RuntimeError("Failed to generate PDF report")
        return pdf_buffer.getvalue()

    def save_report(self, title: Optional[str] = None) -> Dict:
        """Generate and persist report assets (JSON, HTML, PDF) and metadata."""
        report_json = self.generate_json()
        report_html = self.generate_html(report_json)
        report_pdf = self.generate_pdf(report_html)

        generated_at = report_json["report_metadata"]["generated_at"]
        timestamp = generated_at.replace(":", "").replace("-", "")[:15]
        report_id = f"report-{timestamp}-{uuid4().hex[:8]}"
        safe_title = title or f"Threat Report {generated_at[:10]}"

        json_filename = f"{report_id}.json"
        html_filename = f"{report_id}.html"
        pdf_filename = f"{report_id}.pdf"
        metadata_filename = f"{report_id}.meta.json"

        json_path = self.reports_dir / json_filename
        html_path = self.reports_dir / html_filename
        pdf_path = self.reports_dir / pdf_filename
        metadata_path = self.reports_dir / metadata_filename

        json_path.write_text(json.dumps(report_json, indent=2), encoding="utf-8")
        html_path.write_text(report_html, encoding="utf-8")
        pdf_path.write_bytes(report_pdf)

        summary = report_json.get("executive_summary", {})
        metadata = {
            "report_id": report_id,
            "title": safe_title,
            "generated_at": generated_at,
            "threat_count": int(summary.get("total_threats", 0)),
            "severity_distribution": summary.get("severity_distribution", {}),
            "file_size_bytes": pdf_path.stat().st_size,
            "files": {
                "json": json_filename,
                "html": html_filename,
                "pdf": pdf_filename,
            },
        }

        metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        return metadata

    def list_reports(self) -> list[Dict]:
        """List all saved reports by metadata, newest first."""
        reports: list[Dict] = []
        for meta_file in self.reports_dir.glob("*.meta.json"):
            try:
                payload = json.loads(meta_file.read_text(encoding="utf-8"))
                reports.append(payload)
            except (json.JSONDecodeError, OSError):
                continue

        reports.sort(key=lambda x: x.get("generated_at", ""), reverse=True)
        return reports

    def get_saved_report(self, report_id: str) -> Optional[Dict]:
        """Return metadata for a saved report by ID."""
        meta_path = self.reports_dir / f"{report_id}.meta.json"
        if not meta_path.exists():
            return None
        return json.loads(meta_path.read_text(encoding="utf-8"))

    def delete_report(self, report_id: str) -> bool:
        """Delete saved report assets and metadata by ID."""
        metadata = self.get_saved_report(report_id)
        if not metadata:
            return False

        files = metadata.get("files", {})
        file_names = [
            files.get("json", f"{report_id}.json"),
            files.get("html", f"{report_id}.html"),
            files.get("pdf", f"{report_id}.pdf"),
            f"{report_id}.meta.json",
        ]

        for name in file_names:
            if not name:
                continue
            path = self.reports_dir / name
            if path.exists():
                path.unlink()

        return True
