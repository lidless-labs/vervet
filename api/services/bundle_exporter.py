"""Investigation bundle exporter for JSON, HTML, and STIX outputs."""
from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from api.config import settings
from api.services.annotations import annotations_service
from api.services.case_manager import CaseManager
from api.services.evidence_summary import IMPACTS, RESOLUTIONS, VERDICTS, clean_summary, technique_ids, timestamp, timestamp_key


class BundleExporter:
    """Builds export bundles for cases."""

    def __init__(self, case_manager: CaseManager):
        self.case_manager = case_manager

    @staticmethod
    def _text(value: Any, limit: int = 1024, *, empty: bool = False) -> str | None:
        if isinstance(value, str) and len(value) <= limit and (value or empty):
            return value
        return None

    def _decision(
        self, item: dict[str, Any], *, is_ioc: bool,
        annotations_by_target: dict[tuple[str, str], list[dict[str, Any]]],
    ) -> dict[str, Any] | None:
        targets = []
        uid = self._text(item.get("related_connection_uid"))
        if uid:
            targets.append(("connection", uid))
        if is_ioc and item.get("type") == "ip" and self._text(item.get("value")):
            targets.append(("host", item["value"]))
        if item.get("type") in annotations_service.VALID_TARGET_TYPES and self._text(item.get("id")):
            targets.append((item["type"], item["id"]))
        annotations = [
            annotation for target_type, target_id in targets
            for annotation in annotations_by_target.get((target_type, target_id), [])
            if isinstance(annotation.get("verdict"), str) and annotation["verdict"] in VERDICTS
        ]
        def annotation_instant(annotation: dict[str, Any]) -> tuple[int, int, int]:
            time = timestamp(annotation.get("updated_at")) or timestamp(annotation.get("created_at"))
            return timestamp_key(time)

        annotations.sort(key=annotation_instant)
        verdict = item.get("verdict")
        if not isinstance(verdict, str) or verdict not in VERDICTS:
            verdict = None
        # An IOC's stored verdict remains its decision. Only an annotation with
        # the same verdict supplies attribution for that decision.
        if is_ioc:
            annotations = [a for a in annotations if a["verdict"] == verdict]
        annotation = annotations[-1] if annotations else None
        if not is_ioc and annotation:
            verdict = annotation["verdict"]
        if verdict is None:
            return None
        return {
            "verdict": verdict,
            "rationale": self._text(annotation.get("content"), 8192, empty=True) if annotation else None,
            "by": self._text(annotation.get("author")) if annotation else None,
            "at": (timestamp(annotation.get("updated_at")) or timestamp(annotation.get("created_at"))) if annotation else None,
        }

    def _evidence_record(
        self, item: dict[str, Any], *, is_ioc: bool,
        annotations_by_target: dict[tuple[str, str], list[dict[str, Any]]],
    ) -> dict[str, Any]:
        identity = self._text(item.get("id"))
        if identity is None:
            raise ValueError("Evidence item has no bounded identity")
        data = item.get("data") if isinstance(item.get("data"), dict) else {}
        tool = self._text(item.get("source") if is_ioc else item.get("type")) or "vervet"
        ref = self._text(item.get("related_connection_uid")) or self._text(item.get("related_rule_id")) or self._text(item.get("ref"))
        raw = {}
        for field in (("type", "value") if is_ioc else ("type", "summary", "severity")):
            value = self._text(item.get(field), 8192, empty=True)
            if value is not None:
                raw[field] = value
        mappings = data.get("mitre_techniques")
        # Retain the bounded original mapping facts separately from normalized
        # technique_ids. Other finding/provider data is not copied into raw.
        if isinstance(mappings, list) and len(mappings) <= 64 and all(self._text(t) is not None for t in mappings):
            raw["mitre_techniques"] = mappings
        enrichments = []
        techniques = technique_ids(mappings)
        if techniques:
            enrichments.append({"kind": "attack", "provider": "vervet", "value": {"technique_ids": techniques}, "at": None})
        stored = item.get("enrichment", [])
        summaries = {}
        for value in stored[:64] if isinstance(stored, list) else []:
            summary = clean_summary(value)
            if summary:
                summaries[summary["provider"]] = summary
        for summary in summaries.values():
            enrichments.append({
                "kind": "ti", "provider": summary["provider"],
                "value": {key: summary[key] for key in ("hit_count", "refs", "observed_at")},
                "at": summary["at"],
            })
            if summary["mitre_techniques"]:
                enrichments.append({
                    "kind": "attack", "provider": summary["provider"],
                    "value": {"technique_ids": summary["mitre_techniques"]}, "at": summary["at"],
                })
        return {
            "id": identity,
            "source": {"tool": tool, "observed_at": timestamp(item.get("observed_at")), "ref": ref, "raw": raw or None},
            "enrichment": enrichments,
            "decision": self._decision(item, is_ioc=is_ioc, annotations_by_target=annotations_by_target),
        }

    def export_evidence_record(self, case_id: str) -> dict[str, Any]:
        """Project stored case facts. References are opaque and never fetched."""
        case = self.case_manager.get_case(case_id)
        identity, title = self._text(case.get("id")), self._text(case.get("title"))
        if identity is None or title is None:
            raise ValueError("Case identity and title must be nonempty strings up to 1024 characters")
        findings, iocs = case.get("findings", []), case.get("iocs", [])
        if not isinstance(findings, list) or not isinstance(iocs, list) or len(findings) + len(iocs) > 10000:
            raise ValueError("Evidence export requires at most 10000 findings and IOCs")
        if any(not isinstance(item, dict) for item in findings + iocs):
            raise ValueError("Malformed case evidence item")
        annotations_by_target: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for annotation in annotations_service.list_all():
            target_type, target_id = annotation.get("target_type"), annotation.get("target_id")
            if isinstance(target_type, str) and isinstance(target_id, str):
                annotations_by_target.setdefault((target_type, target_id), []).append(annotation)
        resolution, impact = case.get("resolution"), case.get("impact")
        closed = case.get("status") in CaseManager.CLOSED_STATUSES
        result = {
            "format": "evidence-record", "format_version": "1",
            "generator": {"name": "vervet", "version": self._text(settings.app_version)},
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "subject": {"kind": "case", "id": identity, "title": title},
            "records": [
                self._evidence_record(item, is_ioc=False, annotations_by_target=annotations_by_target)
                for item in findings
            ] + [
                self._evidence_record(item, is_ioc=True, annotations_by_target=annotations_by_target)
                for item in iocs
            ],
            "closeout": {
                "status": "closed" if closed else "open",
                "resolution": resolution if isinstance(resolution, str) and resolution in RESOLUTIONS else None,
                "impact": impact if isinstance(impact, str) and impact in IMPACTS else None,
                "summary": self._text(case.get("summary"), 8192, empty=True),
                "closed_at": timestamp(case.get("closed_at")) if closed else None,
                "closed_by": self._text(case.get("assignee")),
            },
        }
        if len(json.dumps(result, ensure_ascii=False).encode("utf-8")) > 4 * 1024 * 1024:
            raise ValueError("Evidence export exceeds 4 MiB")
        return result

    def export_json(self, case_id: str) -> dict[str, Any]:
        case = self.case_manager.get_case(case_id)
        case["exported_at"] = datetime.now(timezone.utc).isoformat()
        case["export_format"] = "json"
        return case

    def export_stix(self, case_id: str) -> dict[str, Any]:
        case = self.case_manager.get_case(case_id)
        now = datetime.now(timezone.utc).isoformat()
        report_id = f"report--{uuid4()}"

        objects: list[dict[str, Any]] = [
            {
                "type": "report",
                "spec_version": "2.1",
                "id": report_id,
                "created": now,
                "modified": now,
                "name": case.get("title", "Vervet Case"),
                "description": case.get("description", ""),
                "published": now,
                "report_types": ["threat-report"],
                "labels": [f"severity:{case.get('severity', 'medium')}", f"status:{case.get('status', 'open')}"] + [f"tag:{t}" for t in case.get("tags", [])],
                "object_refs": [],
            }
        ]

        report_refs: list[str] = []

        for ioc in case.get("iocs", []):
            indicator_id = f"indicator--{uuid4()}"
            value = str(ioc.get("value", "")).replace("'", "\\'")
            ioc_type = ioc.get("type", "ip")
            if ioc_type == "domain":
                pattern = f"[domain-name:value = '{value}']"
            elif ioc_type == "url":
                pattern = f"[url:value = '{value}']"
            elif ioc_type == "hash":
                pattern = f"[file:hashes.SHA-256 = '{value}']"
            else:
                pattern = f"[ipv4-addr:value = '{value}']"

            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": indicator_id,
                    "created": now,
                    "modified": now,
                    "name": f"IOC: {ioc_type} {ioc.get('value')}",
                    "description": f"Source: {ioc.get('source', 'manual')} | Verdict: {ioc.get('verdict', 'unknown')}",
                    "indicator_types": ["malicious-activity"],
                    "pattern_type": "stix",
                    "pattern": pattern,
                    "valid_from": now,
                }
            )
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{uuid4()}",
                    "created": now,
                    "modified": now,
                    "relationship_type": "related-to",
                    "source_ref": report_id,
                    "target_ref": indicator_id,
                }
            )
            report_refs.append(indicator_id)

        objects[0]["object_refs"] = report_refs
        return {"type": "bundle", "id": f"bundle--{uuid4()}", "spec_version": "2.1", "objects": objects}

    def export_html(self, case_id: str) -> str:
        case = self.case_manager.get_case(case_id)
        findings = case.get("findings", [])
        notes = case.get("notes", [])
        iocs = case.get("iocs", [])
        timeline = sorted(case.get("timeline", []), key=lambda x: x.get("timestamp", ""))

        finding_rows = "".join(
            f"<tr><td>{html.escape(f.get('type', 'manual'))}</td><td>{html.escape(f.get('summary', ''))}</td><td>{html.escape(f.get('severity', 'medium'))}</td></tr>"
            for f in findings
        ) or "<tr><td colspan='3'>No findings</td></tr>"

        ioc_rows = "".join(
            f"<tr><td>{html.escape(i.get('type', ''))}</td><td>{html.escape(i.get('value', ''))}</td><td>{html.escape(i.get('source', ''))}</td><td>{html.escape(i.get('verdict', 'unknown'))}</td></tr>"
            for i in iocs
        ) or "<tr><td colspan='4'>No IOCs</td></tr>"

        note_blocks = "".join(
            f"<div class='note'><div class='meta'>{html.escape(n.get('author', 'analyst'))} · {html.escape(n.get('created_at', ''))}</div><pre>{html.escape(n.get('content', ''))}</pre></div>"
            for n in notes
        ) or "<p class='muted'>No notes.</p>"

        timeline_items = "".join(
            f"<li><span class='time'>{html.escape(e.get('timestamp', ''))}</span><span class='event'>{html.escape(e.get('description', ''))}</span></li>"
            for e in timeline
        ) or "<li><span class='event'>No timeline events</span></li>"

        mitre = sorted({t for f in findings for t in f.get("data", {}).get("mitre_techniques", []) if isinstance(t, str)})
        mitre_tags = "".join(f"<span class='tag'>{html.escape(t)}</span>" for t in mitre) or "<span class='muted'>No techniques identified</span>"

        return f"""<!doctype html>
<html>
<head>
  <meta charset='utf-8' />
  <meta name='viewport' content='width=device-width, initial-scale=1' />
  <title>Case Report - {html.escape(case.get('title', 'Case'))}</title>
  <style>
    body {{ background:#0f172a; color:#e2e8f0; font-family:Inter,system-ui,sans-serif; margin:0; padding:28px; }}
    .wrap {{ max-width:1100px; margin:0 auto; }}
    .card {{ background:#111827; border:1px solid #1f2937; border-radius:10px; padding:16px; margin-bottom:16px; }}
    h1,h2 {{ margin:0 0 8px; }}
    .muted {{ color:#94a3b8; }}
    table {{ width:100%; border-collapse:collapse; }}
    th,td {{ border-bottom:1px solid #1f2937; padding:8px; text-align:left; font-size:13px; }}
    .grid {{ display:grid; grid-template-columns:repeat(3,1fr); gap:12px; }}
    .timeline {{ list-style:none; padding:0; margin:0; }}
    .timeline li {{ display:flex; gap:10px; padding:8px 0; border-bottom:1px solid #1f2937; }}
    .time {{ color:#94a3b8; font-family:monospace; font-size:12px; min-width:250px; }}
    .note pre {{ white-space:pre-wrap; margin:8px 0 0; background:#0b1220; border:1px solid #1f2937; border-radius:6px; padding:8px; }}
    .tag {{ display:inline-block; margin:3px 5px 0 0; background:#1e3a8a33; color:#93c5fd; border:1px solid #1e40af66; border-radius:9999px; padding:2px 8px; font-size:11px; }}
  </style>
</head>
<body>
  <div class='wrap'>
    <div class='card'>
      <h1>{html.escape(case.get('title', 'Untitled Case'))}</h1>
      <p class='muted'>{html.escape(case.get('description', ''))}</p>
      <div class='grid'>
        <div><strong>Status:</strong> {html.escape(case.get('status', 'open'))}</div>
        <div><strong>Severity:</strong> {html.escape(case.get('severity', 'medium'))}</div>
        <div><strong>Assignee:</strong> {html.escape(case.get('assignee') or 'Unassigned')}</div>
      </div>
    </div>

    <div class='card'>
      <h2>Executive Summary</h2>
      <p class='muted'>Findings: {len(findings)} · IOCs: {len(iocs)} · Notes: {len(notes)} · Timeline events: {len(timeline)}</p>
      <div><strong>MITRE ATT&CK:</strong> {mitre_tags}</div>
    </div>

    <div class='card'>
      <h2>Findings</h2>
      <table><thead><tr><th>Type</th><th>Summary</th><th>Severity</th></tr></thead><tbody>{finding_rows}</tbody></table>
    </div>

    <div class='card'>
      <h2>IOCs</h2>
      <table><thead><tr><th>Type</th><th>Value</th><th>Source</th><th>Verdict</th></tr></thead><tbody>{ioc_rows}</tbody></table>
    </div>

    <div class='card'>
      <h2>Timeline</h2>
      <ul class='timeline'>{timeline_items}</ul>
    </div>

    <div class='card'>
      <h2>Notes</h2>
      {note_blocks}
    </div>
  </div>
</body>
</html>"""


bundle_exporter = BundleExporter(CaseManager())
