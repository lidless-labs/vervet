"""
Case manager service for case CRUD, findings, notes, IOC tracking, and timeline events.
"""
from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from api.services.evidence_summary import IMPACTS, RESOLUTIONS, VERDICTS, clean_summary, summarize_hits


class CaseManager:
    """File-backed case management service."""

    VALID_STATUS = {"open", "investigating", "escalated", "resolved", "closed"}
    VALID_SEVERITY = {"low", "medium", "high", "critical"}
    VALID_FINDING_TYPES = {"connection", "dns", "alert", "rule_match", "manual"}
    VALID_IOC_TYPES = {"ip", "domain", "hash", "url"}
    VALID_VERDICTS = VERDICTS
    CLOSED_STATUSES = {"resolved", "closed"}

    def __init__(self, cases_dir: Optional[Path] = None):
        base_dir = Path(__file__).resolve().parents[2]
        self.cases_dir = cases_dir or (base_dir / "data" / "cases")
        self.cases_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def _case_path(self, case_id: str) -> Path:
        return self.cases_dir / f"{case_id}.json"

    def _read_case(self, case_id: str) -> dict[str, Any]:
        path = self._case_path(case_id)
        if not path.exists():
            raise FileNotFoundError(f"Case not found: {case_id}")
        return json.loads(path.read_text(encoding="utf-8"))

    def _write_case(self, case: dict[str, Any]) -> dict[str, Any]:
        case["updated_at"] = self._now_iso()
        path = self._case_path(case["id"])
        path.write_text(json.dumps(case, indent=2), encoding="utf-8")
        return case

    def _append_timeline(
        self,
        case: dict[str, Any],
        event_type: str,
        description: str,
        *,
        auto_generated: bool = True,
    ) -> None:
        case["timeline"].append(
            {
                "id": str(uuid4()),
                "timestamp": self._now_iso(),
                "event_type": event_type,
                "description": description,
                "auto_generated": auto_generated,
            }
        )

    def list_cases(
        self,
        *,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> list[dict[str, Any]]:
        cases: list[dict[str, Any]] = []
        for path in sorted(self.cases_dir.glob("*.json"), reverse=True):
            try:
                case = json.loads(path.read_text(encoding="utf-8"))
            except Exception:
                continue
            if status and case.get("status") != status:
                continue
            if severity and case.get("severity") != severity:
                continue
            if tags:
                case_tags = set(case.get("tags", []))
                if not set(tags).issubset(case_tags):
                    continue
            cases.append(case)
        return cases

    @staticmethod
    def _validate_closeout(payload: dict[str, Any]) -> None:
        for field, vocabulary in (("resolution", RESOLUTIONS), ("impact", IMPACTS)):
            value = payload.get(field)
            if value is not None and (not isinstance(value, str) or value not in vocabulary):
                raise ValueError(f"Invalid {field}: {value}")
        summary = payload.get("summary")
        if summary is not None and (not isinstance(summary, str) or len(summary) > 8192):
            raise ValueError("Summary must be null or a string of at most 8192 characters")

    def create_case(self, payload: dict[str, Any]) -> dict[str, Any]:
        status = payload.get("status", "open")
        severity = payload.get("severity", "medium")
        if status not in self.VALID_STATUS:
            raise ValueError(f"Invalid status: {status}")
        if severity not in self.VALID_SEVERITY:
            raise ValueError(f"Invalid severity: {severity}")

        self._validate_closeout(payload)
        now = self._now_iso()
        case = {
            "id": str(uuid4()),
            "title": payload["title"],
            "description": payload.get("description", ""),
            "status": status,
            "severity": severity,
            "assignee": payload.get("assignee"),
            "tags": payload.get("tags", []),
            "created_at": now,
            "updated_at": now,
            "closed_at": now if status in self.CLOSED_STATUSES else None,
            "resolution": payload.get("resolution"),
            "impact": payload.get("impact"),
            "summary": payload.get("summary"),
            "findings": [],
            "notes": [],
            "timeline": [],
            "iocs": [],
            "related_connections": payload.get("related_connections", []),
            "related_rules": payload.get("related_rules", []),
            "attachments": payload.get("attachments", []),
        }
        self._append_timeline(case, "case_created", "Case created")
        return self._write_case(case)

    def get_case(self, case_id: str) -> dict[str, Any]:
        return self._read_case(case_id)

    def update_case(self, case_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        case = self._read_case(case_id)
        previous_status = case.get("status")
        self._validate_closeout(payload)

        for field in [
            "title",
            "description",
            "status",
            "severity",
            "assignee",
            "tags",
            "related_connections",
            "related_rules",
            "attachments",
            "resolution",
            "impact",
            "summary",
        ]:
            if field in payload:
                case[field] = payload[field]

        if case.get("status") not in self.VALID_STATUS:
            raise ValueError(f"Invalid status: {case.get('status')}")
        if case.get("severity") not in self.VALID_SEVERITY:
            raise ValueError(f"Invalid severity: {case.get('severity')}")

        if previous_status != case.get("status"):
            if case.get("status") in self.CLOSED_STATUSES:
                if previous_status not in self.CLOSED_STATUSES:
                    case["closed_at"] = self._now_iso()
            else:
                case["closed_at"] = None
            self._append_timeline(
                case,
                "status_changed",
                f"Status changed from {previous_status} to {case.get('status')}",
            )

        return self._write_case(case)

    def delete_case(self, case_id: str) -> None:
        path = self._case_path(case_id)
        if not path.exists():
            raise FileNotFoundError(f"Case not found: {case_id}")
        path.unlink()

    def add_finding(self, case_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        case = self._read_case(case_id)
        finding_type = payload.get("type", "manual")
        if finding_type not in self.VALID_FINDING_TYPES:
            raise ValueError(f"Invalid finding type: {finding_type}")

        finding = {
            "id": str(uuid4()),
            "type": finding_type,
            "summary": payload["summary"],
            "severity": payload.get("severity", case.get("severity", "medium")),
            "data": payload.get("data", {}),
            "added_at": self._now_iso(),
        }
        for field in ("related_connection_uid", "related_rule_id", "observed_at"):
            if field in payload:
                finding[field] = payload[field]
        case["findings"].append(finding)

        uid = payload.get("related_connection_uid")
        if uid and uid not in case["related_connections"]:
            case["related_connections"].append(uid)

        rule_id = payload.get("related_rule_id")
        if rule_id and rule_id not in case["related_rules"]:
            case["related_rules"].append(rule_id)

        self._append_timeline(case, "finding_added", f"Finding added: {finding['summary']}")
        self._write_case(case)
        return finding

    def add_note(self, case_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        case = self._read_case(case_id)
        now = self._now_iso()
        note = {
            "id": str(uuid4()),
            "content": payload["content"],
            "author": payload.get("author", "analyst"),
            "created_at": now,
            "updated_at": now,
        }
        case["notes"].append(note)
        self._append_timeline(case, "note_added", f"Note added by {note['author']}")
        self._write_case(case)
        return note

    def update_note(self, case_id: str, note_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        case = self._read_case(case_id)
        note = next((n for n in case["notes"] if n["id"] == note_id), None)
        if not note:
            raise FileNotFoundError(f"Note not found: {note_id}")

        if "content" in payload:
            note["content"] = payload["content"]
        if "author" in payload:
            note["author"] = payload["author"]
        note["updated_at"] = self._now_iso()

        self._append_timeline(case, "note_updated", f"Note updated by {note['author']}")
        self._write_case(case)
        return note

    def add_ioc(self, case_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        case = self._read_case(case_id)
        ioc_type = payload.get("type", "ip").lower()
        if ioc_type not in self.VALID_IOC_TYPES:
            raise ValueError(f"Invalid IOC type: {ioc_type}")

        verdict = payload.get("verdict", "unknown")
        if not isinstance(verdict, str) or verdict not in self.VALID_VERDICTS:
            raise ValueError(f"Invalid verdict: {verdict}")

        ioc = {
            "id": str(uuid4()),
            "type": ioc_type,
            "value": payload["value"],
            "source": payload.get("source", "manual"),
            "verdict": verdict,
            "added_at": self._now_iso(),
        }
        for field in ("ref", "observed_at", "related_connection_uid"):
            if field in payload:
                ioc[field] = payload[field]
        case["iocs"].append(ioc)
        self._append_timeline(case, "ioc_added", f"IOC added: {ioc['type']} {ioc['value']}")
        self._write_case(case)
        return ioc

    def persist_ioc_enrichment(
        self, case_id: str, ioc_id: str, provider: str, hits: list[Any], count: int,
    ) -> None:
        case = self._read_case(case_id)
        ioc = next((item for item in case.get("iocs", []) if item.get("id") == ioc_id), None)
        if ioc is None:
            raise FileNotFoundError(f"IOC not found: {ioc_id}")
        summary = summarize_hits(provider, hits, count, self._now_iso())
        if summary is None:
            raise ValueError("Invalid provider summary")
        # One latest query summary per provider and stable case IOC identity.
        stored = ioc.get("enrichment", [])
        existing = {}
        for item in stored[:64] if isinstance(stored, list) else []:
            cleaned = clean_summary(item)
            if cleaned:
                existing[cleaned["provider"]] = cleaned
        existing[provider] = summary
        ioc["enrichment"] = list(existing.values())
        self._write_case(case)

    def get_timeline(self, case_id: str) -> list[dict[str, Any]]:
        case = self._read_case(case_id)
        timeline = sorted(case.get("timeline", []), key=lambda x: x.get("timestamp", ""))
        return deepcopy(timeline)


case_manager = CaseManager()
