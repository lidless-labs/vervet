"""
Minimal TheHive client for exporting Vervet cases.
"""
from __future__ import annotations

import json
import os
from typing import Any
from urllib import error, request


class TheHiveClient:
    def __init__(self) -> None:
        self.base_url = os.getenv("THEHIVE_URL", "").rstrip("/")
        self.api_key = os.getenv("THEHIVE_API_KEY", "")
        self.auth_scheme = os.getenv("THEHIVE_AUTH_SCHEME", "Bearer")

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.api_key)

    def _headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Authorization": f"{self.auth_scheme} {self.api_key}",
        }

    def create_case(self, payload: dict[str, Any]) -> dict[str, Any]:
        if not self.configured:
            raise RuntimeError("TheHive integration is not configured")

        url = f"{self.base_url}/api/v1/case"
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(url, data=data, headers=self._headers(), method="POST")

        try:
            with request.urlopen(req, timeout=20) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw) if raw else {"status": "ok"}
        except error.HTTPError as e:
            body = e.read().decode("utf-8", errors="ignore") if hasattr(e, "read") else str(e)
            raise RuntimeError(f"TheHive HTTP {e.code}: {body}") from e
        except Exception as e:
            raise RuntimeError(f"TheHive request failed: {e}") from e


def map_vervet_case_to_thehive(case: dict[str, Any]) -> dict[str, Any]:
    severity_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    bh_sev = str(case.get("severity", "medium")).lower()

    findings = case.get("findings", [])[:10]
    finding_lines = [f"- [{f.get('severity', 'n/a')}] {f.get('summary', '')}" for f in findings]

    notes = case.get("notes", [])[:5]
    note_lines = [f"- {n.get('author', 'analyst')}: {n.get('content', '')}" for n in notes]

    description_parts = [
        case.get("description", "").strip(),
        "\nTop Findings:\n" + ("\n".join(finding_lines) if finding_lines else "- None"),
        "\nNotes:\n" + ("\n".join(note_lines) if note_lines else "- None"),
        f"\nSource Case ID: {case.get('id')}",
    ]

    tags = ["vervet", f"severity:{bh_sev}"] + list(case.get("tags", []))

    return {
        "title": case.get("title", "Vervet Case"),
        "description": "\n".join([p for p in description_parts if p]),
        "severity": severity_map.get(bh_sev, 2),
        "tags": tags,
        "tlp": 2,
        "pap": 2,
    }
