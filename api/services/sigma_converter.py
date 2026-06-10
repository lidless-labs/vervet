"""Lightweight Sigma YAML converter for Vervet rules."""
from __future__ import annotations

import base64
import re
from typing import Any

from api.services.rule_engine import RuleCreate, RuleCondition

FIELD_MAP = {
    "SourceIp": "src_ip",
    "DestinationIp": "dst_ip",
    "SourcePort": "src_port",
    "DestinationPort": "dst_port",
    "Protocol": "proto",
    "QueryName": "dns_query",
    "DnsQuery": "dns_query",
    "UserAgent": "user_agent",
    "HttpMethod": "http_method",
    "Url": "http_uri",
    "StatusCode": "http_status",
    "TlsSni": "tls_server_name",
    "BytesOut": "bytes_orig",
    "BytesIn": "bytes_resp",
    "Duration": "duration",
}


def _coerce_scalar(raw: str) -> Any:
    s = raw.strip().strip('"').strip("'")
    if s.lower() in {"true", "false"}:
        return s.lower() == "true"
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    if re.fullmatch(r"-?\d+\.\d+", s):
        return float(s)
    return s


def parse_simple_yaml(content: str) -> dict[str, Any]:
    """Parse a small Sigma-friendly YAML subset (mappings + one-level lists)."""
    root: dict[str, Any] = {}
    stack: list[tuple[int, dict[str, Any]]] = [(-1, root)]

    for raw_line in content.splitlines():
        line = raw_line.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        indent = len(line) - len(line.lstrip(" "))
        text = line.strip()

        while stack and indent <= stack[-1][0]:
            stack.pop()

        parent = stack[-1][1]

        if text.startswith("- "):
            # List item support is only needed inside explicit list values; ignore top-level items.
            continue

        if ":" not in text:
            continue

        key, value = text.split(":", 1)
        key = key.strip()
        value = value.strip()

        if value == "":
            node: dict[str, Any] = {}
            parent[key] = node
            stack.append((indent, node))
            continue

        if value.startswith("[") and value.endswith("]"):
            items = [v.strip() for v in value[1:-1].split(",") if v.strip()]
            parent[key] = [_coerce_scalar(v) for v in items]
        else:
            parent[key] = _coerce_scalar(value)

    return root


def _map_field(field_expr: str) -> tuple[str, str]:
    if "|" not in field_expr:
        return FIELD_MAP.get(field_expr, field_expr), "eq"

    field, modifier = field_expr.split("|", 1)
    mapped = FIELD_MAP.get(field, field)

    modifier = modifier.strip().lower()
    if modifier == "contains":
        return mapped, "contains"
    if modifier == "startswith":
        return mapped, "regex"
    if modifier == "endswith":
        return mapped, "regex"
    if modifier in {"re", "all"}:
        return mapped, "regex"
    if modifier == "base64":
        return mapped, "contains"
    return mapped, "eq"


def convert_sigma_yaml(content: str, source: str | None = "sigma") -> RuleCreate:
    doc = parse_simple_yaml(content)
    title = str(doc.get("title", "Imported Sigma Rule"))
    description = str(doc.get("description", "Imported from Sigma"))
    level = str(doc.get("level", "medium")).lower()
    severity = level if level in {"low", "medium", "high", "critical"} else "medium"

    detection = doc.get("detection", {}) if isinstance(doc.get("detection", {}), dict) else {}
    condition_str = str(detection.get("condition", "selection"))

    logic = "OR" if " or " in condition_str.lower() else "AND"

    selection = detection.get("selection", {})
    if not isinstance(selection, dict):
        selection = {}

    conditions: list[RuleCondition] = []
    for raw_field, raw_value in selection.items():
        mapped_field, op = _map_field(raw_field)

        value = raw_value
        if isinstance(raw_value, str) and "|" in raw_field:
            modifier = raw_field.split("|", 1)[1].strip().lower()
            if modifier == "startswith":
                value = f"^{re.escape(raw_value)}"
            elif modifier == "endswith":
                value = f"{re.escape(raw_value)}$"
            elif modifier == "base64":
                value = base64.b64decode(raw_value).decode("utf-8", errors="ignore")

        if isinstance(raw_value, list):
            op = "in" if op == "eq" else op

        conditions.append(RuleCondition(field=mapped_field, operator=op, value=value))

    return RuleCreate(
        name=title,
        description=description,
        severity=severity,
        enabled=True,
        logic=logic,
        conditions=conditions,
        actions=["alert", "tag"],
        source=source,
    )


def convert_sigma_batch(files: list[tuple[str, str]]) -> list[RuleCreate]:
    converted: list[RuleCreate] = []
    for filename, content in files:
        rule = convert_sigma_yaml(content, source=f"sigma:{filename}")
        converted.append(rule)
    return converted
