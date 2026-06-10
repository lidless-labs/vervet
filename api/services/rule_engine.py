"""Custom detection rule engine for Vervet."""
from __future__ import annotations

import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field

from api.services.log_store import log_store

SEVERITIES = {"low", "medium", "high", "critical"}
OPERATORS = {"eq", "neq", "contains", "regex", "gt", "lt", "in", "not_in", "cidr_match"}
RULE_FIELDS = {
    "src_ip", "dst_ip", "src_port", "dst_port", "proto", "conn_state", "service",
    "dns_query", "http_method", "http_uri", "http_status", "user_agent", "tls_server_name",
    "bytes_orig", "bytes_resp", "duration",
}

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
RULES_FILE = os.path.join(ROOT_DIR, "data", "rules.json")


class RuleCondition(BaseModel):
    field: str
    operator: str
    value: Any


class RuleDefinition(BaseModel):
    id: str
    name: str
    description: str = ""
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    enabled: bool = True
    logic: Literal["AND", "OR"] = "AND"
    conditions: list[RuleCondition] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=list)
    created_at: str
    updated_at: str
    hit_count: int = 0
    source: str | None = None


class RuleCreate(BaseModel):
    name: str
    description: str = ""
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    enabled: bool = True
    logic: Literal["AND", "OR"] = "AND"
    conditions: list[RuleCondition] = Field(default_factory=list)
    actions: list[str] = Field(default_factory=list)
    source: str | None = None


class RuleUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    severity: Literal["low", "medium", "high", "critical"] | None = None
    enabled: bool | None = None
    logic: Literal["AND", "OR"] | None = None
    conditions: list[RuleCondition] | None = None
    actions: list[str] | None = None
    hit_count: int | None = None
    source: str | None = None


class RuleEngine:
    def __init__(self, rules_file: str = RULES_FILE):
        self.rules_file = rules_file
        self._ensure_file()

    def _ensure_file(self):
        os.makedirs(os.path.dirname(self.rules_file), exist_ok=True)
        if not os.path.exists(self.rules_file):
            with open(self.rules_file, "w", encoding="utf-8") as f:
                json.dump([], f, indent=2)

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _load(self) -> list[RuleDefinition]:
        self._ensure_file()
        with open(self.rules_file, "r", encoding="utf-8") as f:
            data = json.load(f) or []
        return [RuleDefinition(**r) for r in data]

    def _save(self, rules: list[RuleDefinition]):
        with open(self.rules_file, "w", encoding="utf-8") as f:
            json.dump([r.model_dump() for r in rules], f, indent=2)

    def list_rules(self) -> list[RuleDefinition]:
        return self._load()

    def get_rule(self, rule_id: str) -> RuleDefinition | None:
        for rule in self._load():
            if rule.id == rule_id:
                return rule
        return None

    def create_rule(self, payload: RuleCreate) -> RuleDefinition:
        self._validate_payload(payload.logic, payload.conditions)
        now = self._now()
        rule = RuleDefinition(
            id=str(uuid4()),
            name=payload.name.strip(),
            description=payload.description,
            severity=payload.severity,
            enabled=payload.enabled,
            logic=payload.logic,
            conditions=payload.conditions,
            actions=payload.actions,
            created_at=now,
            updated_at=now,
            hit_count=0,
            source=payload.source,
        )
        rules = self._load()
        rules.append(rule)
        self._save(rules)
        return rule

    def update_rule(self, rule_id: str, payload: RuleUpdate) -> RuleDefinition | None:
        rules = self._load()
        for idx, rule in enumerate(rules):
            if rule.id != rule_id:
                continue

            updates = payload.model_dump(exclude_unset=True)
            next_logic = updates.get("logic", rule.logic)
            next_conditions = updates.get("conditions", rule.conditions)
            self._validate_payload(next_logic, next_conditions)

            merged = rule.model_dump()
            merged.update(updates)
            merged["updated_at"] = self._now()
            updated = RuleDefinition(**merged)
            rules[idx] = updated
            self._save(rules)
            return updated
        return None

    def delete_rule(self, rule_id: str) -> bool:
        rules = self._load()
        next_rules = [r for r in rules if r.id != rule_id]
        if len(next_rules) == len(rules):
            return False
        self._save(next_rules)
        return True

    def test_rule(self, rule: RuleDefinition) -> dict[str, Any]:
        matches = self._evaluate_rule(rule)
        return {
            "rule_id": rule.id,
            "rule_name": rule.name,
            "match_count": len(matches),
            "sample_matches": matches[:25],
        }

    def evaluate_enabled(self) -> dict[str, Any]:
        rules = self._load()
        summary: list[dict[str, Any]] = []
        updated_rules: list[RuleDefinition] = []

        for rule in rules:
            if not rule.enabled:
                updated_rules.append(rule)
                continue

            matches = self._evaluate_rule(rule)
            updated = RuleDefinition(**{
                **rule.model_dump(),
                "hit_count": rule.hit_count + len(matches),
                "updated_at": self._now(),
            })
            updated_rules.append(updated)
            summary.append({
                "rule_id": rule.id,
                "rule_name": rule.name,
                "severity": rule.severity,
                "matches": len(matches),
                "sample_matches": matches[:10],
            })

        self._save(updated_rules)
        return {
            "evaluated_rules": len(summary),
            "total_matches": sum(r["matches"] for r in summary),
            "results": summary,
        }

    def _validate_payload(self, logic: str, conditions: list[RuleCondition]):
        if logic not in {"AND", "OR"}:
            raise ValueError("logic must be AND or OR")
        for cond in conditions:
            if cond.operator not in OPERATORS:
                raise ValueError(f"unsupported operator: {cond.operator}")
            if cond.field not in RULE_FIELDS:
                raise ValueError(f"unsupported field: {cond.field}")

    def _iter_events(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []

        for conn in log_store.get_connections():
            row = conn.model_dump()
            events.append({
                "kind": "connection",
                "uid": row.get("uid"),
                "src_ip": row.get("src_ip"),
                "dst_ip": row.get("dst_ip"),
                "src_port": row.get("src_port"),
                "dst_port": row.get("dst_port"),
                "proto": row.get("proto"),
                "conn_state": row.get("conn_state"),
                "service": row.get("service"),
                "bytes_orig": row.get("bytes_sent"),
                "bytes_resp": row.get("bytes_recv"),
                "duration": row.get("duration"),
                "timestamp": row.get("timestamp"),
            })

        for dns in log_store.get_dns_queries():
            row = dns.model_dump()
            events.append({
                "kind": "dns",
                "src_ip": row.get("src_ip"),
                "dst_ip": row.get("dst_ip"),
                "src_port": row.get("src_port"),
                "dst_port": row.get("dst_port"),
                "dns_query": row.get("query"),
                "proto": "udp",
                "service": "dns",
                "timestamp": row.get("timestamp"),
            })

        for alert in log_store.get_alerts():
            row = alert.model_dump()
            events.append({
                "kind": "alert",
                "src_ip": row.get("src_ip"),
                "dst_ip": row.get("dst_ip"),
                "src_port": row.get("src_port"),
                "dst_port": row.get("dst_port"),
                "proto": row.get("proto"),
                "service": "ids",
                "user_agent": row.get("signature"),
                "timestamp": row.get("timestamp"),
            })

        return events

    def _evaluate_rule(self, rule: RuleDefinition) -> list[dict[str, Any]]:
        matches: list[dict[str, Any]] = []
        events = self._iter_events()
        for event in events:
            outcomes = [self._match_condition(event, c) for c in rule.conditions]
            passed = all(outcomes) if rule.logic == "AND" else any(outcomes)
            if passed:
                matches.append(event)
        return matches

    def _match_condition(self, event: dict[str, Any], cond: RuleCondition) -> bool:
        left = event.get(cond.field)
        op = cond.operator
        right = cond.value

        if op == "eq":
            return str(left) == str(right)
        if op == "neq":
            return str(left) != str(right)
        if op == "contains":
            return str(right).lower() in str(left or "").lower()
        if op == "regex":
            try:
                return re.search(str(right), str(left or ""), flags=re.IGNORECASE) is not None
            except re.error:
                return False
        if op == "gt":
            try:
                return float(left) > float(right)
            except (TypeError, ValueError):
                return False
        if op == "lt":
            try:
                return float(left) < float(right)
            except (TypeError, ValueError):
                return False
        if op == "in":
            if isinstance(right, list):
                return str(left) in [str(v) for v in right]
            return str(left) in [v.strip() for v in str(right).split(",")]
        if op == "not_in":
            if isinstance(right, list):
                return str(left) not in [str(v) for v in right]
            return str(left) not in [v.strip() for v in str(right).split(",")]
        if op == "cidr_match":
            try:
                return ipaddress.ip_address(str(left)) in ipaddress.ip_network(str(right), strict=False)
            except ValueError:
                return False

        return False


rule_engine = RuleEngine()
