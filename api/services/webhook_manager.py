"""
Webhook alert delivery manager.
Supports Discord, Slack, and generic JSON webhooks.
"""
import ipaddress
import json
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.parse import urlparse
import httpx

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
CONFIGS_PATH = os.path.join(DATA_DIR, "webhook_configs.json")
HISTORY_PATH = os.path.join(DATA_DIR, "webhook_history.json")


@dataclass
class WebhookConfig:
    id: str
    name: str
    url: str
    webhook_type: str = "generic"  # discord | slack | generic
    enabled: bool = True
    severity_threshold: str = "medium"  # critical | high | medium | low
    event_types: list[str] = field(default_factory=lambda: ["new_threat", "score_change", "beacon_detected", "cert_anomaly"])

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DeliveryRecord:
    id: str
    config_name: str
    config_id: str
    timestamp: float
    status: str  # success | failed | pending
    response_code: Optional[int] = None
    payload_preview: str = ""
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


class WebhookManager:
    def __init__(self):
        self.configs: list[WebhookConfig] = []
        self.history: list[DeliveryRecord] = []
        self._load()

    def _load(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        if os.path.exists(CONFIGS_PATH):
            try:
                with open(CONFIGS_PATH) as f:
                    data = json.load(f)
                self.configs = [WebhookConfig(**c) for c in data]
            except Exception:
                self.configs = []
        if os.path.exists(HISTORY_PATH):
            try:
                with open(HISTORY_PATH) as f:
                    data = json.load(f)
                self.history = [DeliveryRecord(**r) for r in data[-100:]]
            except Exception:
                self.history = []

    def _save_configs(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(CONFIGS_PATH, "w") as f:
            json.dump([c.to_dict() for c in self.configs], f, indent=2)

    def _save_history(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(HISTORY_PATH, "w") as f:
            json.dump([r.to_dict() for r in self.history[-100:]], f, indent=2)

    def add_config(self, data: dict) -> WebhookConfig:
        config = WebhookConfig(id=str(uuid.uuid4())[:8], **data)
        self.configs.append(config)
        self._save_configs()
        return config

    def update_config(self, config_id: str, data: dict) -> Optional[WebhookConfig]:
        for c in self.configs:
            if c.id == config_id:
                for k, v in data.items():
                    if hasattr(c, k) and k != "id":
                        setattr(c, k, v)
                self._save_configs()
                return c
        return None

    def delete_config(self, config_id: str) -> bool:
        before = len(self.configs)
        self.configs = [c for c in self.configs if c.id != config_id]
        if len(self.configs) < before:
            self._save_configs()
            return True
        return False

    def get_config(self, config_id: str) -> Optional[WebhookConfig]:
        return next((c for c in self.configs if c.id == config_id), None)

    def _format_discord(self, payload: dict) -> dict:
        return {
            "embeds": [{
                "title": f"🚨 {payload.get('event_type', 'Alert')}",
                "description": payload.get("message", "No details"),
                "color": 0xFF0000 if payload.get("severity") == "critical" else 0xFF8800,
                "fields": [
                    {"name": "Severity", "value": payload.get("severity", "unknown"), "inline": True},
                    {"name": "Source", "value": "Vervet", "inline": True},
                ],
                "timestamp": payload.get("timestamp", ""),
            }]
        }

    def _format_slack(self, payload: dict) -> dict:
        return {
            "blocks": [
                {"type": "header", "text": {"type": "plain_text", "text": f"🚨 {payload.get('event_type', 'Alert')}"}},
                {"type": "section", "text": {"type": "mrkdwn", "text": payload.get("message", "No details")}},
                {"type": "section", "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:* {payload.get('severity', 'unknown')}"},
                    {"type": "mrkdwn", "text": "*Source:* Vervet"},
                ]},
            ]
        }

    @staticmethod
    def _is_safe_url(url: str) -> bool:
        parsed = urlparse(url)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            return False
        try:
            ip = ipaddress.ip_address(parsed.hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
        except ValueError:
            pass  # non-IP hostname, allow
        return True

    async def send_webhook(self, config: WebhookConfig, payload: dict) -> DeliveryRecord:
        record = DeliveryRecord(
            id=str(uuid.uuid4())[:8],
            config_name=config.name,
            config_id=config.id,
            timestamp=time.time(),
            status="pending",
            payload_preview=json.dumps(payload)[:200],
        )

        if not self._is_safe_url(config.url):
            record.status = "failed"
            record.error = "Unsafe webhook URL (private/loopback/reserved)"
            self.history.append(record)
            self._save_history()
            return record

        if config.webhook_type == "discord":
            body = self._format_discord(payload)
        elif config.webhook_type == "slack":
            body = self._format_slack(payload)
        else:
            body = payload

        retries = 2
        for attempt in range(retries + 1):
            try:
                async with httpx.AsyncClient(timeout=3.0) as client:
                    resp = await client.post(config.url, json=body)
                record.response_code = resp.status_code
                if 200 <= resp.status_code < 300:
                    record.status = "success"
                    break
                else:
                    record.status = "failed"
                    record.error = f"HTTP {resp.status_code}"
            except Exception as exc:
                record.status = "failed"
                record.error = str(exc)
                if attempt < retries:
                    continue

        self.history.append(record)
        self._save_history()
        return record

    async def test_webhook(self, config_id: str) -> Optional[DeliveryRecord]:
        config = self.get_config(config_id)
        if not config:
            return None
        payload = {
            "event_type": "test_alert",
            "message": "This is a test alert from Vervet",
            "severity": "low",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        return await self.send_webhook(config, payload)


webhook_manager = WebhookManager()
