"""
Webhook alert delivery manager.
Supports Discord, Slack, and generic JSON webhooks.
"""
import asyncio
import ipaddress
import json
import os
import re
import socket
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Optional
from urllib.parse import urlparse
import httpx

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data")
CONFIGS_PATH = os.path.join(DATA_DIR, "webhook_configs.json")
MAX_PAYLOAD_BYTES = 64 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
ATTEMPT_TIMEOUT = 3.0
DELIVERY_TIMEOUT = 10.0

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
    def _parse_url(url: str) -> httpx.URL:
        """Normalize one HTTP authority before resolving its destination."""
        try:
            if len(url) > 4096 or any(ord(c) <= 32 or ord(c) == 127 for c in url):
                raise ValueError
            parsed = urlparse(url)
            if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                    or parsed.username is not None or parsed.password is not None
                    or parsed.netloc.endswith(":")):
                raise ValueError
            port = parsed.port
            if port is not None and not 1 <= port <= 65535:
                raise ValueError
            normalized = httpx.URL(url)
            host = normalized.raw_host.decode("ascii")
            try:
                ipaddress.ip_address(host)
            except ValueError:
                labels = host.rstrip(".").split(".")
                if len(host) > 253 or any(
                    not re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label)
                    for label in labels
                ):
                    raise ValueError
            return normalized
        except (ValueError, httpx.InvalidURL):
            raise ValueError("Invalid webhook URL") from None

    @staticmethod
    async def _resolve_destination(url: httpx.URL) -> list[str]:
        """Require every answer to satisfy the global-address policy."""
        host = url.raw_host.decode("ascii")
        try:
            address = ipaddress.ip_address(host)
            addresses = [address]
        except ValueError:
            try:
                results = await asyncio.get_running_loop().getaddrinfo(
                    host, url.port or (443 if url.scheme == "https" else 80),
                    type=socket.SOCK_STREAM,
                )
                addresses = [ipaddress.ip_address(result[4][0]) for result in results]
            except (OSError, ValueError):
                raise ValueError("Webhook resolution failed") from None
        if not addresses or any(
            not address.is_global or address.is_multicast for address in addresses
        ):
            raise ValueError("Invalid webhook destination")
        return list(dict.fromkeys(str(address) for address in addresses))

    @staticmethod
    def _encode_payload(payload: dict) -> bytes:
        """Stop serialization as soon as the delivery size limit is exceeded."""
        body = bytearray()
        for chunk in json.JSONEncoder(ensure_ascii=True, allow_nan=False).iterencode(payload):
            if len(chunk) > MAX_PAYLOAD_BYTES - len(body):
                raise ValueError("Webhook payload too large")
            body.extend(chunk.encode("ascii"))
        return bytes(body)

    async def send_webhook(self, config: WebhookConfig, payload: dict) -> DeliveryRecord:
        record = DeliveryRecord(
            id=str(uuid.uuid4())[:8], config_name=config.name, config_id=config.id,
            timestamp=time.time(), status="failed",
        )
        try:
            async with asyncio.timeout(DELIVERY_TIMEOUT):
                raw_payload = self._encode_payload(payload)
                record.payload_preview = raw_payload[:200].decode("ascii")
                if config.webhook_type == "discord":
                    body = self._encode_payload(self._format_discord(payload))
                elif config.webhook_type == "slack":
                    body = self._encode_payload(self._format_slack(payload))
                else:
                    body = raw_payload
                url = self._parse_url(config.url)
                addresses = await self._resolve_destination(url)
                # The transport connects only to a validated address. Each attempt
                # moves to the next one, so an unreachable answer does not fail
                # the delivery. Host and TLS verification use the URL authority.
                transport = _PinnedTransport(addresses[0])
                async with httpx.AsyncClient(
                    transport=transport, timeout=ATTEMPT_TIMEOUT,
                    follow_redirects=False, trust_env=False,
                ) as client:
                    for attempt in range(3):
                        transport.address = addresses[attempt % len(addresses)]
                        record.response_code = None
                        try:
                            async with asyncio.timeout(ATTEMPT_TIMEOUT):
                                async with client.stream(
                                    "POST", url, content=body,
                                    headers={"Content-Type": "application/json", "Accept-Encoding": "identity"},
                                ) as response:
                                    record.response_code = response.status_code
                                    if 300 <= response.status_code < 400:
                                        record.error = "Webhook redirect rejected"
                                        break
                                    size = 0
                                    async for chunk in response.aiter_raw():
                                        size += len(chunk)
                                        if size > MAX_RESPONSE_BYTES:
                                            raise ValueError("Webhook response too large")
                                    if 200 <= response.status_code < 300:
                                        record.status = "success"
                                        record.error = None
                                        break
                                    record.error = "Webhook HTTP error"
                        except (httpx.HTTPError, OSError):
                            record.error = "Webhook delivery failed"
                        except TimeoutError:
                            record.error = "Webhook delivery timed out"
        except TimeoutError:
            record.error = "Webhook delivery timed out"
        except ValueError as exc:
            record.error = str(exc) if str(exc) in {
                "Invalid webhook URL", "Invalid webhook destination", "Webhook resolution failed",
                "Webhook payload too large", "Webhook response too large",
            } else "Invalid webhook payload"
        except (TypeError, OverflowError, RecursionError):
            record.error = "Invalid webhook payload"

        self.history.append(record)
        self.history = self.history[-100:]
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


class _PinnedTransport(httpx.AsyncHTTPTransport):
    """Connect to a checked IP while retaining the original HTTP/TLS authority."""

    def __init__(self, address: str):
        super().__init__(trust_env=False, retries=0)
        self.address = address

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        pinned = httpx.Request(
            request.method, request.url.copy_with(host=self.address),
            headers=request.headers, content=request.stream,
            extensions={**request.extensions, "sni_hostname": request.url.raw_host.decode("ascii")},
        )
        return await super().handle_async_request(pinned)


webhook_manager = WebhookManager()
