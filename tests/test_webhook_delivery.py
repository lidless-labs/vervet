"""Offline checks for webhook destination and delivery bounds."""
import asyncio
import ipaddress
import json
import socket

import httpx
import pytest

from api.services import webhook_manager as module


GLOBAL_IP = str(ipaddress.IPv4Address(0x08080808))
LOCAL_IP = str(ipaddress.IPv4Address(0x7F000001))
GLOBAL_IPV6 = str(ipaddress.IPv6Address(0x20014860486000000000000000008888))


class Chunks(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            yield chunk

    async def aclose(self):
        self.closed = True


@pytest.fixture
def delivery(monkeypatch, tmp_path):
    monkeypatch.setattr(module, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(module, "CONFIGS_PATH", str(tmp_path / "configs.json"))
    monkeypatch.setattr(module, "HISTORY_PATH", str(tmp_path / "history.json"))
    manager = module.WebhookManager()
    requests = []
    resolutions = []
    answers = [GLOBAL_IP]
    response = {"status": 204, "chunks": [b"ok"]}

    def resolve(host, port, *args, **kwargs):
        resolutions.append((host, port))
        if response.get("dns_error"):
            raise socket.gaierror("example resolution detail")
        result = [(socket.AF_INET6 if ":" in ip else socket.AF_INET,
                   socket.SOCK_STREAM, 6, "", (ip, port)) for ip in answers]
        if response.get("change_dns"):
            answers[:] = [LOCAL_IP]
        return result

    async def send(transport, request):
        requests.append(request)
        if response.get("delay"):
            await asyncio.sleep(response["delay"])
        if response.get("error") or len(requests) > response.get("error_after", float("inf")):
            raise httpx.ConnectError("example transport detail")
        stream = Chunks(response["chunks"])
        response["stream"] = stream
        return httpx.Response(response["status"], stream=stream,
                              headers={"location": "https://example.com/next"})

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(httpx.AsyncHTTPTransport, "handle_async_request", send)
    config = module.WebhookConfig(id="example", name="Example", url="https://example.com/hook")
    return manager, config, requests, resolutions, answers, response


@pytest.mark.asyncio
@pytest.mark.parametrize("url", [
    "file:///example", "https:///hook", "https://name:pass@example.com/hook",
    "https://@example.com/hook", "https://example.com:0/hook",
    "https://example.com:65536/hook", "https://example.com:invalid/hook",
    "https://example.com:/hook", "https://example.com/\nnext",
    "https://bad_host.example.com/hook",
])
async def test_invalid_destination_is_rejected_before_transport(delivery, url):
    manager, config, requests, _, _, _ = delivery
    config.url = url
    record = await manager.send_webhook(config, {})
    assert (record.status, record.error) == ("failed", "Invalid webhook URL")
    assert requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize("addresses", [
    [], [GLOBAL_IP, LOCAL_IP], [LOCAL_IP, GLOBAL_IP],
    [str(ipaddress.IPv6Address(1))],
    [str(ipaddress.IPv4Network("224.0.0.0/4").network_address)],
    [str(ipaddress.IPv4Network("100.64.0.0/10").network_address)],
    [str(ipaddress.IPv4Network("192.0.2.0/24").network_address)],
])
async def test_all_dns_answers_must_be_global(delivery, addresses):
    manager, config, requests, _, answers, _ = delivery
    answers[:] = addresses
    record = await manager.send_webhook(config, {})
    assert record.error == "Invalid webhook destination"
    assert record.status == "failed"
    assert requests == []


@pytest.mark.asyncio
async def test_resolution_failure_is_stable(delivery):
    manager, config, requests, _, _, response = delivery
    response["dns_error"] = True
    record = await manager.send_webhook(config, {})
    assert record.error == "Webhook resolution failed"
    assert requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize("url", ["https://example.com/hook", "http://example.com:8080/hook"])
async def test_delivery_pins_address_and_preserves_authority(delivery, monkeypatch, url):
    manager, config, requests, resolutions, _, response = delivery
    monkeypatch.setenv("HTTPS_PROXY", "http://example.com:8081")
    config.url = url
    response["change_dns"] = True
    record = await manager.send_webhook(config, {"message": "Example"})
    assert record.status == "success"
    assert record.error is None
    assert len(resolutions) == len(requests) == 1
    request = requests[0]
    assert request.url.host == GLOBAL_IP
    assert request.headers["host"] == ("example.com:8080" if ":8080" in url else "example.com")
    assert request.extensions["sni_hostname"] == "example.com"
    assert response["stream"].closed


@pytest.mark.asyncio
async def test_redirect_is_not_followed(delivery):
    manager, config, requests, _, _, response = delivery
    response["status"] = 302
    record = await manager.send_webhook(config, {})
    assert record.error == "Webhook redirect rejected"
    assert len(requests) == 1


@pytest.mark.asyncio
async def test_network_retries_are_bounded_and_errors_are_generic(delivery):
    manager, config, requests, resolutions, _, response = delivery
    response.update(error=True, change_dns=True)
    record = await manager.send_webhook(config, {})
    assert record.error == "Webhook delivery failed"
    assert record.status == "failed"
    assert len(requests) == 3
    assert len(resolutions) == 1
    assert all(request.url.host == GLOBAL_IP for request in requests)


@pytest.mark.asyncio
async def test_last_attempt_does_not_retain_an_earlier_response_code(delivery):
    manager, config, requests, _, _, response = delivery
    response.update(status=503, error_after=1)
    record = await manager.send_webhook(config, {})
    assert record.error == "Webhook delivery failed"
    assert record.response_code is None
    assert len(requests) == 3


@pytest.mark.asyncio
async def test_internationalized_authority_uses_ascii_wire_name(delivery):
    manager, config, requests, resolutions, _, _ = delivery
    config.url = "https://xn--bcher-kva.example/hook"
    record = await manager.send_webhook(config, {})
    assert record.status == "success"
    assert resolutions[0][0] == "xn--bcher-kva.example"
    assert requests[0].headers["host"] == "xn--bcher-kva.example"
    assert requests[0].extensions["sni_hostname"] == "xn--bcher-kva.example"


@pytest.mark.asyncio
@pytest.mark.parametrize("literal", [False, True])
async def test_ipv6_delivery_preserves_authority(delivery, literal):
    manager, config, requests, resolutions, answers, _ = delivery
    answers[:] = [GLOBAL_IPV6]
    if literal:
        config.url = f"https://[{GLOBAL_IPV6}]/hook"
    record = await manager.send_webhook(config, {})
    assert record.status == "success"
    assert requests[0].url.host == GLOBAL_IPV6
    assert requests[0].headers["host"] == (f"[{GLOBAL_IPV6}]" if literal else "example.com")
    assert len(resolutions) == (0 if literal else 1)


@pytest.mark.asyncio
async def test_retained_history_is_bounded_in_memory_and_on_disk(delivery):
    manager, config, _, _, _, _ = delivery
    manager.history = [module.DeliveryRecord(
        id=f"example-{index}", config_name="Example", config_id=config.id,
        timestamp=0, status="failed",
    ) for index in range(100)]
    record = await manager.send_webhook(config, {})
    assert len(manager.history) == 100
    assert manager.history[0].id == "example-1"
    assert manager.history[-1] == record
    with open(module.HISTORY_PATH) as history:
        assert len(json.load(history)) == 100


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [400, 503])
async def test_http_failure_retries_are_bounded(delivery, status):
    manager, config, requests, _, _, response = delivery
    response["status"] = status
    record = await manager.send_webhook(config, {})
    assert (record.status, record.error, record.response_code) == (
        "failed", "Webhook HTTP error", status,
    )
    assert len(requests) == 3


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["discord", "slack"])
async def test_formatted_payload_has_its_own_size_limit(delivery, kind):
    manager, config, requests, resolutions, _, _ = delivery
    config.webhook_type = kind
    record = await manager.send_webhook(config, {"message": "x" * (65536 - 100)})
    assert record.error == "Webhook payload too large"
    assert len(record.payload_preview) == 200
    assert requests == resolutions == []


@pytest.mark.asyncio
async def test_large_response_is_bounded_and_closed(delivery):
    manager, config, requests, _, _, response = delivery
    response["chunks"] = [b"x" * 4096] * 17
    record = await manager.send_webhook(config, {})
    assert record.error == "Webhook response too large"
    assert record.status == "failed"
    assert len(requests) == 1
    assert response["stream"].closed


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["generic", "discord", "slack"])
async def test_large_payload_is_rejected_before_resolution(delivery, kind):
    manager, config, requests, resolutions, _, _ = delivery
    config.webhook_type = kind
    record = await manager.send_webhook(config, {"message": "x" * 65536})
    assert record.error == "Webhook payload too large"
    assert record.status == "failed"
    assert len(record.payload_preview) <= 200
    assert requests == resolutions == []


@pytest.mark.asyncio
async def test_attempt_and_overall_deadlines(delivery, monkeypatch):
    manager, config, requests, _, _, response = delivery
    monkeypatch.setattr(module, "ATTEMPT_TIMEOUT", 0.03, raising=False)
    monkeypatch.setattr(module, "DELIVERY_TIMEOUT", 0.05, raising=False)
    response["delay"] = 1
    async with asyncio.timeout(0.3):
        record = await manager.send_webhook(config, {})
    assert record.status == "failed"
    assert record.error == "Webhook delivery timed out"
    assert 1 <= len(requests) <= 2
