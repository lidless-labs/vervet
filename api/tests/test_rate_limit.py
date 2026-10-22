"""Rate-limit decisions with isolated configuration and a controlled clock."""
from collections import defaultdict
import importlib
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

from api.dependencies.auth import api_key_auth
from api.middleware import rate_limit
from api.routers import workflow


def request_for(client="example-client", forwarded=None):
    headers = [] if forwarded is None else [(b"x-forwarded-for", forwarded.encode())]
    return Request({"type": "http", "headers": headers, "client": (client, 1234)})


@pytest.fixture
def limiter(monkeypatch):
    try:
        with monkeypatch.context() as scoped:
            scoped.setenv("VERVET_RATE_LIMIT_ENABLED", "true")
            scoped.setenv("VERVET_RATE_LIMIT_HOURLY", "2")
            scoped.setenv("VERVET_RATE_LIMIT_DAILY", "3")
            scoped.setenv("TRUSTED_PROXIES", "example-proxy")
            importlib.reload(rate_limit)
            clock = [1000000.0]
            scoped.setattr(rate_limit, "time", SimpleNamespace(time=lambda: clock[0]))
            scoped.setattr(rate_limit, "_upload_log", defaultdict(list))
            yield rate_limit, clock
    finally:
        importlib.reload(rate_limit)


def test_hourly_limit_and_retry_after(limiter):
    module, _ = limiter
    request = request_for()
    for _ in range(2):
        assert module.check_rate_limit(request) is None
        module.record_upload(request)
    blocked = module.check_rate_limit(request)
    assert blocked is not None
    assert "2 uploads per hour" in blocked["detail"]
    assert blocked["retry_after"] == 3600


def test_daily_limit_and_retry_after(limiter):
    module, clock = limiter
    module._upload_log["example-client"] = [clock[0] - 7200, clock[0] - 3601, clock[0] - 1]
    blocked = module.check_rate_limit(request_for())
    assert blocked is not None
    assert "3 uploads per day" in blocked["detail"]
    assert blocked["retry_after"] == 79200


def test_upload_route_returns_rate_limit_header_before_processing(limiter, monkeypatch):
    module, clock = limiter
    module._upload_log["example-client"] = [clock[0]] * 2
    app = FastAPI()
    app.dependency_overrides[api_key_auth] = lambda: "example-authorized"
    app.include_router(workflow.router)

    def unexpected_manager():
        pytest.fail("Rate-limited upload must not create an analysis job")

    monkeypatch.setattr(workflow, "_get_manager", unexpected_manager)

    async def identified_client(scope, receive, send):
        scope = {**scope, "client": ("example-client", 1234)}
        await app(scope, receive, send)

    response = TestClient(identified_client).post(
        "/upload-and-analyze", files={"file": ("example.pcap", b"example")},
    )
    assert response.status_code == 429
    assert response.headers["Retry-After"] == "3600"
    assert response.json() == {
        "detail": "Rate limit exceeded: 2 uploads per hour. Try again later.",
    }
    assert module._upload_log["example-client"] == [clock[0]] * 2


def test_client_budgets_are_independent(limiter):
    module, _ = limiter
    for _ in range(2):
        module.record_upload(request_for("example-first"))
    assert module.check_rate_limit(request_for("example-first")) is not None
    assert module.check_rate_limit(request_for("example-second")) is None


@pytest.mark.parametrize("window, count", [(3600, 2), (86400, 3)])
def test_exact_window_boundary_expires(limiter, window, count):
    module, clock = limiter
    module._upload_log["example-client"] = [clock[0] - window] * count
    assert module.check_rate_limit(request_for()) is None
    if window == 86400:
        assert module._upload_log["example-client"] == []


@pytest.mark.parametrize("client, forwarded, expected", [
    ("example-proxy", "example-forwarded, example-intermediate", "example-forwarded"),
    ("example-untrusted", "example-forwarded", "example-untrusted"),
    ("example-proxy", None, "example-proxy"),
    ("example-proxy", "", "example-proxy"),
])
def test_forwarded_address_requires_trusted_proxy(limiter, client, forwarded, expected):
    module, _ = limiter
    assert module._get_client_ip(request_for(client, forwarded)) == expected


def test_missing_client_uses_unknown(limiter):
    module, _ = limiter
    request = Request({"type": "http", "headers": [], "client": None})
    assert module._get_client_ip(request) == "unknown"


def test_trusted_proxy_separates_forwarded_budgets(limiter):
    module, _ = limiter
    first = request_for("example-proxy", "example-first")
    for _ in range(2):
        module.record_upload(first)
    assert module.check_rate_limit(first) is not None
    assert module.check_rate_limit(request_for("example-proxy", "example-second")) is None


def test_environment_can_disable_limits(monkeypatch):
    try:
        with monkeypatch.context() as scoped:
            scoped.setenv("VERVET_RATE_LIMIT_ENABLED", "false")
            importlib.reload(rate_limit)
            request = request_for()
            rate_limit._upload_log["example-client"] = [0.0] * 100
            assert rate_limit.check_rate_limit(request) is None
            rate_limit.record_upload(request)
            assert rate_limit._upload_log["example-client"] == [0.0] * 100
    finally:
        importlib.reload(rate_limit)
