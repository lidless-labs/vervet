"""Application boundary checks for consistent API authentication."""
import re

import pytest
from fastapi.routing import APIRoute, iter_route_contexts
from fastapi.testclient import TestClient

from api.config import settings
from api.main import app
from api.routers import hosts, search, sessions
from api.services.log_store import LogStore


API_ROUTES = [
    route for route in iter_route_contexts(app.routes)
    if isinstance(route.route, APIRoute)
    and (route.path.startswith("/api/v1/") or route.path == "/api/status")
]
assert API_ROUTES, "API route enumeration must include registered endpoints"


@pytest.mark.parametrize("key", [None, "incorrect-example-key"])
@pytest.mark.parametrize("route", API_ROUTES, ids=lambda route: route.path)
def test_every_api_route_requires_key_before_endpoint(monkeypatch, route, key):
    monkeypatch.setattr(settings, "api_key", "configured-example-key")
    reached = []

    async def endpoint(**kwargs):
        reached.append(kwargs)
        return {"reached": True}

    monkeypatch.setattr(route.dependant, "call", endpoint)
    path = re.sub(r"\{[^}]+\}", "example", route.path)
    headers = {"X-API-Key": key} if key else {}
    client = TestClient(app)
    for method in route.methods:
        response = client.request(method, path, headers=headers, json={})
        assert response.status_code == 401, (method, path, response.text)
    assert reached == []


@pytest.mark.parametrize("configured", [None, "configured-example-key"])
def test_key_and_dev_mode_allow_read_routes_and_health(monkeypatch, configured):
    monkeypatch.setattr(settings, "api_key", configured)
    monkeypatch.setattr(settings, "demo_mode", False)
    for module in (hosts, search, sessions):
        monkeypatch.setattr(module, "log_store", LogStore())
    headers = {"X-API-Key": configured} if configured else {}
    paths = ["/api/status", "/api/v1/tls/stats", "/api/v1/http/stats",
             "/api/v1/lateral/stats", "/api/v1/webhooks", "/api/v1/trends/summary",
             "/api/v1/sessions", "/api/v1/search?q=example", "/api/v1/hosts/ranking",
             "/api/v1/cases", "/api/v1/hypotheses", "/api/v1/annotations",
             "/api/v1/rules", "/api/v1/settings", "/api/v1/baseline"]
    client = TestClient(app)
    for path in paths:
        response = client.get(path, headers=headers)
        assert response.status_code == 200, (path, response.text)
    assert client.get("/health").json() == {"status": "healthy"}
