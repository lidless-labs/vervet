"""Offline integration contracts using a MockTransport-backed urllib boundary."""
from io import BytesIO
from itertools import product
import json
from urllib import error, request

from fastapi import FastAPI
from fastapi.testclient import TestClient
import httpx
import pytest

from api.routers import integrations
from api.services.misp_client import MISPClient
from api.services.thehive_client import TheHiveClient
from api.services.wazuh_client import WazuhClient


CLIENTS = {"THEHIVE": TheHiveClient, "MISP": MISPClient, "WAZUH": WazuhClient}


@pytest.fixture(autouse=True)
def isolated_integration_environment(monkeypatch):
    for name in (
        "THEHIVE_URL", "THEHIVE_API_KEY", "THEHIVE_AUTH_SCHEME",
        "MISP_URL", "MISP_API_KEY", "MISP_SEARCH_PATH",
        "WAZUH_URL", "WAZUH_API_KEY", "WAZUH_AUTH_SCHEME", "WAZUH_ALERTS_PATH",
    ):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def upstream(monkeypatch):
    seen = []
    timeouts = []
    state = {"status": 200, "content": b'{"example": true}'}

    def respond(incoming):
        seen.append(incoming)
        if "error" in state:
            raise state["error"]
        return httpx.Response(state["status"], content=state["content"])

    transport = httpx.MockTransport(respond)

    def urlopen(outgoing, *, timeout):
        # The production clients use urllib. Preserve its request and error
        # boundary while MockTransport supplies every response without sockets.
        timeouts.append(timeout)
        response = transport.handle_request(httpx.Request(
            outgoing.get_method(), outgoing.full_url,
            headers=dict(outgoing.header_items()), content=outgoing.data,
        ))
        if response.status_code >= 400:
            raise error.HTTPError(
                outgoing.full_url, response.status_code, "Example HTTP error",
                response.headers, BytesIO(response.content),
            )
        return BytesIO(response.content)

    monkeypatch.setattr(request, "urlopen", urlopen)
    yield state, seen, timeouts
    transport.close()


def configured_client(monkeypatch, kind):
    monkeypatch.setenv(f"{kind}_URL", "https://example.com/")
    monkeypatch.setenv(f"{kind}_API_KEY", "example-key")
    return CLIENTS[kind]()


def invoke(kind, client, limit=7):
    if kind == "THEHIVE":
        return client.create_case({"title": "Example case", "severity": 2})
    if kind == "MISP":
        return client.search_attribute("example +&/?=", limit=limit)
    return client.search_alerts_for_ioc("example +&/?=", limit=limit)


@pytest.mark.parametrize("kind", CLIENTS)
@pytest.mark.parametrize("url, key, expected", [
    (False, False, False), (True, False, False),
    (False, True, False), (True, True, True),
])
def test_client_configuration_requires_url_and_key(monkeypatch, kind, url, key, expected):
    if url:
        monkeypatch.setenv(f"{kind}_URL", "https://example.com/")
    if key:
        monkeypatch.setenv(f"{kind}_API_KEY", "example-key")
    client = CLIENTS[kind]()
    assert client.configured is expected
    assert client.base_url == ("https://example.com" if url else "")


@pytest.mark.parametrize("kind", CLIENTS)
def test_unconfigured_client_never_calls_upstream(kind, upstream):
    _, seen, timeouts = upstream
    with pytest.raises(RuntimeError, match="integration is not configured"):
        invoke(kind, CLIENTS[kind]())
    assert seen == timeouts == []


@pytest.mark.parametrize("kind", CLIENTS)
def test_request_protocol_headers_payload_and_timeout(monkeypatch, kind, upstream):
    _, seen, timeouts = upstream
    assert invoke(kind, configured_client(monkeypatch, kind)) == {"example": True}
    assert len(seen) == 1
    outgoing = seen[0]
    assert outgoing.url.scheme == "https"
    assert outgoing.url.host == "example.com"
    assert outgoing.headers["Content-Type"] == "application/json"
    assert outgoing.headers["Authorization"] == (
        "example-key" if kind == "MISP" else "Bearer example-key"
    )
    assert timeouts == [20]
    if kind == "THEHIVE":
        assert outgoing.method == "POST"
        assert outgoing.url.path == "/api/v1/case"
        assert json.loads(outgoing.content) == {"title": "Example case", "severity": 2}
    elif kind == "MISP":
        assert outgoing.method == "POST"
        assert outgoing.url.path == "/attributes/restSearch"
        assert outgoing.headers["Accept"] == "application/json"
        assert json.loads(outgoing.content) == {
            "returnFormat": "json", "value": "example +&/?=", "limit": 7,
        }
    else:
        assert outgoing.method == "GET"
        assert outgoing.url.path == "/alerts"
        assert dict(outgoing.url.params) == {"q": "example +&/?=", "limit": "7"}
        assert outgoing.content == b""


@pytest.mark.parametrize("kind", ["THEHIVE", "WAZUH"])
def test_custom_authorization_scheme(monkeypatch, kind, upstream):
    monkeypatch.setenv(f"{kind}_AUTH_SCHEME", "Example")
    invoke(kind, configured_client(monkeypatch, kind))
    assert upstream[1][0].headers["Authorization"] == "Example example-key"


@pytest.mark.parametrize("kind, setting", [
    ("MISP", "MISP_SEARCH_PATH"), ("WAZUH", "WAZUH_ALERTS_PATH"),
])
def test_custom_search_path(monkeypatch, kind, setting, upstream):
    monkeypatch.setenv(setting, "/example/search")
    invoke(kind, configured_client(monkeypatch, kind))
    assert upstream[1][0].url.path == "/example/search"


@pytest.mark.parametrize("kind", CLIENTS)
@pytest.mark.parametrize("status", [401, 503])
def test_http_errors_map_to_runtime_error(monkeypatch, kind, status, upstream):
    state, seen, _ = upstream
    state.update(status=status, content=b"example upstream error")
    with pytest.raises(RuntimeError, match=f"HTTP {status}: example upstream error") as caught:
        invoke(kind, configured_client(monkeypatch, kind))
    assert isinstance(caught.value.__cause__, error.HTTPError)
    assert len(seen) == 1


@pytest.mark.parametrize("kind", CLIENTS)
@pytest.mark.parametrize("problem_type", [TimeoutError, error.URLError])
def test_network_errors_map_to_runtime_error(monkeypatch, kind, problem_type, upstream):
    problem = problem_type("example unavailable")
    upstream[0]["error"] = problem
    with pytest.raises(RuntimeError, match="request failed:") as caught:
        invoke(kind, configured_client(monkeypatch, kind))
    assert caught.value.__cause__ is problem
    assert len(upstream[1]) == 1


@pytest.mark.parametrize("kind", CLIENTS)
def test_invalid_json_maps_to_runtime_error(monkeypatch, kind, upstream):
    upstream[0]["content"] = b"example invalid JSON"
    with pytest.raises(RuntimeError, match="request failed:") as caught:
        invoke(kind, configured_client(monkeypatch, kind))
    assert isinstance(caught.value.__cause__, json.JSONDecodeError)


@pytest.mark.parametrize("kind", CLIENTS)
def test_empty_response_is_supported(monkeypatch, kind, upstream):
    upstream[0]["content"] = b""
    expected = {"status": "ok"} if kind == "THEHIVE" else {}
    assert invoke(kind, configured_client(monkeypatch, kind)) == expected


@pytest.mark.parametrize("enabled", list(product([False, True], repeat=3)))
def test_integration_status_configuration_matrix(monkeypatch, enabled):
    for kind, configured in zip(CLIENTS, enabled):
        if configured:
            configured_client(monkeypatch, kind)
    app = FastAPI()
    app.include_router(integrations.router)
    response = TestClient(app).get("/api/v1/integrations/status")
    assert response.status_code == 200
    data = response.json()
    for kind, configured in zip(CLIENTS, enabled):
        assert data[kind.lower()]["configured"] is configured
        assert data[kind.lower()]["url"] == ("https://example.com" if configured else None)
    assert data["misp"]["search_path"] == "/attributes/restSearch"
    assert data["wazuh"]["alerts_path"] == "/alerts"
