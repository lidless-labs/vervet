"""Verify multipart defaults through the application's batch upload route."""
import pytest
from fastapi.testclient import TestClient

from api.config import settings
from api.main import app


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(settings, "api_key", None)
    return TestClient(app)


@pytest.mark.parametrize("headers, expected", [
    (b"X-Example: example\r\n", 200),
    (b"X-Example: " + b"a" * 65536 + b"\r\n", 400),
    (b"X-Example: a\r\n" * 129, 400),
], ids=["valid", "header-size", "header-count"])
def test_batch_upload_header_bounds(client, headers, expected):
    body = (
        b'--example\r\nContent-Disposition: form-data; name="files"; filename="example.txt"\r\n'
        + headers + b"\r\nexample\r\n--example--\r\n"
    )
    response = client.post(
        "/api/v1/sigma/import-batch", content=body,
        headers={"Content-Type": "multipart/form-data; boundary=example"},
    )
    assert response.status_code == expected
    if expected == 200:
        assert response.json() == {"imported_count": 0, "rules": []}
    else:
        assert response.json() == {"detail": "Invalid multipart data."}


@pytest.mark.parametrize("size, expected", [(1048576, 200), (1048577, 400)])
def test_batch_upload_field_size_bounds(client, size, expected):
    response = client.post(
        "/api/v1/sigma/import-batch",
        files={"files": ("example.txt", b"example", "text/plain")},
        data={"note": "a" * size},
    )
    assert response.status_code == expected
    if expected == 200:
        assert response.json() == {"imported_count": 0, "rules": []}
    else:
        assert response.json() == {"detail": "Part exceeded maximum size of 1024KB."}
