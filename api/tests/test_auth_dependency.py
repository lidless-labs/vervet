"""Offline contracts for the API key dependency and comparison helper."""
from typing import Annotated
from unittest.mock import patch

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from api.config import settings
from api.dependencies.auth import _secure_compare, api_key_auth


@pytest.mark.parametrize("configured, supplied, expected", [
    (None, None, 200),
    ("", None, 200),
    (None, "example-unused", 200),
    ("example-key", None, 401),
    ("example-key", "example-wrong", 401),
    ("example-key", "example-key", 200),
    ("example-key", "", 401),
])
def test_authentication_contract(monkeypatch, configured, supplied, expected):
    monkeypatch.setattr(settings, "api_key", configured)
    app = FastAPI()

    @app.get("/example")
    async def protected(key: Annotated[str, Depends(api_key_auth)]):
        return {"authorized": True, "development": key == "dev-mode"}

    headers = {} if supplied is None else {"X-API-Key": supplied}
    response = TestClient(app).get("/example", headers=headers)
    assert response.status_code == expected
    if expected == 200:
        assert response.json() == {"authorized": True, "development": not bool(configured)}
    else:
        assert response.headers["WWW-Authenticate"] == "ApiKey"
        assert response.json()["detail"] == (
            "Missing API key. Provide X-API-Key header." if not supplied else "Invalid API key."
        )


@pytest.mark.parametrize("left, right, expected", [
    ("example", "example", True),
    ("example", "different", False),
    ("example", "example-longer", False),
    ("", "", True),
    ("", "example", False),
    ("éxample", "éxample", True),
    ("éxample", "example", False),
])
def test_secure_comparison_values(left, right, expected):
    assert _secure_compare(left, right) is expected


def test_secure_comparison_uses_constant_time_primitive():
    with patch("hmac.compare_digest", return_value=True) as compare:
        assert _secure_compare("éxample", "éxample") is True
    compare.assert_called_once_with("éxample".encode(), "éxample".encode())
