"""Exercise the real import-time startup guard in isolated subprocesses."""
import os
from pathlib import Path
import subprocess
import sys

import pytest


@pytest.mark.parametrize("environment, key, expected", [
    ("production", None, 1),
    ("PRODUCTION", None, 1),
    ("production", "", 1),
    ("production", "example-key", 0),
    ("development", None, 0),
])
def test_startup_authentication_guard(monkeypatch, environment, key, expected):
    monkeypatch.setenv("vervet_api_key", "example-parent-key")
    env = {name: value for name, value in os.environ.items()
           if not name.upper().startswith(("VERVET_", "BROHUNTER_"))}
    env["VERVET_ENV"] = environment
    env["VERVET_DEMO_MODE"] = "false"
    if key is not None:
        env["VERVET_API_KEY"] = key
    result = subprocess.run(
        [sys.executable, "-c", "import api.main"], env=env,
        cwd=Path(__file__).resolve().parents[2],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == expected, result.stderr
    if expected:
        assert "Refusing to start without authentication" in result.stderr
    elif key is None:
        assert "authentication is disabled" in result.stderr
