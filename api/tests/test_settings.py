"""Tests for settings router."""
import os
import json
import pytest
from unittest.mock import patch

from api.routers.settings import _load_settings, _save_settings, _mask_key, DEFAULT_SETTINGS


class TestSettings:
    def test_default_settings_structure(self):
        assert "threat_intel" in DEFAULT_SETTINGS
        assert "scoring" in DEFAULT_SETTINGS
        assert "export" in DEFAULT_SETTINGS
        assert "display" in DEFAULT_SETTINGS

    def test_mask_key_short(self):
        assert _mask_key("") == ""
        assert _mask_key("abc") == "***"

    def test_mask_key_long(self):
        key = "abcdefghijklmnop"
        masked = _mask_key(key)
        assert masked.startswith("abcd")
        assert masked.endswith("mnop")
        assert "..." in masked

    def test_load_default_when_no_file(self, tmp_path):
        missing = str(tmp_path / "nonexistent_vervet_settings.json")
        with patch("api.routers.settings.SETTINGS_FILE", missing):
            settings = _load_settings()
            assert settings["scoring"]["beacon_weight"] == 1.0

    def test_save_and_load(self, tmp_path):
        settings_file = str(tmp_path / "test_settings.json")
        with patch("api.routers.settings.SETTINGS_FILE", settings_file):
            settings = _load_settings()
            settings["scoring"]["beacon_weight"] = 2.5
            _save_settings(settings)

            loaded = _load_settings()
            assert loaded["scoring"]["beacon_weight"] == 2.5
