"""Tests for global search router."""
import pytest
from unittest.mock import MagicMock, patch
from dataclasses import dataclass
from typing import Optional

from api.routers.search import global_search


@dataclass
class MockConnection:
    src_ip: str = "203.0.113.1"
    dst_ip: str = "192.0.2.1"
    dst_port: int = 443
    proto: str = "tcp"
    duration: float = 1.5


@dataclass
class MockDNS:
    query: str = "example.com"
    qtype_name: str = "A"
    src_ip: str = "203.0.113.1"


@dataclass
class MockAlert:
    signature: str = "ET MALWARE Known Trojan"
    src_ip: str = "203.0.113.1"
    dst_ip: str = "192.0.2.1"
    severity: int = 1
    category: str = "Malware"


class TestSearch:
    @pytest.mark.asyncio
    async def test_search_by_ip(self):
        mock_store = MagicMock()
        mock_store.get_connections.return_value = [MockConnection()]
        mock_store.get_dns_queries.return_value = []
        mock_store.get_alerts.return_value = []

        with patch("api.routers.search.log_store", mock_store):
            results = await global_search(q="203.0.113")
            assert results["total"] > 0
            assert len(results["ips"]) > 0

    @pytest.mark.asyncio
    async def test_search_empty_results(self):
        mock_store = MagicMock()
        mock_store.get_connections.return_value = []
        mock_store.get_dns_queries.return_value = []
        mock_store.get_alerts.return_value = []

        with patch("api.routers.search.log_store", mock_store):
            results = await global_search(q="nonexistent_query_xyz")
            assert results["total"] == 0

    @pytest.mark.asyncio
    async def test_search_by_domain(self):
        mock_store = MagicMock()
        mock_store.get_connections.return_value = []
        mock_store.get_dns_queries.return_value = [MockDNS()]
        mock_store.get_alerts.return_value = []

        with patch("api.routers.search.log_store", mock_store):
            results = await global_search(q="example")
            assert len(results["domains"]) > 0

    @pytest.mark.asyncio
    async def test_search_by_alert(self):
        mock_store = MagicMock()
        mock_store.get_connections.return_value = []
        mock_store.get_dns_queries.return_value = []
        mock_store.get_alerts.return_value = [MockAlert()]

        with patch("api.routers.search.log_store", mock_store):
            results = await global_search(q="trojan")
            assert len(results["alerts"]) > 0
