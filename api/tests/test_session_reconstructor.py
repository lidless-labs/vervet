"""Tests for session reconstruction logic."""
import pytest
from unittest.mock import MagicMock
from dataclasses import dataclass

from api.services.session_reconstructor import SessionReconstructor


@dataclass
class MockConnection:
    src_ip: str = "203.0.113.1"
    dst_ip: str = "192.0.2.1"
    src_port: int = 49000
    dst_port: int = 443
    proto: str = "tcp"
    service: str = "ssl"
    timestamp: float = 1700000000.0
    duration: float = 1.5
    bytes_sent: int = 1000
    bytes_recv: int = 5000
    uid: str = "test-uid"


@dataclass
class MockDnsQuery:
    src_ip: str = "203.0.113.1"
    query: str = "example.com"
    query_type: str = "A"
    timestamp: float = 1700000000.0


class TestSessionGrouping:
    def _make_store(self, connections, dns_queries=None, alerts=None):
        store = MagicMock()
        store.connections = connections
        store.dns_queries = dns_queries or []
        store.alerts = alerts or []
        return store

    def test_single_session(self):
        """Connections within gap window form one session."""
        conns = [
            MockConnection(timestamp=1700000000.0),
            MockConnection(timestamp=1700000060.0),
            MockConnection(timestamp=1700000120.0),
        ]
        store = self._make_store(conns)
        reconstructor = SessionReconstructor(store, gap_seconds=300)
        sessions = reconstructor.reconstruct_all()
        assert len(sessions) == 1
        assert sessions[0].connection_count == 3

    def test_gap_splits_sessions(self):
        """Connections separated by > gap_seconds form separate sessions."""
        conns = [
            MockConnection(timestamp=1700000000.0),
            MockConnection(timestamp=1700000060.0),
            MockConnection(timestamp=1700001000.0),  # 1000s gap > 300s
        ]
        store = self._make_store(conns)
        reconstructor = SessionReconstructor(store, gap_seconds=300)
        sessions = reconstructor.reconstruct_all()
        assert len(sessions) == 2

    def test_different_ip_pairs(self):
        """Different IP pairs form separate sessions."""
        conns = [
            MockConnection(src_ip="203.0.113.1", dst_ip="192.0.2.1", timestamp=1700000000.0),
            MockConnection(src_ip="203.0.113.2", dst_ip="192.0.2.2", timestamp=1700000000.0),
        ]
        store = self._make_store(conns)
        reconstructor = SessionReconstructor(store, gap_seconds=300)
        sessions = reconstructor.reconstruct_all()
        assert len(sessions) == 2

    def test_bidirectional_grouping(self):
        """A->B and B->A go into the same session."""
        conns = [
            MockConnection(src_ip="203.0.113.1", dst_ip="192.0.2.1", timestamp=1700000000.0),
            MockConnection(src_ip="192.0.2.1", dst_ip="203.0.113.1", timestamp=1700000060.0),
        ]
        store = self._make_store(conns)
        reconstructor = SessionReconstructor(store, gap_seconds=300)
        sessions = reconstructor.reconstruct_all()
        assert len(sessions) == 1
        assert sessions[0].connection_count == 2

    def test_byte_totals(self):
        """Byte totals are summed correctly."""
        conns = [
            MockConnection(bytes_sent=1000, bytes_recv=2000, timestamp=1700000000.0),
            MockConnection(bytes_sent=3000, bytes_recv=4000, timestamp=1700000060.0),
        ]
        store = self._make_store(conns)
        reconstructor = SessionReconstructor(store, gap_seconds=300)
        sessions = reconstructor.reconstruct_all()
        assert sessions[0].total_bytes_sent == 4000
        assert sessions[0].total_bytes_recv == 6000

    def test_dns_enrichment(self):
        """DNS queries are attached to matching sessions."""
        conns = [MockConnection(timestamp=1700000000.0)]
        dns = [MockDnsQuery(src_ip="203.0.113.1", timestamp=1700000010.0)]
        store = self._make_store(conns, dns_queries=dns)
        reconstructor = SessionReconstructor(store, gap_seconds=300)
        sessions = reconstructor.reconstruct_all()
        assert sessions[0].dns_query_count == 1

    def test_session_id_deterministic(self):
        """Same inputs produce same session ID."""
        conns = [MockConnection(timestamp=1700000000.0)]
        store = self._make_store(conns)
        r1 = SessionReconstructor(store, gap_seconds=300)
        r2 = SessionReconstructor(store, gap_seconds=300)
        s1 = r1.reconstruct_all()
        s2 = r2.reconstruct_all()
        assert s1[0].session_id == s2[0].session_id


class TestSuspiciousFlags:
    def _make_store(self, connections):
        store = MagicMock()
        store.connections = connections
        store.dns_queries = []
        store.alerts = []
        return store

    def test_large_transfer_flag(self):
        """Sessions with >10MB get flagged."""
        conns = [MockConnection(bytes_sent=11_000_000, bytes_recv=0, timestamp=1700000000.0)]
        store = self._make_store(conns)
        sessions = SessionReconstructor(store).reconstruct_all()
        assert "large_transfer" in sessions[0].flags

    def test_rapid_connections_flag(self):
        """Many connections in short time get flagged."""
        conns = [MockConnection(timestamp=1700000000.0 + i * 0.5) for i in range(60)]
        store = self._make_store(conns)
        sessions = SessionReconstructor(store).reconstruct_all()
        assert "rapid_connections" in sessions[0].flags

    def test_beaconing_detection(self):
        """Regular interval connections get flagged as beaconing."""
        # 10 connections at exactly 60-second intervals
        conns = [MockConnection(timestamp=1700000000.0 + i * 60) for i in range(10)]
        store = self._make_store(conns)
        sessions = SessionReconstructor(store).reconstruct_all()
        assert "beaconing_pattern" in sessions[0].flags
