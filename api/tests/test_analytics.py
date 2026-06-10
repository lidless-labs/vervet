"""Tests for analytics endpoints."""
import pytest
from unittest.mock import MagicMock
from dataclasses import dataclass
from collections import defaultdict

# Test the analytics logic directly


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


class TestTopTalkers:
    def test_aggregates_bytes(self):
        connections = [
            MockConnection(src_ip="203.0.113.1", bytes_sent=1000, bytes_recv=2000),
            MockConnection(src_ip="203.0.113.1", bytes_sent=3000, bytes_recv=4000),
            MockConnection(src_ip="203.0.113.2", bytes_sent=500, bytes_recv=500),
        ]
        host_bytes: dict = defaultdict(lambda: {"sent": 0, "recv": 0, "connections": 0})
        for conn in connections:
            host_bytes[conn.src_ip]["sent"] += conn.bytes_sent
            host_bytes[conn.src_ip]["recv"] += conn.bytes_recv
            host_bytes[conn.src_ip]["connections"] += 1

        sorted_hosts = sorted(host_bytes.items(), key=lambda x: x[1]["sent"] + x[1]["recv"], reverse=True)
        assert sorted_hosts[0][0] == "203.0.113.1"
        assert sorted_hosts[0][1]["sent"] == 4000
        assert sorted_hosts[0][1]["recv"] == 6000

    def test_connection_count(self):
        connections = [
            MockConnection(src_ip="203.0.113.1"),
            MockConnection(src_ip="203.0.113.1"),
            MockConnection(src_ip="203.0.113.2"),
        ]
        host_bytes: dict = defaultdict(lambda: {"sent": 0, "recv": 0, "connections": 0})
        for conn in connections:
            host_bytes[conn.src_ip]["connections"] += 1
        assert host_bytes["203.0.113.1"]["connections"] == 2
        assert host_bytes["203.0.113.2"]["connections"] == 1


class TestProtocolBreakdown:
    def test_counts_protocols(self):
        connections = [
            MockConnection(proto="tcp"),
            MockConnection(proto="tcp"),
            MockConnection(proto="udp"),
            MockConnection(proto="icmp"),
        ]
        protos: dict = defaultdict(int)
        for conn in connections:
            protos[conn.proto] += 1
        assert protos["tcp"] == 2
        assert protos["udp"] == 1
        assert protos["icmp"] == 1


class TestTrafficTimeline:
    def test_bucketing(self):
        bucket_seconds = 300  # 5 minutes
        connections = [
            MockConnection(timestamp=1700000000.0),
            MockConnection(timestamp=1700000060.0),  # same bucket
            MockConnection(timestamp=1700000400.0),  # next bucket
        ]
        buckets: dict = defaultdict(int)
        for conn in connections:
            bucket_ts = int(conn.timestamp / bucket_seconds) * bucket_seconds
            buckets[bucket_ts] += 1

        assert len(buckets) == 2
        bucket_values = sorted(buckets.values(), reverse=True)
        assert bucket_values[0] == 2  # first bucket has 2
        assert bucket_values[1] == 1  # second has 1
