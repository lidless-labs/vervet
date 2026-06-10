"""Tests for baseline profiler service."""
from datetime import datetime, timezone, timedelta

from api.parsers.unified import Connection, DnsQuery
from api.services.log_store import LogStore
from api.services.baseline_profiler import BaselineProfiler


def _build_store() -> LogStore:
    store = LogStore()
    now = datetime.now(timezone.utc)

    for i in range(30):
        store._add_connection(
            Connection(
                uid=f"conn-{i}",
                src_ip=f"203.0.113.{(i % 5) + 1}",
                src_port=50000 + i,
                dst_ip=f"198.51.100.{(i % 7) + 1}",
                dst_port=443 if i % 2 == 0 else 53,
                proto="tcp" if i % 3 else "udp",
                service="https",
                duration=1.0 + (i % 4),
                bytes_sent=1000 + i * 50,
                bytes_recv=600 + i * 25,
                timestamp=now + timedelta(minutes=i),
                tags=[],
                source="zeek",
            )
        )

    for i in range(20):
        store._add_dns_query(
            DnsQuery(
                timestamp=now + timedelta(minutes=i),
                src_ip=f"203.0.113.{(i % 4) + 1}",
                src_port=53000 + i,
                dst_ip="8.8.8.8",
                dst_port=53,
                query=f"domain{i}.example.com",
                qtype="A",
                rcode="NOERROR",
                answers=["203.0.113.10"],
                source="zeek",
            )
        )

    return store


def test_build_baseline_contains_required_sections():
    profiler = BaselineProfiler(_build_store())
    baseline = profiler.build_baseline()

    assert baseline["connection_count"] == 30
    assert "protocol_distribution" in baseline
    assert "traffic_volume" in baseline
    assert "duration_stats" in baseline
    assert "dns_profile" in baseline
    assert "host_profile" in baseline


def test_compare_returns_deviation_list():
    store = _build_store()
    profiler = BaselineProfiler(store)
    profiler.build_baseline()

    # Inject spike for comparison
    now = datetime.now(timezone.utc)
    for i in range(10):
        store._add_connection(
            Connection(
                uid=f"spike-{i}",
                src_ip="203.0.113.99",
                src_port=51000 + i,
                dst_ip="203.0.113.250",
                dst_port=4444,
                proto="tcp",
                service="unknown",
                duration=40.0,
                bytes_sent=800000,
                bytes_recv=1000,
                timestamp=now + timedelta(seconds=i),
                tags=[],
                source="zeek",
            )
        )

    result = profiler.compare_against_baseline()
    assert result["status"] == "ok"
    assert isinstance(result["deviations"], list)
