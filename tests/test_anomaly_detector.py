"""Tests for anomaly detector service."""
from datetime import datetime, timezone, timedelta

from api.parsers.unified import Connection, DnsQuery
from api.services.log_store import LogStore
from api.services.baseline_profiler import BaselineProfiler
from api.services.anomaly_detector import AnomalyDetector


def _build_store() -> LogStore:
    store = LogStore()
    base = datetime.now(timezone.utc)

    for i in range(80):
        store._add_connection(
            Connection(
                uid=f"base-{i}",
                src_ip=f"203.0.113.{(i % 8) + 1}",
                src_port=50000 + i,
                dst_ip=f"198.51.100.{(i % 12) + 1}",
                dst_port=443,
                proto="tcp",
                service="https",
                duration=1.2,
                bytes_sent=1500,
                bytes_recv=2500,
                timestamp=base + timedelta(minutes=i),
                tags=[],
                source="zeek",
            )
        )

    for i in range(40):
        store._add_dns_query(
            DnsQuery(
                timestamp=base + timedelta(minutes=i),
                src_ip=f"203.0.113.{(i % 6) + 1}",
                src_port=53000 + i,
                dst_ip="8.8.8.8",
                dst_port=53,
                query=f"normal{i}.example.com",
                qtype="A",
                rcode="NOERROR",
                answers=["203.0.113.5"],
                source="zeek",
            )
        )

    return store


def test_detect_returns_expected_shape():
    store = _build_store()
    profiler = BaselineProfiler(store)
    profiler.build_baseline()

    # Add anomalies after baseline
    spike_time = datetime.now(timezone.utc)
    for i in range(15):
        store._add_connection(
            Connection(
                uid=f"anom-{i}",
                src_ip="203.0.113.250",
                src_port=61000 + i,
                dst_ip="203.0.113.99",
                dst_port=5555,
                proto="udp",
                service="unknown",
                duration=95.0,
                bytes_sent=900000,
                bytes_recv=50,
                timestamp=spike_time + timedelta(seconds=i),
                tags=[],
                source="zeek",
            )
        )
        store._add_dns_query(
            DnsQuery(
                timestamp=spike_time + timedelta(seconds=i),
                src_ip="203.0.113.250",
                src_port=54000 + i,
                dst_ip="8.8.8.8",
                dst_port=53,
                query=f"x{i}q9w8e7r6t5y4u3i2o1p0.bad-domain.test",
                qtype="TXT",
                rcode="NOERROR",
                answers=[],
                source="zeek",
            )
        )

    detector = AnomalyDetector(store, profiler)
    result = detector.detect()

    assert "total" in result
    assert "by_type" in result
    assert "by_severity" in result
    assert isinstance(result["anomalies"], list)
    assert result["total"] == len(result["anomalies"])


def test_get_anomaly_round_trip():
    store = _build_store()
    profiler = BaselineProfiler(store)
    profiler.build_baseline()

    detector = AnomalyDetector(store, profiler)
    result = detector.detect()

    if result["anomalies"]:
        anomaly_id = result["anomalies"][0]["id"]
        found = detector.get_anomaly(anomaly_id)
        assert found is not None
        assert found["id"] == anomaly_id
