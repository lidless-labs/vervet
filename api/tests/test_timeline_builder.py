"""Tests for timeline builder service."""

from types import SimpleNamespace
from datetime import datetime, timedelta, timezone

from api.parsers.unified import Connection, DnsQuery, Alert
from api.services.log_store import LogStore
from api.services.timeline_builder import build_timeline


class MockThreatEngine:
    def __init__(self, profiles):
        self._profiles = profiles

    def analyze_all(self):
        return self._profiles


class ThreatLevelObj:
    def __init__(self, value: str):
        self.value = value


def _build_store() -> LogStore:
    now = datetime.now(timezone.utc)
    store = LogStore()
    store._add_connection(
        Connection(
            uid="c1",
            src_ip="203.0.113.5",
            src_port=51515,
            dst_ip="45.33.32.156",
            dst_port=443,
            proto="tcp",
            service="tls",
            duration=12.0,
            bytes_sent=2400000,
            bytes_recv=1200,
            timestamp=now,
            tags=[],
            source="zeek",
        )
    )
    store._add_connection(
        Connection(
            uid="c2",
            src_ip="203.0.113.5",
            src_port=51516,
            dst_ip="45.33.32.156",
            dst_port=443,
            proto="tcp",
            service="tls",
            duration=10.0,
            bytes_sent=128000,
            bytes_recv=900,
            timestamp=now + timedelta(seconds=3),
            tags=[],
            source="zeek",
        )
    )
    store._add_dns_query(
        DnsQuery(
            timestamp=now + timedelta(seconds=1),
            src_ip="203.0.113.5",
            src_port=53000,
            dst_ip="8.8.8.8",
            dst_port=53,
            query="bad.example",
            qtype="A",
            rcode="NOERROR",
            answers=["1.2.3.4"],
            source="zeek",
        )
    )
    store._add_alert(
        Alert(
            timestamp=now + timedelta(seconds=2),
            src_ip="203.0.113.5",
            src_port=51515,
            dst_ip="45.33.32.156",
            dst_port=443,
            proto="TCP",
            signature="ET MALWARE C2 Checkin",
            signature_id=999999,
            category="Trojan Activity",
            severity=1,
            action="allowed",
        )
    )
    return store


def _mock_profiles(now: datetime):
    beacon = SimpleNamespace(src_ip="203.0.113.5", dst_ip="45.33.32.156", dst_port=443)
    dns_threat_data = SimpleNamespace(domain="bad.example")

    profile = SimpleNamespace(
        ip="203.0.113.5",
        beacons=[beacon],
        dns_threats=[{"type": "dga", "data": dns_threat_data}],
        first_seen=now.timestamp(),
        threat_level=ThreatLevelObj("high"),
        score=0.91,
        confidence=0.87,
        all_reasons=["Beaconing and suspicious DNS"],
        mitre_techniques={"T1071", "T1071.004"},
    )
    return {"203.0.113.5": profile}


def test_build_timeline_generates_human_readable_events():
    store = _build_store()
    now = store.connections[0].timestamp
    engine = MockThreatEngine(_mock_profiles(now))

    events, total = build_timeline(store, engine, {"limit": 100, "offset": 0})

    assert len(events) > 0
    assert total >= len(events)
    summaries = [e.summary for e in events]
    assert any("203.0.113.5" in s and "45.33.32.156" in s for s in summaries)
    assert any(e.type == "threat" for e in events)


def test_build_timeline_clusters_rapid_events():
    store = _build_store()
    now = store.connections[0].timestamp
    engine = MockThreatEngine(_mock_profiles(now))

    events, _ = build_timeline(store, engine, {"limit": 100, "offset": 0, "src_ip": "203.0.113.5", "dst_ip": "45.33.32.156"})

    assert any(e.type == "cluster" for e in events)


def test_build_timeline_applies_severity_filter():
    store = _build_store()
    now = store.connections[0].timestamp
    engine = MockThreatEngine(_mock_profiles(now))

    events, total = build_timeline(store, engine, {"limit": 100, "offset": 0, "severity_min": "high"})

    assert len(events) > 0
    assert total == len(events)  # no pagination offset, so total == len
    assert all(e.severity in {"high", "critical"} for e in events)
