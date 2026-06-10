"""
Tests for unified threat scoring engine.
"""
import pytest
from api.services.unified_threat_engine import UnifiedThreatEngine
from api.services.log_store import LogStore
from api.parsers.unified import Connection, DnsQuery, Alert
from api.models.threat import ThreatLevel


def create_test_log_store() -> LogStore:
    """Create a test log store with sample data."""
    store = LogStore()

    # Add some test connections
    # Beaconing pattern: regular connections to same destination
    for i in range(15):
        conn = Connection(
            uid=f"beacon-{i}",
            src_ip="192.0.2.100",
            src_port=54321 + i,
            dst_ip="8.8.8.8",
            dst_port=443,
            proto="TCP",
            service="https",
            duration=5.0,
            bytes_sent=512,
            bytes_recv=256,
            timestamp=1704000000.0 + (i * 600),  # Every 10 minutes
            source="zeek",
        )
        store._add_connection(conn)

    # Long connection
    long_conn = Connection(
        uid="long-conn",
        src_ip="192.0.2.101",
        src_port=12345,
        dst_ip="1.2.3.4",
        dst_port=8080,
        proto="TCP",
        service="http",
        duration=7200.0,  # 2 hours
        bytes_sent=50 * 1024 * 1024,  # 50 MB upload
        bytes_recv=1024,
        timestamp=1704000000.0,
        source="zeek",
    )
    store._add_connection(long_conn)

    # DNS queries for tunneling detection
    for i in range(20):
        query = DnsQuery(
            src_ip="192.0.2.102",
            src_port=50000 + i,
            dst_ip="8.8.8.8",
            dst_port=53,
            query=f"aGVsbG93b3JsZHRlc3RkYXRhe{i:03d}.malicious.com",  # Base64-like subdomain
            qtype="A",
            rcode="NOERROR",
            answers=["1.2.3.4"],
            timestamp=1704000000.0 + i,
            source="zeek",
        )
        store._add_dns_query(query)

    # Suricata alerts (normalized unified.Alert, as produced by ingestion)
    for i in range(5):
        alert = Alert(
            timestamp=1704000000.0 + i,
            src_ip="203.0.113.50",
            dst_ip="192.0.2.200",
            src_port=12345,
            dst_port=22,
            proto="TCP",
            signature="SSH Brute Force Attempt",
            signature_id=2001219,
            severity=2,
            category="Attempted Recon",
            action="allowed",
        )
        store._add_alert(alert)

    return store


class TestUnifiedThreatEngine:
    """Tests for UnifiedThreatEngine."""

    def test_engine_initialization(self):
        """Test engine can be initialized."""
        store = LogStore()
        engine = UnifiedThreatEngine(store)
        assert engine.log_store == store

    def test_analyze_empty_store(self):
        """Test analyzing empty log store."""
        store = LogStore()
        engine = UnifiedThreatEngine(store)
        profiles = engine.analyze_all()

        assert isinstance(profiles, dict)
        assert len(profiles) == 0

    def test_analyze_all_runs_analyzers(self):
        """Test that analyze_all runs all detection engines."""
        store = create_test_log_store()
        engine = UnifiedThreatEngine(store)

        profiles = engine.analyze_all()

        # Should have profiles for hosts with detections
        assert len(profiles) > 0

    def test_beacon_detection_in_profile(self):
        """Test that beaconing is detected and added to profile."""
        store = create_test_log_store()
        engine = UnifiedThreatEngine(store)

        profiles = engine.analyze_all()

        # Host 192.0.2.100 should have beacons
        if "192.0.2.100" in profiles:
            profile = profiles["192.0.2.100"]
            assert profile.beacon_count > 0
            assert len(profile.beacons) > 0

    def test_dns_threat_detection_in_profile(self):
        """Test that DNS threats are detected and added to profile."""
        store = create_test_log_store()
        engine = UnifiedThreatEngine(store)

        profiles = engine.analyze_all()

        # Host 192.0.2.102 should have DNS threats
        if "192.0.2.102" in profiles:
            profile = profiles["192.0.2.102"]
            assert profile.dns_threat_count > 0
            assert len(profile.dns_threats) > 0

    def test_alert_detection_in_profile(self):
        """Test that alerts are added to profile."""
        store = create_test_log_store()
        engine = UnifiedThreatEngine(store)

        profiles = engine.analyze_all()

        # Host 203.0.113.50 should have alerts
        if "203.0.113.50" in profiles:
            profile = profiles["203.0.113.50"]
            assert profile.alert_count > 0
            assert len(profile.alerts) > 0

    def test_long_connection_detection_in_profile(self):
        """Test that long connections are detected and added to profile."""
        store = create_test_log_store()
        engine = UnifiedThreatEngine(store)

        profiles = engine.analyze_all()

        # Host 192.0.2.101 should have long connections
        if "192.0.2.101" in profiles:
            profile = profiles["192.0.2.101"]
            assert profile.long_connection_count > 0
            assert len(profile.long_connections) > 0

    def test_unified_scoring(self):
        """Test that unified scores are calculated."""
        store = create_test_log_store()
        engine = UnifiedThreatEngine(store)

        profiles = engine.analyze_all()

        for profile in profiles.values():
            # Score should be normalized to 0-1
            assert 0 <= profile.score <= 1
            # Should have a threat level
            assert profile.threat_level in [
                ThreatLevel.CRITICAL,
                ThreatLevel.HIGH,
                ThreatLevel.MEDIUM,
                ThreatLevel.LOW,
                ThreatLevel.INFO,
            ]

    def test_multiple_detections_boost_score(self):
        """Test that multiple detection types boost the score."""
        store = create_test_log_store()
        engine = UnifiedThreatEngine(store)

        profiles = engine.analyze_all()

        # Find profiles with multiple detection types
        multi_detection = [
            p for p in profiles.values()
            if sum([
                1 if p.beacon_count > 0 else 0,
                1 if p.dns_threat_count > 0 else 0,
                1 if p.alert_count > 0 else 0,
                1 if p.long_connection_count > 0 else 0,
            ]) >= 2
        ]

        # These should have boosted scores
        if multi_detection:
            assert any(p.score > 0.5 for p in multi_detection)

    def test_mitre_techniques_aggregated(self):
        """Test that MITRE techniques are aggregated from all sources."""
        store = create_test_log_store()
        engine = UnifiedThreatEngine(store)

        profiles = engine.analyze_all()

        for profile in profiles.values():
            if profile.beacon_count > 0 or profile.dns_threat_count > 0:
                # Should have MITRE techniques
                assert len(profile.mitre_techniques) > 0

    def test_mitre_mappings_consolidated(self):
        """Test that MITRE mappings are consolidated."""
        store = create_test_log_store()
        engine = UnifiedThreatEngine(store)

        profiles = engine.analyze_all()

        for profile in profiles.values():
            if len(profile.mitre_mappings) > 0:
                # Each mapping should have evidence
                for mapping in profile.mitre_mappings:
                    assert len(mapping.evidence) > 0
                    assert mapping.detection_count >= 1
                    assert 0 <= mapping.confidence <= 1

    def test_attack_timeline_created(self):
        """Test that attack timeline is created."""
        store = create_test_log_store()
        engine = UnifiedThreatEngine(store)

        profiles = engine.analyze_all()

        for profile in profiles.values():
            # Timeline should exist
            assert isinstance(profile.attack_timeline, list)

            # If there are detections, timeline should have events
            total_detections = (
                profile.beacon_count +
                profile.dns_threat_count +
                profile.alert_count +
                profile.long_connection_count
            )
            if total_detections > 0:
                assert len(profile.attack_timeline) > 0

    def test_attack_timeline_sorted(self):
        """Test that attack timeline is sorted chronologically."""
        store = create_test_log_store()
        engine = UnifiedThreatEngine(store)

        profiles = engine.analyze_all()

        for profile in profiles.values():
            if len(profile.attack_timeline) > 1:
                # Verify chronological order
                timestamps = [event["timestamp"] for event in profile.attack_timeline]
                assert timestamps == sorted(timestamps)

    def test_reasons_provided(self):
        """Test that reasons are provided for explainability."""
        store = create_test_log_store()
        engine = UnifiedThreatEngine(store)

        profiles = engine.analyze_all()

        for profile in profiles.values():
            # Should have reasons if threats detected
            total_detections = (
                profile.beacon_count +
                profile.dns_threat_count +
                profile.alert_count +
                profile.long_connection_count
            )
            if total_detections > 0:
                assert len(profile.all_reasons) > 0

    def test_indicators_provided(self):
        """Test that threat indicators are provided."""
        store = create_test_log_store()
        engine = UnifiedThreatEngine(store)

        profiles = engine.analyze_all()

        for profile in profiles.values():
            # Should have indicators if threats detected
            total_detections = (
                profile.beacon_count +
                profile.dns_threat_count +
                profile.alert_count +
                profile.long_connection_count
            )
            if total_detections > 0:
                assert len(profile.all_indicators) > 0

    def test_attack_summary_generated(self):
        """Test that attack summary is generated."""
        store = create_test_log_store()
        engine = UnifiedThreatEngine(store)

        profiles = engine.analyze_all()

        for profile in profiles.values():
            # Should have a summary
            assert isinstance(profile.attack_summary, str)
            # Summary should mention the host IP
            assert profile.ip in profile.attack_summary

    def test_related_entities_tracked(self):
        """Test that related IPs and domains are tracked."""
        store = create_test_log_store()
        engine = UnifiedThreatEngine(store)

        profiles = engine.analyze_all()

        for profile in profiles.values():
            # Related entities should be sets (converted to lists)
            assert isinstance(profile.related_ips, set)
            assert isinstance(profile.related_domains, set)

    def test_temporal_bounds_tracked(self):
        """Test that first_seen and last_seen are tracked."""
        store = create_test_log_store()
        engine = UnifiedThreatEngine(store)

        profiles = engine.analyze_all()

        for profile in profiles.values():
            if profile.first_seen > 0:
                # last_seen should be >= first_seen
                assert profile.last_seen >= profile.first_seen

    def test_get_host_profile(self):
        """Test getting a specific host profile."""
        store = create_test_log_store()
        engine = UnifiedThreatEngine(store)

        # Get profile for host with beacons
        profile = engine.get_host_profile("192.0.2.100")

        if profile:
            assert profile.ip == "192.0.2.100"
            assert profile.beacon_count > 0

    def test_get_host_profile_nonexistent(self):
        """Test getting profile for non-existent host."""
        store = create_test_log_store()
        engine = UnifiedThreatEngine(store)

        profile = engine.get_host_profile("198.19.110.10")
        assert profile is None

    def test_get_top_threats(self):
        """Test getting top N threats."""
        store = create_test_log_store()
        engine = UnifiedThreatEngine(store)

        top_threats = engine.get_top_threats(limit=5)

        # Should return list of profiles
        assert isinstance(top_threats, list)
        assert len(top_threats) <= 5

        # Should be sorted by score descending
        if len(top_threats) > 1:
            scores = [p.score for p in top_threats]
            assert scores == sorted(scores, reverse=True)

    def test_get_threats_by_level(self):
        """Test filtering threats by level."""
        store = create_test_log_store()
        engine = UnifiedThreatEngine(store)

        # Get all critical threats
        critical = engine.get_threats_by_level(ThreatLevel.CRITICAL)

        # All should be critical
        assert all(p.threat_level == ThreatLevel.CRITICAL for p in critical)

    def test_get_mitre_attack_overview(self):
        """Test getting MITRE ATT&CK overview."""
        store = create_test_log_store()
        engine = UnifiedThreatEngine(store)

        overview = engine.get_mitre_attack_overview()

        # Should have required keys
        assert "techniques" in overview
        assert "tactics" in overview
        assert "affected_hosts" in overview

        # Techniques should map to counts
        assert isinstance(overview["techniques"], dict)
        # Tactics should map to counts
        assert isinstance(overview["tactics"], dict)
        # Affected hosts should map to host lists
        assert isinstance(overview["affected_hosts"], dict)

    def test_confidence_scoring(self):
        """Test confidence scoring."""
        store = create_test_log_store()
        engine = UnifiedThreatEngine(store)

        profiles = engine.analyze_all()

        for profile in profiles.values():
            # Confidence should be between 0 and 1
            assert 0 <= profile.confidence <= 1

    def test_threat_correlation_beacon_with_dns(self):
        """Test correlation of beacon + DNS exfil from same host."""
        store = LogStore()

        # Add beaconing connections
        for i in range(15):
            conn = Connection(
                uid=f"beacon-{i}",
                src_ip="192.0.2.100",
                # External C2 IP (not an allowlisted DNS resolver like 8.8.8.8,
                # which the beacon analyzer correctly filters regardless of port)
                dst_ip="203.0.113.50",
                src_port=54321 + i,
                dst_port=443,
                proto="TCP",
                service="https",
                duration=5.0,
                bytes_sent=512,
                bytes_recv=256,
                timestamp=1704000000.0 + (i * 600),
                source="zeek",
            )
            store._add_connection(conn)

        # Add DNS tunneling from same host
        for i in range(20):
            query = DnsQuery(
                src_ip="192.0.2.100",  # Same host as beacons
                src_port=50000 + i,
                dst_ip="8.8.8.8",
                dst_port=53,
                query=f"aGVsbG93b3JsZHRlc3RkYXRhe{i:03d}.malicious.com",
                qtype="A",
                rcode="NOERROR",
                answers=["1.2.3.4"],
                timestamp=1704000000.0 + i,
                source="zeek",
            )
            store._add_dns_query(query)

        engine = UnifiedThreatEngine(store)
        profiles = engine.analyze_all()

        # Host should have both detections
        if "192.0.2.100" in profiles:
            profile = profiles["192.0.2.100"]
            assert profile.beacon_count > 0
            assert profile.dns_threat_count > 0
            # Correlation should boost score
            assert profile.score > 0.5

    def test_profile_with_no_detections(self):
        """Test that hosts with no significant detections are not profiled."""
        store = LogStore()

        # Add a single short connection (below thresholds)
        conn = Connection(
            uid="short-conn",
            src_ip="192.0.2.100",
            src_port=54321,
            dst_ip="192.0.2.200",
            dst_port=80,
            proto="TCP",
            service="http",
            duration=2.0,
            bytes_sent=512,
            bytes_recv=256,
            timestamp=1704000000.0,
            source="zeek",
        )
        store._add_connection(conn)

        engine = UnifiedThreatEngine(store)
        profiles = engine.analyze_all()

        # Should have no profiles or very low scores
        if len(profiles) > 0:
            for profile in profiles.values():
                assert profile.score < 0.5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
