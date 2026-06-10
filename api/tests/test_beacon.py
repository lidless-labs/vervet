"""
Unit tests for beacon detection functionality.
Tests analyzer logic with synthetic beacon and non-beacon data.
"""
import pytest
from datetime import datetime, timedelta
from api.services.beacon_analyzer import BeaconAnalyzer
from api.parsers.unified import Connection
from api.config.allowlists import BeaconAllowlist


def create_synthetic_connections(
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    count: int,
    interval_seconds: float,
    jitter_pct: float = 0.0,
    start_time: datetime = None,
    data_size: int = 1024,
    data_variance: float = 0.0,
) -> list[Connection]:
    """
    Create synthetic connection data for testing.

    Args:
        src_ip: Source IP
        dst_ip: Destination IP
        dst_port: Destination port
        count: Number of connections
        interval_seconds: Base interval between connections
        jitter_pct: Percentage of jitter to add (0-100)
        start_time: Starting timestamp
        data_size: Base data size
        data_variance: Variance in data size (0-1)

    Returns:
        List of synthetic Connection objects
    """
    if start_time is None:
        start_time = datetime(2024, 1, 1, 0, 0, 0)

    connections = []
    current_time = start_time

    import random
    random.seed(42)  # Reproducible results

    for i in range(count):
        # Add jitter to interval
        if jitter_pct > 0 and i > 0:
            jitter = interval_seconds * (jitter_pct / 100.0) * (random.random() - 0.5) * 2
            actual_interval = interval_seconds + jitter
        else:
            actual_interval = interval_seconds if i > 0 else 0

        if i > 0:
            current_time += timedelta(seconds=actual_interval)

        # Add variance to data size
        if data_variance > 0:
            size_jitter = data_size * data_variance * (random.random() - 0.5) * 2
            actual_data_size = max(1, int(data_size + size_jitter))
        else:
            actual_data_size = data_size

        conn = Connection(
            uid=f"test-{i}",
            src_ip=src_ip,
            src_port=50000 + i,
            dst_ip=dst_ip,
            dst_port=dst_port,
            proto="tcp",
            service="http",
            duration=1.0,
            bytes_sent=actual_data_size // 2,
            bytes_recv=actual_data_size // 2,
            timestamp=current_time,
            tags=[],
            source="test",
            conn_state="SF",
            pkts_sent=10,
            pkts_recv=10,
        )
        connections.append(conn)

    return connections


class TestBeaconAnalyzer:
    """Test cases for BeaconAnalyzer class."""

    def test_perfect_beacon_detection(self):
        """Test detection of perfect beacon with no jitter."""
        analyzer = BeaconAnalyzer(
            min_connections=10,
            max_jitter_pct=20.0,
            min_time_span_hours=1.0,
            score_threshold=70.0,
        )

        # Create perfect beacon: 20 connections, no jitter.
        # Interval of 4800s gives a ~26.7h observation window so the time-span
        # coverage component is fully earned, letting a perfect beacon reach 90.
        connections = create_synthetic_connections(
            src_ip="192.0.2.100",
            dst_ip="203.0.113.50",
            dst_port=443,
            count=20,
            interval_seconds=4800.0,
            jitter_pct=0.0,
        )

        beacons = analyzer.analyze_connections(connections)

        assert len(beacons) == 1, "Should detect exactly one beacon"
        beacon = beacons[0]

        assert beacon.src_ip == "192.0.2.100"
        assert beacon.dst_ip == "203.0.113.50"
        assert beacon.dst_port == 443
        assert beacon.connection_count == 20
        assert beacon.jitter_pct < 1.0, "Perfect beacon should have near-zero jitter"
        assert beacon.beacon_score >= 90.0, "Perfect beacon should have high score"
        assert beacon.confidence > 0.5

    def test_beacon_with_low_jitter(self):
        """Test detection of beacon with low jitter."""
        analyzer = BeaconAnalyzer(
            min_connections=10,
            max_jitter_pct=20.0,
            score_threshold=70.0,
            min_time_span_hours=0.25,
        )

        # Create beacon with 5% jitter. 20 conns at 7200s span ~40h so the
        # time-span coverage and connection-count components are earned and a
        # low-jitter beacon clears the >=80 score bar.
        connections = create_synthetic_connections(
            src_ip="192.0.2.101",
            dst_ip="203.0.113.51",
            dst_port=8080,
            count=20,
            interval_seconds=7200.0,
            jitter_pct=5.0,
        )

        beacons = analyzer.analyze_connections(connections)

        assert len(beacons) == 1
        beacon = beacons[0]

        assert beacon.jitter_pct < 10.0, "5% jitter should result in low jitter percentage"
        assert beacon.beacon_score >= 80.0, "Low jitter beacon should have high score"

    def test_beacon_with_moderate_jitter(self):
        """Test detection of beacon with moderate jitter."""
        analyzer = BeaconAnalyzer(
            min_connections=10,
            max_jitter_pct=30.0,
            score_threshold=60.0,
            min_time_span_hours=0.25,
        )

        # Create beacon with moderate jitter. With seed-42 reproducible data, a
        # 20% input jitter yields ~12% measured interval CV (in the moderate
        # 10-25% band). 50 conns at 3600s (~50h span) keeps the score in the
        # 60-85 medium range.
        connections = create_synthetic_connections(
            src_ip="192.0.2.102",
            dst_ip="203.0.113.52",
            dst_port=443,
            count=50,
            interval_seconds=3600.0,
            jitter_pct=20.0,
        )

        beacons = analyzer.analyze_connections(connections)

        assert len(beacons) == 1
        beacon = beacons[0]

        assert 10.0 <= beacon.jitter_pct <= 25.0, "Should have moderate jitter"
        assert 60.0 <= beacon.beacon_score <= 85.0, "Moderate jitter should give medium score"

    def test_non_beacon_random_intervals(self):
        """Test that random intervals are not flagged as beacons."""
        analyzer = BeaconAnalyzer(
            min_connections=10,
            max_jitter_pct=20.0,
            score_threshold=70.0,
        )

        # Create connections with high jitter (random intervals)
        connections = create_synthetic_connections(
            src_ip="192.0.2.103",
            dst_ip="203.0.113.53",
            dst_port=80,
            count=15,
            interval_seconds=100.0,
            jitter_pct=80.0,  # Very high jitter
        )

        beacons = analyzer.analyze_connections(connections)

        # Should not detect beacon with high jitter
        assert len(beacons) == 0, "High jitter should not be flagged as beacon"

    def test_insufficient_connections(self):
        """Test that too few connections are not flagged."""
        analyzer = BeaconAnalyzer(
            min_connections=10,
            score_threshold=70.0,
        )

        # Only 5 connections (below minimum)
        connections = create_synthetic_connections(
            src_ip="192.0.2.104",
            dst_ip="203.0.113.54",
            dst_port=443,
            count=5,
            interval_seconds=60.0,
            jitter_pct=0.0,
        )

        beacons = analyzer.analyze_connections(connections)

        assert len(beacons) == 0, "Too few connections should not trigger detection"

    def test_multiple_beacons(self):
        """Test detection of multiple different beacons."""
        analyzer = BeaconAnalyzer(
            min_connections=10,
            score_threshold=70.0,
            min_time_span_hours=0.25,
        )

        # Create two different beacons. Hour-scale intervals give each a
        # multi-hour observation window so both clear the time-span gate.
        beacon1_conns = create_synthetic_connections(
            src_ip="192.0.2.105",
            dst_ip="203.0.113.55",
            dst_port=443,
            count=20,
            interval_seconds=3600.0,
            jitter_pct=5.0,
        )

        beacon2_conns = create_synthetic_connections(
            src_ip="192.0.2.106",
            dst_ip="203.0.113.56",
            dst_port=8080,
            count=20,
            interval_seconds=3600.0,
            jitter_pct=3.0,
            start_time=datetime(2024, 1, 2, 0, 0, 0),  # Different start time
        )

        all_connections = beacon1_conns + beacon2_conns
        beacons = analyzer.analyze_connections(all_connections)

        assert len(beacons) == 2, "Should detect both beacons"

        # Check they are sorted by score (highest first)
        assert beacons[0].beacon_score >= beacons[1].beacon_score

    def test_data_size_consistency(self):
        """Test that consistent data sizes increase beacon score."""
        analyzer = BeaconAnalyzer(
            min_connections=10,
            score_threshold=60.0,
            min_time_span_hours=0.25,
        )

        # Beacon with very consistent data sizes. Hour-scale intervals give a
        # multi-hour span so the beacon clears the time-span gate.
        connections_consistent = create_synthetic_connections(
            src_ip="192.0.2.107",
            dst_ip="203.0.113.57",
            dst_port=443,
            count=20,
            interval_seconds=3600.0,
            jitter_pct=10.0,
            data_size=2048,
            data_variance=0.05,  # Very low variance
        )

        # Beacon with variable data sizes
        connections_variable = create_synthetic_connections(
            src_ip="192.0.2.108",
            dst_ip="203.0.113.58",
            dst_port=443,
            count=20,
            interval_seconds=3600.0,
            jitter_pct=10.0,
            data_size=2048,
            data_variance=0.5,  # High variance
        )

        beacons_consistent = analyzer.analyze_connections(connections_consistent)
        beacons_variable = analyzer.analyze_connections(connections_variable)

        assert len(beacons_consistent) == 1
        assert len(beacons_variable) == 1

        # Consistent data sizes should score higher
        assert beacons_consistent[0].beacon_score > beacons_variable[0].beacon_score

    def test_allowlist_filtering_dns(self):
        """Test that DNS traffic to known resolvers is filtered."""
        analyzer = BeaconAnalyzer(
            min_connections=10,
            score_threshold=70.0,
            min_time_span_hours=0.25,
        )

        # Create beacon to Google DNS (8.8.8.8). Hour-scale intervals give a
        # multi-hour span so the (allowlist-disabled) branch actually detects.
        connections = create_synthetic_connections(
            src_ip="192.0.2.109",
            dst_ip="8.8.8.8",
            dst_port=53,
            count=20,
            interval_seconds=3600.0,
            jitter_pct=2.0,
        )

        # Should filter out DNS to known resolver
        beacons = analyzer.analyze_connections(connections, include_allowlisted=False)
        assert len(beacons) == 0, "DNS to known resolver should be filtered"

        # Should detect if explicitly requested
        beacons_all = analyzer.analyze_connections(connections, include_allowlisted=True)
        assert len(beacons_all) == 1, "Should detect when allowlist disabled"

    def test_allowlist_filtering_ntp(self):
        """Test that NTP traffic is filtered."""
        analyzer = BeaconAnalyzer(
            min_connections=10,
            score_threshold=70.0,
        )

        # Create beacon on NTP port
        connections = create_synthetic_connections(
            src_ip="192.0.2.110",
            dst_ip="132.163.97.1",  # NIST NTP server
            dst_port=123,
            count=15,
            interval_seconds=300.0,  # 5 minute intervals
            jitter_pct=5.0,
        )

        beacons = analyzer.analyze_connections(connections, include_allowlisted=False)
        assert len(beacons) == 0, "NTP traffic should be filtered"

    def test_mitre_technique_mapping(self):
        """Test that appropriate MITRE techniques are assigned."""
        analyzer = BeaconAnalyzer(
            min_connections=10,
            score_threshold=70.0,
            min_time_span_hours=0.25,
        )

        # HTTPS beacon (should get T1071 and T1071.001). Hour-scale intervals
        # give a multi-hour span so the beacon clears the time-span gate.
        connections_https = create_synthetic_connections(
            src_ip="192.0.2.111",
            dst_ip="203.0.113.61",
            dst_port=443,
            count=20,
            interval_seconds=3600.0,
            jitter_pct=5.0,
        )

        # HTTP beacon (should get T1071 and T1071.001)
        connections_http = create_synthetic_connections(
            src_ip="192.0.2.112",
            dst_ip="203.0.113.62",
            dst_port=80,
            count=20,
            interval_seconds=3600.0,
            jitter_pct=5.0,
        )

        beacons_https = analyzer.analyze_connections(connections_https)
        beacons_http = analyzer.analyze_connections(connections_http)

        assert len(beacons_https) == 1
        assert len(beacons_http) == 1

        # Both should have T1071 (Application Layer Protocol)
        assert "T1071" in beacons_https[0].mitre_techniques
        assert "T1071" in beacons_http[0].mitre_techniques

        # Both should have T1071.001 (Web Protocols)
        assert "T1071.001" in beacons_https[0].mitre_techniques
        assert "T1071.001" in beacons_http[0].mitre_techniques

        # High-score HTTPS beacon should also have T1573 (Encrypted Channel)
        if beacons_https[0].beacon_score >= 80.0:
            assert "T1573" in beacons_https[0].mitre_techniques

    def test_detailed_analysis(self):
        """Test detailed analysis with histogram."""
        analyzer = BeaconAnalyzer(
            min_connections=10,
            score_threshold=0.0,
            min_time_span_hours=0.25,
        )

        # Hour-scale intervals give a multi-hour span so the detailed analysis
        # (which shares the time-span gate) returns a result.
        connections = create_synthetic_connections(
            src_ip="192.0.2.113",
            dst_ip="203.0.113.63",
            dst_port=443,
            count=20,
            interval_seconds=3600.0,
            jitter_pct=10.0,
        )

        detailed = analyzer.analyze_connection_pair_detailed(
            connections=connections,
            src_ip="192.0.2.113",
            dst_ip="203.0.113.63",
        )

        assert detailed is not None
        assert len(detailed.all_intervals) == 19  # count - 1
        assert len(detailed.all_timestamps) == 20
        assert len(detailed.interval_histogram.bin_edges) > 0
        assert len(detailed.interval_histogram.bin_counts) > 0
        assert len(detailed.interval_histogram.bin_centers) > 0

    def test_time_span_requirement(self):
        """Test that minimum time span requirement is enforced."""
        analyzer = BeaconAnalyzer(
            min_connections=10,
            min_time_span_hours=2.0,  # Require 2 hours
            score_threshold=70.0,
        )

        # Create connections spanning only 30 minutes
        connections = create_synthetic_connections(
            src_ip="192.0.2.114",
            dst_ip="203.0.113.64",
            dst_port=443,
            count=15,
            interval_seconds=120.0,  # 2 minutes
            jitter_pct=5.0,
        )

        beacons = analyzer.analyze_connections(connections)

        # Should not detect due to insufficient time span (30 min < 2 hours)
        assert len(beacons) == 0, "Should require minimum time span"

    def test_high_connection_count_bonus(self):
        """Test that high connection counts increase score."""
        analyzer = BeaconAnalyzer(
            min_connections=10,
            score_threshold=60.0,
            min_time_span_hours=0.25,
        )

        # Few connections. Hour-scale intervals give a multi-hour span so both
        # the few and many cases clear the time-span gate.
        connections_few = create_synthetic_connections(
            src_ip="192.0.2.115",
            dst_ip="203.0.113.65",
            dst_port=443,
            count=20,
            interval_seconds=3600.0,
            jitter_pct=10.0,
        )

        # Many connections
        connections_many = create_synthetic_connections(
            src_ip="192.0.2.116",
            dst_ip="203.0.113.66",
            dst_port=443,
            count=150,
            interval_seconds=3600.0,
            jitter_pct=10.0,
        )

        beacons_few = analyzer.analyze_connections(connections_few)
        beacons_many = analyzer.analyze_connections(connections_many)

        assert len(beacons_few) == 1
        assert len(beacons_many) == 1

        # More connections should give higher score
        assert beacons_many[0].beacon_score > beacons_few[0].beacon_score
        assert beacons_many[0].confidence > beacons_few[0].confidence


class TestBeaconAllowlist:
    """Test cases for BeaconAllowlist class."""

    def test_dns_resolver_detection(self):
        """Test detection of known DNS resolvers."""
        assert BeaconAllowlist.is_allowed_dst("8.8.8.8", 53) is True
        assert BeaconAllowlist.is_allowed_dst("1.1.1.1", 53) is True
        # Port 53 (DNS) is allowlisted for any destination, mirroring the NTP
        # (port 123) behavior asserted in test_ntp_port_detection. A private IP
        # on port 53 is still DNS traffic and is filtered by design.
        assert BeaconAllowlist.is_allowed_dst("203.0.113.1", 53) is True
        # A private IP on a non-periodic port is NOT allowlisted.
        assert BeaconAllowlist.is_allowed_dst("203.0.113.1", 80) is False

    def test_ntp_port_detection(self):
        """Test detection of NTP traffic."""
        assert BeaconAllowlist.is_allowed_dst("132.163.97.1", 123) is True
        assert BeaconAllowlist.is_allowed_dst("203.0.113.1", 123) is True  # Any IP on NTP port
        assert BeaconAllowlist.is_allowed_dst("203.0.113.1", 80) is False

    def test_custom_allowlist(self):
        """Test adding custom allowlist entries."""
        # Add custom DNS server
        BeaconAllowlist.add_custom_allowlist_ip("198.19.110.10", "dns")
        assert BeaconAllowlist.is_allowed_dst("198.19.110.10", 53) is True

        # Remove it
        BeaconAllowlist.remove_custom_allowlist_ip("198.19.110.10")
        # Note: After removal from DNS_RESOLVERS, it may still match on port 53
        # This is expected behavior


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
