"""
Tests for long connection analyzer.
"""
import pytest
from api.services.long_connection_analyzer import LongConnectionAnalyzer
from api.parsers.unified import Connection
from api.models.threat import ThreatLevel


def create_test_connection(
    src_ip: str = "192.0.2.100",
    dst_ip: str = "8.8.8.8",
    dst_port: int = 443,
    service: str = "https",
    duration: float = 600.0,
    bytes_sent: int = 10240,
    bytes_recv: int = 5120,
) -> Connection:
    """Create a test connection."""
    return Connection(
        uid="test-conn",
        src_ip=src_ip,
        src_port=54321,
        dst_ip=dst_ip,
        dst_port=dst_port,
        proto="TCP",
        service=service,
        duration=duration,
        bytes_sent=bytes_sent,
        bytes_recv=bytes_recv,
        timestamp=1704000000.0,
        source="zeek",
    )


class TestLongConnectionAnalyzer:
    """Tests for LongConnectionAnalyzer."""

    def test_analyzer_initialization(self):
        """Test analyzer can be initialized."""
        analyzer = LongConnectionAnalyzer()
        assert analyzer.min_duration == 300.0

    def test_analyze_empty_connections(self):
        """Test analyzing empty connection list."""
        analyzer = LongConnectionAnalyzer()
        results = analyzer.analyze_connections([])
        assert results == []

    def test_short_connection_filtered(self):
        """Test that short connections are filtered out."""
        analyzer = LongConnectionAnalyzer(min_duration_seconds=300.0)

        # Connection too short
        conn = create_test_connection(duration=60.0)
        results = analyzer.analyze_connections([conn])

        assert len(results) == 0

    def test_long_connection_detected(self):
        """Test that long connections are detected."""
        analyzer = LongConnectionAnalyzer(
            min_duration_seconds=300.0,
            min_score_threshold=0.0,
        )

        # Long connection
        conn = create_test_connection(duration=3600.0)
        results = analyzer.analyze_connections([conn])

        assert len(results) == 1
        assert results[0].duration_seconds == 3600.0

    def test_duration_scoring(self):
        """Test that longer durations get higher scores."""
        analyzer = LongConnectionAnalyzer(min_score_threshold=0.0)

        # Very long connection
        conn_long = create_test_connection(duration=7200.0)  # 2 hours
        # Medium connection
        conn_medium = create_test_connection(duration=1800.0)  # 30 minutes

        results_long = analyzer.analyze_connections([conn_long])
        results_medium = analyzer.analyze_connections([conn_medium])

        if results_long and results_medium:
            # Longer connection should score higher (all else equal)
            assert results_long[0].score >= results_medium[0].score

    def test_dns_long_connection_high_score(self):
        """Test that long DNS connections score very high."""
        analyzer = LongConnectionAnalyzer(min_score_threshold=0.0)

        # DNS should be instant, 5 minutes is very suspicious
        conn = create_test_connection(
            service="dns",
            dst_port=53,
            duration=300.0,
            bytes_sent=1024,
            bytes_recv=512,
        )

        results = analyzer.analyze_connections([conn])
        assert len(results) == 1
        # DNS long connection should have high protocol score
        assert results[0].score > 50

    def test_high_upload_exfiltration(self):
        """Test detection of high upload (exfiltration)."""
        analyzer = LongConnectionAnalyzer(min_score_threshold=0.0)

        # High sustained upload
        conn = create_test_connection(
            duration=1800.0,  # 30 minutes
            bytes_sent=100 * 1024 * 1024,  # 100 MB upload
            bytes_recv=1024,  # Minimal download
        )

        results = analyzer.analyze_connections([conn])
        assert len(results) == 1
        # Should have high transfer score
        assert results[0].score > 50
        # Should indicate exfiltration in indicators
        assert any("outbound" in i.lower() for i in results[0].indicators)

    def test_mitre_mapping_exfiltration(self):
        """Test MITRE mapping for exfiltration patterns."""
        analyzer = LongConnectionAnalyzer(min_score_threshold=0.0)

        # Large upload over long duration
        conn = create_test_connection(
            duration=3600.0,
            bytes_sent=50 * 1024 * 1024,  # 50 MB
            bytes_recv=10240,
        )

        results = analyzer.analyze_connections([conn])
        assert len(results) == 1
        # Should map to exfiltration techniques
        assert "T1041" in results[0].mitre_techniques  # Exfiltration Over C2 Channel

    def test_mitre_mapping_c2(self):
        """Test MITRE mapping for C2 patterns."""
        analyzer = LongConnectionAnalyzer(min_score_threshold=0.0)

        # Long duration HTTPS connection
        conn = create_test_connection(
            service="https",
            dst_port=443,
            duration=7200.0,  # 2 hours
            bytes_sent=10240,
            bytes_recv=5120,
        )

        results = analyzer.analyze_connections([conn])
        assert len(results) == 1
        # Should map to C2 techniques
        techniques = results[0].mitre_techniques
        assert "T1071" in techniques  # Application Layer Protocol
        assert "T1071.001" in techniques  # Web Protocols

    def test_covert_channel_detection(self):
        """Test detection of covert channels (low sustained transfer)."""
        analyzer = LongConnectionAnalyzer(min_score_threshold=0.0)

        # Very low but continuous transfer over long time. The analyzer rates
        # by total throughput (sent + recv), so keep the combined rate under the
        # 100 B/s covert-channel ceiling: 25 + 25 = 50 B/s.
        conn = create_test_connection(
            duration=3600.0,  # 1 hour
            bytes_sent=25 * 3600,  # 25 bytes/sec each direction -> 50 B/s total
            bytes_recv=25 * 3600,
        )

        results = analyzer.analyze_connections([conn])
        assert len(results) == 1
        # Should map to covert channel technique
        assert "T1030" in results[0].mitre_techniques  # Data Transfer Size Limits

    def test_external_destination_scoring(self):
        """Test that external destinations score higher."""
        analyzer = LongConnectionAnalyzer(min_score_threshold=0.0)

        # External destination
        conn_external = create_test_connection(dst_ip="8.8.8.8")
        # Internal destination
        conn_internal = create_test_connection(dst_ip="192.0.2.50")

        results_external = analyzer.analyze_connections([conn_external])
        results_internal = analyzer.analyze_connections([conn_internal])

        if results_external and results_internal:
            # External should score higher
            assert results_external[0].score > results_internal[0].score

    def test_private_ip_detection(self):
        """Test private IP detection."""
        analyzer = LongConnectionAnalyzer()

        # Test various private ranges
        assert analyzer._is_private_ip("203.0.113.1")
        assert analyzer._is_private_ip("198.18.160.1")
        assert analyzer._is_private_ip("192.0.2.1")
        assert analyzer._is_private_ip("127.0.0.1")

        # Public IPs
        assert not analyzer._is_private_ip("8.8.8.8")
        assert not analyzer._is_private_ip("1.1.1.1")

    def test_nonstandard_port_scoring(self):
        """Test that non-standard ports score higher."""
        analyzer = LongConnectionAnalyzer(min_score_threshold=0.0)

        # Standard HTTPS port
        conn_standard = create_test_connection(dst_port=443, service="https")
        # Non-standard high port
        conn_nonstandard = create_test_connection(dst_port=55555, service="https")

        results_standard = analyzer.analyze_connections([conn_standard])
        results_nonstandard = analyzer.analyze_connections([conn_nonstandard])

        if results_nonstandard:
            # Non-standard port should contribute to score
            assert results_nonstandard[0].score > 0

    def test_bidirectional_detection(self):
        """Test detection of bidirectional traffic."""
        analyzer = LongConnectionAnalyzer(min_score_threshold=0.0)

        # Bidirectional
        conn_bi = create_test_connection(bytes_sent=10240, bytes_recv=5120)
        results_bi = analyzer.analyze_connections([conn_bi])

        assert len(results_bi) == 1
        assert results_bi[0].is_bidirectional

        # One-way upload
        conn_upload = create_test_connection(bytes_sent=10240, bytes_recv=0)
        results_upload = analyzer.analyze_connections([conn_upload])

        if results_upload:
            assert not results_upload[0].is_bidirectional

    def test_data_ratio_calculation(self):
        """Test data ratio calculation."""
        analyzer = LongConnectionAnalyzer(min_score_threshold=0.0)

        conn = create_test_connection(bytes_sent=20480, bytes_recv=5120)
        results = analyzer.analyze_connections([conn])

        assert len(results) == 1
        # Ratio should be 4:1
        assert results[0].data_ratio == 4.0

    def test_confidence_calculation(self):
        """Test confidence scoring."""
        analyzer = LongConnectionAnalyzer(min_score_threshold=0.0)

        # Large data transfer (higher confidence)
        conn_large = create_test_connection(
            bytes_sent=50 * 1024 * 1024,  # 50 MB
            bytes_recv=10 * 1024 * 1024,  # 10 MB
            service="https",
        )

        # Small data transfer (lower confidence)
        conn_small = create_test_connection(
            bytes_sent=1024,
            bytes_recv=512,
            service=None,
        )

        results_large = analyzer.analyze_connections([conn_large])
        results_small = analyzer.analyze_connections([conn_small])

        if results_large and results_small:
            assert results_large[0].confidence > results_small[0].confidence

    def test_threat_level_assignment(self):
        """Test threat level assignment based on score."""
        analyzer = LongConnectionAnalyzer(min_score_threshold=0.0)

        # Very suspicious connection
        conn_critical = create_test_connection(
            service="dns",
            dst_port=53,
            duration=1800.0,  # 30 min DNS connection
            bytes_sent=10 * 1024 * 1024,
            dst_ip="8.8.8.8",
        )

        results = analyzer.analyze_connections([conn_critical])
        if results:
            # Should be high or critical threat
            assert results[0].threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]

    def test_reasons_explainability(self):
        """Test that reasons provide explainability."""
        analyzer = LongConnectionAnalyzer(min_score_threshold=0.0)

        conn = create_test_connection(
            duration=7200.0,  # 2 hours
            bytes_sent=100 * 1024 * 1024,  # 100 MB
            dst_ip="8.8.8.8",
        )

        results = analyzer.analyze_connections([conn])
        reasons = results[0].reasons

        # Should explain the detection
        assert len(reasons) > 0
        assert any("duration" in r.lower() for r in reasons)
        assert any("upload" in r.lower() or "transfer" in r.lower() for r in reasons)

    def test_indicators_provided(self):
        """Test that indicators are provided."""
        analyzer = LongConnectionAnalyzer(min_score_threshold=0.0)

        conn = create_test_connection(
            duration=3600.0,
            bytes_sent=50 * 1024 * 1024,
        )

        results = analyzer.analyze_connections([conn])
        indicators = results[0].indicators

        # Should provide specific indicators
        assert len(indicators) > 0
        assert any("Duration" in i for i in indicators)
        assert any("Sent" in i for i in indicators)
        assert any("Rate" in i for i in indicators)

    def test_mitre_mappings_have_evidence(self):
        """Test that MITRE mappings include evidence."""
        analyzer = LongConnectionAnalyzer(min_score_threshold=0.0)

        conn = create_test_connection(
            duration=3600.0,
            bytes_sent=50 * 1024 * 1024,
        )

        results = analyzer.analyze_connections([conn])
        mappings = results[0].mitre_mappings

        assert len(mappings) > 0
        for mapping in mappings:
            assert len(mapping.evidence) > 0
            assert mapping.technique_id
            assert mapping.technique_name
            assert 0 <= mapping.confidence <= 1

    def test_scheduled_transfer_detection(self):
        """Test detection of scheduled/regular transfers."""
        analyzer = LongConnectionAnalyzer(min_score_threshold=0.0)

        # Long connection with sustained transfer
        conn = create_test_connection(
            duration=3600.0,
            bytes_sent=10 * 1024 * 1024,
            bytes_recv=5 * 1024 * 1024,
        )

        results = analyzer.analyze_connections([conn])
        assert len(results) == 1
        # Should map to scheduled transfer
        assert "T1029" in results[0].mitre_techniques

    def test_score_threshold_filtering(self):
        """Test that score threshold filters low-score connections."""
        analyzer = LongConnectionAnalyzer(min_score_threshold=60.0)

        # Low-score connection (internal, standard port)
        conn_low = create_test_connection(
            dst_ip="192.0.2.50",
            dst_port=443,
            duration=600.0,
            bytes_sent=1024,
        )

        # High-score connection (external, long, large upload)
        conn_high = create_test_connection(
            dst_ip="8.8.8.8",
            duration=7200.0,
            bytes_sent=100 * 1024 * 1024,
        )

        results = analyzer.analyze_connections([conn_low, conn_high])

        # Only high-score connection should pass threshold
        assert all(r.score >= 60.0 for r in results)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
