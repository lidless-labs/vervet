"""
Tests for Suricata alert analyzer.
"""
import pytest
from api.services.suricata_analyzer import SuricataAnalyzer
from api.models.suricata import SuricataAlert
from api.models.threat import ThreatLevel


def create_test_alert(
    signature: str = "Test Signature",
    category: str = "Misc Attack",
    severity: int = 2,
    src_ip: str = "192.0.2.100",
    dst_ip: str = "8.8.8.8",
    dst_port: int = 443,
    app_proto: str = "tls",
) -> SuricataAlert:
    """Create a test Suricata alert."""
    return SuricataAlert(
        timestamp="2024-01-15T10:30:00.000Z",
        event_type="alert",
        src_ip=src_ip,
        src_port=54321,
        dest_ip=dst_ip,
        dest_port=dst_port,
        proto="TCP",
        alert={
            "action": "allowed",
            "gid": 1,
            "signature_id": 123456,
            "rev": 1,
            "signature": signature,
            "category": category,
            "severity": severity,
        },
        app_proto=app_proto,
    )


class TestSuricataAnalyzer:
    """Tests for SuricataAnalyzer."""

    def test_analyzer_initialization(self):
        """Test analyzer can be initialized."""
        analyzer = SuricataAnalyzer()
        assert analyzer.min_score_threshold == 40.0

    def test_analyze_empty_alerts(self):
        """Test analyzing empty alert list."""
        analyzer = SuricataAnalyzer()
        results = analyzer.analyze_alerts([])
        assert results == []

    def test_analyze_single_alert(self):
        """Test analyzing a single alert."""
        analyzer = SuricataAnalyzer(min_score_threshold=0.0)
        alert = create_test_alert()
        results = analyzer.analyze_alerts([alert])

        assert len(results) == 1
        result = results[0]
        assert result.alert == alert
        assert 0 <= result.score <= 100
        assert 0 <= result.confidence <= 1
        assert result.threat_level in [
            ThreatLevel.CRITICAL,
            ThreatLevel.HIGH,
            ThreatLevel.MEDIUM,
            ThreatLevel.LOW,
            ThreatLevel.INFO,
        ]

    def test_severity_scoring(self):
        """Test that higher severity gets higher scores."""
        analyzer = SuricataAnalyzer(min_score_threshold=0.0)

        # High severity (1)
        alert_high = create_test_alert(severity=1)
        # Low severity (3)
        alert_low = create_test_alert(severity=3)

        results_high = analyzer.analyze_alerts([alert_high])
        results_low = analyzer.analyze_alerts([alert_low])

        assert results_high[0].severity_score > results_low[0].severity_score

    def test_category_scoring(self):
        """Test category-based scoring."""
        analyzer = SuricataAnalyzer(min_score_threshold=0.0)

        # Critical category
        alert_critical = create_test_alert(category="A Network Trojan was detected")
        # Low category
        alert_low = create_test_alert(category="Misc activity")

        results_critical = analyzer.analyze_alerts([alert_critical])
        results_low = analyzer.analyze_alerts([alert_low])

        assert results_critical[0].category_score > results_low[0].category_score

    def test_frequency_scoring(self):
        """Test frequency scoring for repeated alerts."""
        analyzer = SuricataAnalyzer(min_score_threshold=0.0)

        # Create 10 identical alerts
        alerts = [create_test_alert() for _ in range(10)]
        results = analyzer.analyze_alerts(alerts)

        # All should have frequency boost
        for result in results:
            assert result.frequency_score > 0

    def test_mitre_mapping_exploit(self):
        """Test MITRE mapping for exploit signatures."""
        analyzer = SuricataAnalyzer(min_score_threshold=0.0)

        alert = create_test_alert(
            signature="Exploit CVE-2024-1234 detected",
            category="Exploit",
        )
        results = analyzer.analyze_alerts([alert])

        assert len(results) == 1
        assert "T1190" in results[0].mitre_techniques  # Exploit Public-Facing Application

    def test_mitre_mapping_c2(self):
        """Test MITRE mapping for C2 signatures."""
        analyzer = SuricataAnalyzer(min_score_threshold=0.0)

        alert = create_test_alert(
            signature="CobaltStrike C2 beacon detected",
            category="Malware Command and Control Activity Detected",
        )
        results = analyzer.analyze_alerts([alert])

        assert len(results) == 1
        assert "T1071" in results[0].mitre_techniques  # Application Layer Protocol

    def test_mitre_mapping_dns(self):
        """Test MITRE mapping for DNS-based attacks."""
        analyzer = SuricataAnalyzer(min_score_threshold=0.0)

        alert = create_test_alert(
            signature="DNS Tunneling detected",
            app_proto="dns",
            dst_port=53,
        )
        results = analyzer.analyze_alerts([alert])

        assert len(results) == 1
        assert "T1071.004" in results[0].mitre_techniques  # DNS protocol

    def test_mitre_mapping_scanning(self):
        """Test MITRE mapping for scanning activity."""
        analyzer = SuricataAnalyzer(min_score_threshold=0.0)

        alert = create_test_alert(
            signature="Port scan detected from source",
            category="Detection of a Network Scan",
        )
        results = analyzer.analyze_alerts([alert])

        assert len(results) == 1
        assert "T1046" in results[0].mitre_techniques  # Network Service Discovery

    def test_context_scoring_nonstandard_port(self):
        """Test context scoring for non-standard ports."""
        analyzer = SuricataAnalyzer(min_score_threshold=0.0)

        # HTTPS on non-standard port
        alert_nonstandard = create_test_alert(app_proto="tls", dst_port=8888)
        # HTTPS on standard port
        alert_standard = create_test_alert(app_proto="tls", dst_port=443)

        results_nonstandard = analyzer.analyze_alerts([alert_nonstandard])
        results_standard = analyzer.analyze_alerts([alert_standard])

        assert results_nonstandard[0].context_score > results_standard[0].context_score

    def test_pattern_detection_scanning(self):
        """Test detection of scanning patterns."""
        analyzer = SuricataAnalyzer(min_score_threshold=0.0)

        # Create alerts from one source to multiple destinations
        alerts = [
            create_test_alert(
                signature="Port scan detected",
                src_ip="203.0.113.100",
                dst_ip=f"198.19.1.{i}",
                category="Detection of a Network Scan",
            )
            for i in range(10)
        ]

        scored_alerts = analyzer.analyze_alerts(alerts)
        patterns = analyzer.detect_patterns(scored_alerts)

        # Should detect scanning pattern
        assert len(patterns) > 0
        assert any(p.pattern_type == "scanning" for p in patterns)

    def test_pattern_detection_exploit_chain(self):
        """Test detection of exploit chains."""
        analyzer = SuricataAnalyzer(min_score_threshold=0.0)

        # Create multiple different attacks against same target
        alerts = [
            create_test_alert(
                signature="Port scan",
                src_ip="8.8.8.8",
                dst_ip="192.0.2.100",
                category="Detection of a Network Scan",
            ),
            create_test_alert(
                signature="Exploit attempt CVE-2024-1234",
                src_ip="8.8.8.8",
                dst_ip="192.0.2.100",
                category="Exploit",
            ),
            create_test_alert(
                signature="Malware C2 communication",
                src_ip="8.8.8.8",
                dst_ip="192.0.2.100",
                category="Malware Command and Control Activity Detected",
            ),
        ]

        scored_alerts = analyzer.analyze_alerts(alerts)
        patterns = analyzer.detect_patterns(scored_alerts)

        # Should detect exploit chain
        assert len(patterns) > 0
        assert any(p.pattern_type == "exploit_chain" for p in patterns)

    def test_threat_level_assignment(self):
        """Test threat level assignment based on score."""
        analyzer = SuricataAnalyzer(min_score_threshold=0.0)

        # Critical severity alert
        alert_critical = create_test_alert(
            severity=1,
            category="A Network Trojan was detected",
        )

        # Low severity alert
        alert_low = create_test_alert(
            severity=3,
            category="Misc activity",
        )

        results_critical = analyzer.analyze_alerts([alert_critical])
        results_low = analyzer.analyze_alerts([alert_low])

        # Critical should have higher threat level
        level_order = {
            ThreatLevel.CRITICAL: 4,
            ThreatLevel.HIGH: 3,
            ThreatLevel.MEDIUM: 2,
            ThreatLevel.LOW: 1,
            ThreatLevel.INFO: 0,
        }

        assert level_order[results_critical[0].threat_level] > level_order[results_low[0].threat_level]

    def test_reasons_explainability(self):
        """Test that reasons provide explainability."""
        analyzer = SuricataAnalyzer(min_score_threshold=0.0)

        alert = create_test_alert(
            severity=1,
            category="Exploit",
            signature="Exploit CVE-2024-1234 targeting web application",
        )

        results = analyzer.analyze_alerts([alert])
        reasons = results[0].reasons

        # Should have multiple reasons explaining the score
        assert len(reasons) > 0
        assert any("Severity" in r for r in reasons)
        assert any("Category" in r or "Exploit" in r for r in reasons)

    def test_mitre_mappings_have_evidence(self):
        """Test that MITRE mappings include evidence."""
        analyzer = SuricataAnalyzer(min_score_threshold=0.0)

        alert = create_test_alert(
            signature="Malware C2 beacon",
            category="Malware Command and Control Activity Detected",
        )

        results = analyzer.analyze_alerts([alert])
        mappings = results[0].mitre_mappings

        assert len(mappings) > 0
        for mapping in mappings:
            assert len(mapping.evidence) > 0
            assert mapping.technique_id
            assert mapping.technique_name
            assert mapping.tactic
            assert 0 <= mapping.confidence <= 1

    def test_score_threshold_filtering(self):
        """Test that score threshold filters low-score alerts."""
        analyzer = SuricataAnalyzer(min_score_threshold=60.0)

        # Low severity alert (should be filtered)
        alert_low = create_test_alert(severity=3, category="Misc activity")
        # High severity alert (should pass)
        alert_high = create_test_alert(severity=1, category="Exploit")

        results = analyzer.analyze_alerts([alert_low, alert_high])

        # Only high-severity alert should pass threshold
        assert len(results) == 1
        assert results[0].alert == alert_high


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
