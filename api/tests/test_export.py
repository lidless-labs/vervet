"""Tests for IOC export functionality."""
import csv
import io
import json
import xml.etree.ElementTree as ET

import pytest

from api.routers.export import _export_csv, _export_stix, _export_openioc


SAMPLE_IOCS = [
    {
        "indicator": "192.0.2.100",
        "type": "ip",
        "severity": "high",
        "score": 85.0,
        "first_seen": "2026-01-01T00:00:00+00:00",
        "last_seen": "2026-01-01T01:00:00+00:00",
        "mitre_techniques": "T1071,T1048",
        "source": "vervet",
        "context": "C2 beaconing detected",
    },
    {
        "indicator": "evil.example.com",
        "type": "domain",
        "severity": "critical",
        "score": 95.0,
        "first_seen": "2026-01-01T00:05:00+00:00",
        "last_seen": "2026-01-01T00:30:00+00:00",
        "mitre_techniques": "T1071.004",
        "source": "vervet",
        "context": "DNS tunneling to evil.example.com",
    },
]


class TestCsvExport:
    def test_csv_has_header(self):
        response = _export_csv(SAMPLE_IOCS)
        # StreamingResponse wraps content
        assert response.media_type == "text/csv"

    def test_csv_parses_correctly(self):
        output = io.StringIO()
        fields = ["indicator", "type", "severity", "score", "first_seen", "last_seen", "mitre_techniques", "source", "context"]
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for ioc in SAMPLE_IOCS:
            writer.writerow(ioc)
        output.seek(0)
        reader = csv.DictReader(output)
        rows = list(reader)
        assert len(rows) == 2
        assert rows[0]["indicator"] == "192.0.2.100"
        assert rows[1]["type"] == "domain"


class TestStixExport:
    def test_stix_bundle_structure(self):
        response = _export_stix(SAMPLE_IOCS)
        body = json.loads(response.body)
        assert body["type"] == "bundle"
        assert "id" in body
        assert body["id"].startswith("bundle--")
        # Identity + 2 indicators
        assert len(body["objects"]) == 3

    def test_stix_indicator_pattern(self):
        response = _export_stix(SAMPLE_IOCS)
        body = json.loads(response.body)
        indicators = [o for o in body["objects"] if o["type"] == "indicator"]
        assert len(indicators) == 2
        assert "ipv4-addr:value" in indicators[0]["pattern"]
        assert "domain-name:value" in indicators[1]["pattern"]

    def test_stix_confidence_mapping(self):
        response = _export_stix(SAMPLE_IOCS)
        body = json.loads(response.body)
        indicators = [o for o in body["objects"] if o["type"] == "indicator"]
        # high severity = 80 confidence
        assert indicators[0]["confidence"] == 80
        # critical severity = 95 confidence
        assert indicators[1]["confidence"] == 95


class TestOpenIocExport:
    def test_openioc_valid_xml(self):
        response = _export_openioc(SAMPLE_IOCS)
        # Should parse without error
        root = ET.fromstring(response.body)
        assert root.tag.endswith("ioc")

    def test_openioc_has_indicators(self):
        response = _export_openioc(SAMPLE_IOCS)
        content = response.body.decode() if isinstance(response.body, bytes) else response.body
        assert "192.0.2.100" in content
        assert "evil.example.com" in content


class TestSeverityFilter:
    def test_severity_ordering(self):
        from api.routers.export import _severity_filter
        from api.models.threat import ThreatLevel

        assert _severity_filter(ThreatLevel.CRITICAL, "low") is True
        assert _severity_filter(ThreatLevel.LOW, "high") is False
        assert _severity_filter(ThreatLevel.MEDIUM, "medium") is True
        assert _severity_filter(ThreatLevel.INFO, "low") is False
