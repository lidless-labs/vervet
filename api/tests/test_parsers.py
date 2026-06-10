"""
Unit tests for Zeek and Suricata parsers.
Tests parsing, validation, and error handling with fixture data.
"""
import pytest
from pathlib import Path
from datetime import datetime

from api.parsers.zeek_parser import ZeekParser
from api.parsers.suricata_parser import SuricataParser
from api.parsers.unified import (
    normalize_zeek_conn,
    normalize_zeek_dns,
    normalize_suricata_flow,
    normalize_suricata_dns,
    normalize_suricata_alert,
)
from api.models.zeek import ConnLog, DnsLog, HttpLog
from api.models.suricata import SuricataAlert, SuricataFlow, SuricataDns


# Fixture paths
FIXTURES_DIR = Path(__file__).parent.parent.parent / "fixtures"
CONN_LOG = FIXTURES_DIR / "conn.log.json"
DNS_LOG = FIXTURES_DIR / "dns.log.json"
HTTP_LOG = FIXTURES_DIR / "http.log.json"
EVE_JSON = FIXTURES_DIR / "eve.json"


class TestZeekParser:
    """Test suite for Zeek log parser."""

    def test_detect_log_type(self):
        """Test log type detection from filename."""
        assert ZeekParser.detect_log_type("conn.log.json") == "conn"
        assert ZeekParser.detect_log_type("dns.log") == "dns"
        assert ZeekParser.detect_log_type("http.log.json") == "http"
        assert ZeekParser.detect_log_type("ssl.log") == "ssl"

        with pytest.raises(ValueError):
            ZeekParser.detect_log_type("unknown.log")

    def test_parse_timestamp(self):
        """Test Zeek timestamp parsing."""
        # Epoch for 2026-01-28 19:02:37.099166 UTC. The parser returns a
        # UTC-aware datetime, so date components are asserted in UTC. (The
        # previous epoch 1769645917 was actually 2026-01-29 00:18 UTC, which
        # contradicted the day==28 assertion below.)
        ts = 1769626957.099166
        dt = ZeekParser.parse_timestamp(ts)

        assert isinstance(dt, datetime)
        assert dt.year == 2026
        assert dt.month == 1
        assert dt.day == 28

    def test_parse_conn_log(self):
        """Test parsing Zeek connection log."""
        if not CONN_LOG.exists():
            pytest.skip(f"Fixture not found: {CONN_LOG}")

        entries = list(ZeekParser.parse_file(CONN_LOG, log_type="conn"))

        assert len(entries) > 0, "Should parse at least one connection"

        # Validate first entry
        first = entries[0]
        assert isinstance(first, ConnLog)
        assert first.uid is not None
        assert first.id_orig_h is not None
        assert first.id_resp_h is not None
        assert first.proto in ["tcp", "udp", "icmp"]
        assert isinstance(first.ts, float)

    def test_parse_dns_log(self):
        """Test parsing Zeek DNS log."""
        if not DNS_LOG.exists():
            pytest.skip(f"Fixture not found: {DNS_LOG}")

        entries = list(ZeekParser.parse_file(DNS_LOG, log_type="dns"))

        assert len(entries) > 0, "Should parse at least one DNS query"

        # Validate first entry
        first = entries[0]
        assert isinstance(first, DnsLog)
        assert first.uid is not None
        assert first.query is not None
        assert first.qtype_name is not None

    def test_parse_http_log(self):
        """Test parsing Zeek HTTP log."""
        if not HTTP_LOG.exists():
            pytest.skip(f"Fixture not found: {HTTP_LOG}")

        entries = list(ZeekParser.parse_file(HTTP_LOG, log_type="http"))

        assert len(entries) > 0, "Should parse at least one HTTP request"

        # Validate first entry
        first = entries[0]
        assert isinstance(first, HttpLog)
        assert first.uid is not None
        assert first.method is not None
        assert first.host is not None

    def test_parse_line(self):
        """Test parsing a single JSON line."""
        line = '{"ts": 1769645917.099166, "uid": "C5T0tmWEJmx88sZ8Ua", "id_orig_h": "203.0.113.5", "id_orig_p": 54321, "id_resp_h": "157.240.3.35", "id_resp_p": 0, "proto": "icmp", "service": null, "duration": 0.186}'

        entry = ZeekParser.parse_line(line, "conn")

        assert entry is not None
        assert isinstance(entry, ConnLog)
        assert entry.uid == "C5T0tmWEJmx88sZ8Ua"
        assert entry.id_orig_h == "203.0.113.5"

    def test_validate_log_entry(self):
        """Test log entry validation."""
        valid_entry = {
            "ts": 1769645917.099166,
            "uid": "C5T0tmWEJmx88sZ8Ua",
            "id_orig_h": "203.0.113.5",
            "id_orig_p": 54321,
            "id_resp_h": "157.240.3.35",
            "id_resp_p": 0,
            "proto": "icmp",
        }

        assert ZeekParser.validate_log_entry(valid_entry, "conn") is True

        # Missing required field
        invalid_entry = {
            "ts": 1769645917.099166,
            "uid": "C5T0tmWEJmx88sZ8Ua",
        }

        assert ZeekParser.validate_log_entry(invalid_entry, "conn") is False

    def test_error_handling(self):
        """Test parser error handling with malformed data."""
        # Create temporary file with malformed JSON
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log.json", delete=False) as f:
            f.write('{"valid": "json"}\n')
            f.write('this is not json\n')
            f.write('{"ts": 1234, "uid": "test"}\n')  # Missing required fields
            temp_path = Path(f.name)

        try:
            entries = list(ZeekParser.parse_file(temp_path, log_type="conn"))
            # Should parse valid entry and skip malformed ones
            assert len(entries) == 0, "No entries should match conn schema"
        finally:
            temp_path.unlink()


class TestSuricataParser:
    """Test suite for Suricata log parser."""

    def test_parse_eve_json(self):
        """Test parsing Suricata eve.json."""
        if not EVE_JSON.exists():
            pytest.skip(f"Fixture not found: {EVE_JSON}")

        entries = list(SuricataParser.parse_file(EVE_JSON))

        assert len(entries) > 0, "Should parse at least one event"

        # Check for alerts
        alerts = [e for e in entries if isinstance(e, SuricataAlert)]
        assert len(alerts) > 0, "Should have at least one alert"

        first_alert = alerts[0]
        assert first_alert.event_type == "alert"
        assert first_alert.src_ip is not None
        assert first_alert.alert is not None
        assert "signature" in first_alert.alert

    def test_extract_alerts_only(self):
        """Test extracting only alerts from eve.json."""
        if not EVE_JSON.exists():
            pytest.skip(f"Fixture not found: {EVE_JSON}")

        alerts = list(SuricataParser.extract_alerts(EVE_JSON))

        assert len(alerts) > 0
        assert all(isinstance(a, SuricataAlert) for a in alerts)

    def test_parse_timestamp(self):
        """Test Suricata timestamp parsing."""
        ts = "2026-01-28T19:02:37.099166Z"
        dt = SuricataParser.parse_timestamp(ts)

        assert isinstance(dt, datetime)
        assert dt.year == 2026
        assert dt.month == 1
        assert dt.day == 28

    def test_parse_line(self):
        """Test parsing a single eve.json line."""
        line = '{"timestamp": "2026-01-28T19:02:37.099166Z", "flow_id": 7091217, "event_type": "alert", "src_ip": "185.199.108.153", "src_port": 55641, "dest_ip": "192.0.2.10", "dest_port": 8080, "proto": "UDP", "alert": {"action": "allowed", "gid": 1, "signature_id": 2654741, "rev": 10, "signature": "ET SCAN Test", "category": "Misc", "severity": 1}}'

        entry = SuricataParser.parse_line(line)

        assert entry is not None
        assert isinstance(entry, SuricataAlert)
        assert entry.src_ip == "185.199.108.153"
        assert entry.dest_port == 8080

    def test_validate_log_entry(self):
        """Test Suricata log entry validation."""
        valid_entry = {
            "timestamp": "2026-01-28T19:02:37.099166Z",
            "flow_id": 7091217,
            "event_type": "alert",
            "src_ip": "185.199.108.153",
            "src_port": 55641,
            "dest_ip": "192.0.2.10",
            "dest_port": 8080,
            "proto": "UDP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2654741,
                "rev": 10,
                "signature": "Test",
                "category": "Misc",
                "severity": 1,
            },
        }

        assert SuricataParser.validate_log_entry(valid_entry) is True

        # Missing event_type
        invalid_entry = {"timestamp": "2026-01-28T19:02:37.099166Z"}

        assert SuricataParser.validate_log_entry(invalid_entry) is False


class TestUnifiedModels:
    """Test suite for unified model normalization."""

    def test_normalize_zeek_conn(self):
        """Test normalizing Zeek connection to unified model."""
        if not CONN_LOG.exists():
            pytest.skip(f"Fixture not found: {CONN_LOG}")

        zeek_entries = list(ZeekParser.parse_file(CONN_LOG, log_type="conn"))
        first = zeek_entries[0]

        normalized = normalize_zeek_conn(first)

        assert normalized.src_ip == first.id_orig_h
        assert normalized.dst_ip == first.id_resp_h
        assert normalized.src_port == first.id_orig_p
        assert normalized.dst_port == first.id_resp_p
        assert normalized.proto == first.proto.lower()
        assert normalized.source == "zeek"
        assert isinstance(normalized.timestamp, datetime)

    def test_normalize_zeek_dns(self):
        """Test normalizing Zeek DNS to unified model."""
        if not DNS_LOG.exists():
            pytest.skip(f"Fixture not found: {DNS_LOG}")

        zeek_entries = list(ZeekParser.parse_file(DNS_LOG, log_type="dns"))
        first = zeek_entries[0]

        normalized = normalize_zeek_dns(first)

        assert normalized.src_ip == first.id_orig_h
        assert normalized.dst_ip == first.id_resp_h
        assert normalized.query == first.query
        assert normalized.source == "zeek"
        assert isinstance(normalized.timestamp, datetime)

    def test_normalize_suricata_alert(self):
        """Test normalizing Suricata alert to unified model."""
        if not EVE_JSON.exists():
            pytest.skip(f"Fixture not found: {EVE_JSON}")

        alerts = list(SuricataParser.extract_alerts(EVE_JSON))
        first = alerts[0]

        normalized = normalize_suricata_alert(first)

        assert normalized.src_ip == first.src_ip
        assert normalized.dst_ip == first.dest_ip
        assert normalized.signature is not None
        assert normalized.severity >= 1
        assert isinstance(normalized.timestamp, datetime)


class TestIntegration:
    """Integration tests using fixture data."""

    def test_full_ingestion_workflow(self):
        """Test complete ingestion workflow with all log types."""
        if not FIXTURES_DIR.exists():
            pytest.skip(f"Fixtures directory not found: {FIXTURES_DIR}")

        from api.services.log_store import LogStore

        store = LogStore()

        # Load directory
        stats = store.load_directory(FIXTURES_DIR)

        # Verify stats
        assert stats["file_count"] > 0, "Should load at least one file"
        assert stats["record_count"] > 0, "Should load at least one record"

        # Verify connections
        connections = store.get_connections(limit=10)
        assert len(connections) > 0, "Should have connections"

        # Verify DNS queries
        dns_queries = store.get_dns_queries(limit=10)
        assert len(dns_queries) > 0, "Should have DNS queries"

    def test_connection_filtering(self):
        """Test connection filtering functionality."""
        if not CONN_LOG.exists():
            pytest.skip(f"Fixture not found: {CONN_LOG}")

        from api.services.log_store import LogStore

        store = LogStore()
        store.load_directory(FIXTURES_DIR)

        # Filter by protocol
        tcp_conns = store.get_connections(proto="tcp")
        assert all(c.proto == "tcp" for c in tcp_conns)

        # Filter by source IP
        if len(store.connections) > 0:
            test_ip = store.connections[0].src_ip
            filtered = store.get_connections(src_ip=test_ip)
            assert all(c.src_ip == test_ip for c in filtered)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
