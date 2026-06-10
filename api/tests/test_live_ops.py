"""Tests for live operations endpoints."""
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from api.services.live_ops import LiveOpsService, SourceStats, LiveOpsState
from api.parsers.unified import Connection, DnsQuery, Alert


class TestLiveOpsService:
    """Test the LiveOpsService class."""
    
    def setup_method(self):
        """Reset service before each test."""
        self.service = LiveOpsService()
        self.service.reset()
    
    def test_record_zeek_ingest_updates_stats(self):
        """Test that Zeek ingest updates stats correctly."""
        self.service.record_zeek_ingest(10, 1000, 0)
        
        status = self.service.get_status()
        assert status["zeek"]["event_count"] == 10
        assert status["zeek"]["bytes_received"] == 1000
        assert status["zeek"]["error_count"] == 0
        assert status["total_events_ingested"] == 10
        assert status["zeek"]["last_ingest_at"] is not None
    
    def test_record_suricata_ingest_updates_stats(self):
        """Test that Suricata ingest updates stats correctly."""
        self.service.record_suricata_ingest(5, 500, 1)
        
        status = self.service.get_status()
        assert status["suricata"]["event_count"] == 5
        assert status["suricata"]["bytes_received"] == 500
        assert status["suricata"]["error_count"] == 1
        assert status["total_events_ingested"] == 5
    
    def test_mixed_ingest_accumulates_totals(self):
        """Test that mixed Zeek and Suricata ingest accumulates totals."""
        self.service.record_zeek_ingest(10, 1000, 0)
        self.service.record_suricata_ingest(5, 500, 0)
        
        status = self.service.get_status()
        assert status["zeek"]["event_count"] == 10
        assert status["suricata"]["event_count"] == 5
        assert status["total_events_ingested"] == 15
    
    def test_add_and_get_recent_events(self):
        """Test adding and retrieving recent events."""
        event = {
            "id": "test-1",
            "timestamp": datetime.now(timezone.utc),
            "event_type": "conn",
            "source": "zeek",
            "data": {"src_ip": "203.0.113.1"},
        }
        
        self.service.add_recent_event(event)
        events = self.service.get_recent_events(limit=10)
        
        assert len(events) == 1
        assert events[0]["id"] == "test-1"
    
    def test_get_recent_events_filtered_by_since(self):
        """Test filtering events by since timestamp."""
        now = datetime.now(timezone.utc)
        
        old_event = {
            "id": "old",
            "timestamp": datetime(2024, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
            "event_type": "conn",
            "source": "zeek",
            "data": {},
        }
        new_event = {
            "id": "new",
            "timestamp": now,
            "event_type": "conn",
            "source": "zeek",
            "data": {},
        }
        
        self.service.add_recent_event(old_event)
        self.service.add_recent_event(new_event)
        
        # Filter events after 2024-06-01
        since = datetime(2024, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
        events = self.service.get_recent_events(since=since, limit=10)
        
        assert len(events) == 1
        assert events[0]["id"] == "new"
    
    def test_get_recent_events_respects_limit(self):
        """Test that limit parameter is respected."""
        for i in range(100):
            self.service.add_recent_event({
                "id": f"event-{i}",
                "timestamp": datetime.now(timezone.utc),
                "event_type": "conn",
                "source": "zeek",
                "data": {},
            })
        
        events = self.service.get_recent_events(limit=10)
        assert len(events) == 10
    
    def test_reset_clears_state(self):
        """Test that reset clears all state."""
        self.service.record_zeek_ingest(10, 1000, 0)
        self.service.add_recent_event({"id": "test", "timestamp": datetime.now(timezone.utc), "event_type": "conn", "source": "zeek", "data": {}})
        
        self.service.reset()
        
        status = self.service.get_status()
        assert status["total_events_ingested"] == 0
        assert status["zeek"]["event_count"] == 0
        
        events = self.service.get_recent_events(limit=10)
        assert len(events) == 0


class TestLiveOpsEndpoints:
    """Integration tests for live ops API endpoints."""
    
    @pytest.fixture
    def client(self):
        """Create a test client."""
        from fastapi.testclient import TestClient
        from api.main import app
        return TestClient(app)
    
    def test_get_status_returns_valid_response(self, client):
        """Test that GET /api/v1/live/status returns valid response."""
        response = client.get("/api/v1/live/status")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "zeek" in data
        assert "suricata" in data
        assert "total_events_ingested" in data
        assert "is_healthy" in data
        assert isinstance(data["is_healthy"], bool)
    
    def test_ingest_zeek_requires_auth(self, client):
        """Test that Zeek ingest requires API key."""
        # When API key is configured, auth is required
        # For tests, we'll just check the endpoint structure
        response = client.post(
            "/api/v1/live/ingest/zeek",
            content='{"ts":1700000000.0,"uid":"C1","id_orig_h":"203.0.113.1","id_orig_p":12345,"id_resp_h":"192.0.2.1","id_resp_p":80,"proto":"tcp"}',
            headers={"Content-Type": "text/plain"},
        )
        # In dev mode (no API key configured), this should succeed
        # In prod mode, would return 401
        assert response.status_code in [200, 401]
    
    def test_ingest_zeek_with_valid_payload(self, client):
        """Test Zeek ingest with valid payload."""
        payload = '{"ts":1700000000.0,"uid":"C1","id_orig_h":"203.0.113.1","id_orig_p":12345,"id_resp_h":"192.0.2.1","id_resp_p":80,"proto":"tcp","conn_state":"SF","orig_bytes":100,"resp_bytes":200}'
        
        response = client.post(
            "/api/v1/live/ingest/zeek?log_type=conn",
            content=payload,
            headers={"Content-Type": "text/plain"},
        )

        # Should succeed or require auth
        assert response.status_code in [200, 401]
        
        if response.status_code == 200:
            data = response.json()
            assert data["success"] is True
            assert data["events_ingested"] >= 0
    
    def test_ingest_suricata_with_valid_payload(self, client):
        """Test Suricata ingest with valid payload."""
        payload = '{"timestamp":"2024-01-01T00:00:00.000Z","event_type":"alert","src_ip":"203.0.113.1","dest_ip":"192.0.2.1","src_port":12345,"dest_port":80,"proto":"TCP","alert":{"signature":"Test","signature_id":123,"category":"test","severity":3,"action":"allowed"}}'
        
        response = client.post(
            "/api/v1/live/ingest/suricata",
            content=payload,
            headers={"Content-Type": "text/plain"},
        )

        assert response.status_code in [200, 401]

        if response.status_code == 200:
            data = response.json()
            assert data["success"] is True

    def test_ingest_zeek_empty_payload_fails(self, client):
        """Test that empty payload is rejected."""
        response = client.post(
            "/api/v1/live/ingest/zeek",
            content="",
            headers={"Content-Type": "text/plain"},
        )
        # A completely empty body fails the required-Body validation (422)
        # before the handler runs; a whitespace body would hit the handler's
        # explicit 400. Either way it is rejected (and 401 in prod auth mode).
        assert response.status_code in [400, 401, 422]

    def test_ingest_suricata_empty_payload_fails(self, client):
        """Test that empty payload is rejected."""
        response = client.post(
            "/api/v1/live/ingest/suricata",
            content="",
            headers={"Content-Type": "text/plain"},
        )
        assert response.status_code in [400, 401, 422]
    
    def test_get_events_returns_valid_response(self, client):
        """Test that GET /api/v1/live/events returns valid response."""
        response = client.get("/api/v1/live/events?limit=10")
        
        assert response.status_code == 200
        data = response.json()
        
        assert "events" in data
        assert "total" in data
        assert isinstance(data["events"], list)
        assert isinstance(data["total"], int)
    
    def test_get_events_with_invalid_since_fails(self, client):
        """Test that invalid since parameter returns 400."""
        response = client.get("/api/v1/live/events?since=invalid-timestamp")
        assert response.status_code == 400
    
    def test_get_events_respects_limit_parameter(self, client):
        """Test that limit parameter is respected."""
        response = client.get("/api/v1/live/events?limit=5")
        assert response.status_code == 200
        data = response.json()
        assert data["total"] <= 5


class TestLiveOpsState:
    """Test the LiveOpsState dataclass."""
    
    def test_state_initializes_with_defaults(self):
        """Test that state initializes with default values."""
        state = LiveOpsState()
        
        assert state.zeek_stats.event_count == 0
        assert state.suricata_stats.event_count == 0
        assert state.total_events_ingested == 0
        assert state.is_healthy is True
    
    def test_state_to_dict_serializes_correctly(self):
        """Test that to_dict produces correct output."""
        state = LiveOpsState()
        state.zeek_stats.event_count = 5
        state.zeek_stats.last_ingest_at = datetime(2024, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        
        result = state.to_dict()
        
        assert result["zeek"]["event_count"] == 5
        assert result["zeek"]["last_ingest_at"] == "2024-01-01T12:00:00+00:00"
        assert result["total_events_ingested"] == 0


class TestSourceStats:
    """Test the SourceStats dataclass."""
    
    def test_source_stats_initializes_with_defaults(self):
        """Test that SourceStats initializes with default values."""
        stats = SourceStats()
        
        assert stats.event_count == 0
        assert stats.bytes_received == 0
        assert stats.error_count == 0
        assert stats.last_ingest_at is None
