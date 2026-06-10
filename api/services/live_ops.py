"""
Live Operations service for Vervet.
Tracks real-time ingest state including timestamps, counters, and source statistics.
"""
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional
from threading import Lock

logger = logging.getLogger(__name__)


@dataclass
class SourceStats:
    """Statistics for a single ingest source."""
    event_count: int = 0
    last_ingest_at: Optional[datetime] = None
    bytes_received: int = 0
    error_count: int = 0


@dataclass
class LiveOpsState:
    """In-memory state for live operations tracking."""
    # Source-specific stats
    zeek_stats: SourceStats = field(default_factory=SourceStats)
    suricata_stats: SourceStats = field(default_factory=SourceStats)
    
    # Global counters
    total_events_ingested: int = 0
    last_event_at: Optional[datetime] = None
    
    # Status
    is_healthy: bool = True
    
    def to_dict(self) -> dict:
        """Convert state to dictionary for API responses."""
        return {
            "zeek": {
                "event_count": self.zeek_stats.event_count,
                "last_ingest_at": self.zeek_stats.last_ingest_at.isoformat() if self.zeek_stats.last_ingest_at else None,
                "bytes_received": self.zeek_stats.bytes_received,
                "error_count": self.zeek_stats.error_count,
            },
            "suricata": {
                "event_count": self.suricata_stats.event_count,
                "last_ingest_at": self.suricata_stats.last_ingest_at.isoformat() if self.suricata_stats.last_ingest_at else None,
                "bytes_received": self.suricata_stats.bytes_received,
                "error_count": self.suricata_stats.error_count,
            },
            "total_events_ingested": self.total_events_ingested,
            "last_event_at": self.last_event_at.isoformat() if self.last_event_at else None,
            "is_healthy": self.is_healthy,
        }


class LiveOpsService:
    """
    Service for tracking live operations state.
    Thread-safe in-memory storage for ingest metrics.
    """
    
    def __init__(self):
        self._state = LiveOpsState()
        self._lock = Lock()
        self._recent_events: list[dict] = []
        self._max_recent_events = 10000  # Keep last 10k events in memory
    
    def record_zeek_ingest(self, event_count: int, bytes_received: int, errors: int = 0) -> None:
        """Record Zeek ingest batch."""
        with self._lock:
            now = datetime.now(timezone.utc)
            self._state.zeek_stats.event_count += event_count
            self._state.zeek_stats.bytes_received += bytes_received
            self._state.zeek_stats.error_count += errors
            self._state.zeek_stats.last_ingest_at = now
            self._state.total_events_ingested += event_count
            self._state.last_event_at = now
            logger.debug(f"Recorded Zeek ingest: {event_count} events, {bytes_received} bytes")
    
    def record_suricata_ingest(self, event_count: int, bytes_received: int, errors: int = 0) -> None:
        """Record Suricata ingest batch."""
        with self._lock:
            now = datetime.now(timezone.utc)
            self._state.suricata_stats.event_count += event_count
            self._state.suricata_stats.bytes_received += bytes_received
            self._state.suricata_stats.error_count += errors
            self._state.suricata_stats.last_ingest_at = now
            self._state.total_events_ingested += event_count
            self._state.last_event_at = now
            logger.debug(f"Recorded Suricata ingest: {event_count} events, {bytes_received} bytes")
    
    def get_status(self) -> dict:
        """Get current live operations status."""
        with self._lock:
            return self._state.to_dict()
    
    def add_recent_event(self, event: dict) -> None:
        """Add an event to the recent events buffer."""
        with self._lock:
            self._recent_events.append(event)
            # Trim if exceeds max
            if len(self._recent_events) > self._max_recent_events:
                self._recent_events = self._recent_events[-self._max_recent_events:]
    
    def get_recent_events(self, since: Optional[datetime] = None, limit: int = 500) -> list[dict]:
        """
        Get recent events, optionally filtered by timestamp.
        
        Args:
            since: Only return events after this timestamp
            limit: Maximum number of events to return
            
        Returns:
            List of event dictionaries
        """
        with self._lock:
            events = self._recent_events
            if since:
                events = [
                    e for e in events 
                    if e.get("timestamp") and e.get("timestamp") > since
                ]
            # Return most recent first, limited
            return events[-limit:][::-1]
    
    def reset(self) -> None:
        """Reset all state (useful for testing)."""
        with self._lock:
            self._state = LiveOpsState()
            self._recent_events = []
            logger.info("LiveOps state reset")


# Global singleton instance
live_ops_service = LiveOpsService()
