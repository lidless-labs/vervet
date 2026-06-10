"""
Live Operations router for Vervet.
Provides real-time ingest endpoints and incremental event queries.
"""
import json
import logging
from datetime import datetime, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, HTTPException, status, Depends, Query, Body
from pydantic import BaseModel, Field

from api.dependencies.auth import api_key_auth
from api.services.live_ops import live_ops_service
from api.services.log_store import log_store
from api.parsers.zeek_parser import ZeekParser
from api.parsers.suricata_parser import SuricataParser
from api.parsers.unified import (
    normalize_zeek_conn,
    normalize_zeek_dns,
    normalize_suricata_flow,
    normalize_suricata_dns,
    normalize_suricata_alert,
)
from api.models.zeek import ConnLog, DnsLog
from api.models.suricata import SuricataAlert, SuricataFlow, SuricataDns

logger = logging.getLogger(__name__)

router = APIRouter()


class IngestResponse(BaseModel):
    """Response model for ingest operations."""
    success: bool = Field(..., description="Whether ingest succeeded")
    message: str = Field(..., description="Status message")
    events_ingested: int = Field(..., description="Number of events ingested")
    errors: int = Field(0, description="Number of parsing errors")


class LiveStatusResponse(BaseModel):
    """Response model for live status endpoint."""
    zeek: dict = Field(..., description="Zeek ingest statistics")
    suricata: dict = Field(..., description="Suricata ingest statistics")
    total_events_ingested: int = Field(..., description="Total events ingested")
    last_event_at: Optional[str] = Field(None, description="ISO timestamp of last event")
    is_healthy: bool = Field(..., description="Overall health status")


class EventItem(BaseModel):
    """Single event in the events list."""
    id: str = Field(..., description="Unique event identifier")
    timestamp: str = Field(..., description="ISO 8601 timestamp")
    event_type: str = Field(..., description="Event type (conn, dns, alert)")
    source: str = Field(..., description="Source system (zeek, suricata)")
    data: dict = Field(..., description="Event data")


class EventsResponse(BaseModel):
    """Response model for events endpoint."""
    events: list[EventItem] = Field(..., description="List of events")
    total: int = Field(..., description="Total events returned")
    since: Optional[str] = Field(None, description="Query timestamp filter")


def _parse_iso_timestamp(ts_str: str) -> Optional[datetime]:
    """Parse ISO timestamp string to timezone-aware datetime (UTC default)."""
    try:
        # Handle various ISO formats
        ts_str = ts_str.replace('Z', '+00:00')
        parsed = datetime.fromisoformat(ts_str)
        # Avoid naive/aware comparison errors downstream
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except (ValueError, TypeError) as e:
        logger.warning(f"Failed to parse timestamp '{ts_str}': {e}")
        return None


@router.get(
    "/status",
    response_model=LiveStatusResponse,
    summary="Get live operations status",
    description="Returns current ingest statistics and health status",
)
async def get_live_status() -> LiveStatusResponse:
    """
    Get live operations status including ingest counters and timestamps.
    
    Returns:
        LiveStatusResponse with zeek/suricata stats and health status
    """
    status_data = live_ops_service.get_status()
    return LiveStatusResponse(**status_data)


@router.post(
    "/ingest/zeek",
    response_model=IngestResponse,
    summary="Ingest Zeek JSON lines",
    description="Accept Zeek JSON lines payload and parse incremental events into log store",
)
async def ingest_zeek(
    _: Annotated[str, Depends(api_key_auth)],
    payload: str = Body(..., media_type="text/plain", description="Zeek JSON lines (one JSON object per line)"),
    log_type: str = Query("auto", description="Log type (conn, dns) or auto-detect"),
) -> IngestResponse:
    """
    Ingest Zeek log events from JSON lines payload.
    
    Accepts raw JSON lines text where each line is a Zeek log entry.
    Parses and normalizes events into the unified log store.
    
    Args:
        payload: Raw JSON lines text
        log_type: Type of Zeek log (conn, dns) or "auto" to detect
        
    Returns:
        IngestResponse with count of ingested events
    """
    if not payload or not payload.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty payload",
        )
    
    lines = payload.strip().split('\n')
    events_ingested = 0
    errors = 0
    bytes_received = len(payload.encode('utf-8'))
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        try:
            # Auto-detect log type if needed
            detected_type = log_type
            if log_type == "auto":
                # Try to detect from JSON content
                try:
                    data = json.loads(line)
                    if 'id.orig_h' in data or 'id_orig_h' in data:
                        if 'query' in data:
                            detected_type = 'dns'
                        else:
                            detected_type = 'conn'
                    else:
                        detected_type = 'conn'  # default
                except json.JSONDecodeError:
                    errors += 1
                    continue
            
            # Parse based on type
            if detected_type == 'conn':
                entry = ZeekParser.parse_line(line, 'conn')
                if entry:
                    conn = normalize_zeek_conn(entry)
                    log_store._add_connection(conn)
                    events_ingested += 1
                    
                    # Add to recent events
                    live_ops_service.add_recent_event({
                        "id": conn.uid,
                        "timestamp": conn.timestamp,
                        "event_type": "conn",
                        "source": "zeek",
                        "data": {
                            "src_ip": conn.src_ip,
                            "dst_ip": conn.dst_ip,
                            "src_port": conn.src_port,
                            "dst_port": conn.dst_port,
                            "proto": conn.proto,
                        }
                    })
                    
            elif detected_type == 'dns':
                entry = ZeekParser.parse_line(line, 'dns')
                if entry:
                    dns = normalize_zeek_dns(entry)
                    log_store._add_dns_query(dns)
                    events_ingested += 1
                    
                    # Add to recent events
                    live_ops_service.add_recent_event({
                        "id": f"dns-{dns.timestamp.isoformat()}-{dns.src_ip}",
                        "timestamp": dns.timestamp,
                        "event_type": "dns",
                        "source": "zeek",
                        "data": {
                            "src_ip": dns.src_ip,
                            "dst_ip": dns.dst_ip,
                            "query": dns.query,
                            "qtype": dns.qtype,
                        }
                    })
            else:
                logger.warning(f"Unsupported Zeek log type: {detected_type}")
                errors += 1
                
        except Exception as e:
            logger.warning(f"Failed to parse Zeek line: {e}")
            errors += 1
            continue
    
    # Record stats
    live_ops_service.record_zeek_ingest(events_ingested, bytes_received, errors)
    
    return IngestResponse(
        success=errors < len(lines),
        message=f"Ingested {events_ingested} Zeek events" + (f" ({errors} errors)" if errors > 0 else ""),
        events_ingested=events_ingested,
        errors=errors,
    )


@router.post(
    "/ingest/suricata",
    response_model=IngestResponse,
    summary="Ingest Suricata EVE JSON lines",
    description="Accept Suricata EVE JSON lines payload and parse incremental events into log store",
)
async def ingest_suricata(
    _: Annotated[str, Depends(api_key_auth)],
    payload: str = Body(..., media_type="text/plain", description="Suricata EVE JSON lines (one JSON object per line)"),
) -> IngestResponse:
    """
    Ingest Suricata EVE log events from JSON lines payload.
    
    Accepts raw JSON lines text where each line is a Suricata EVE event.
    Parses and normalizes events (flow, dns, alert) into the unified log store.
    
    Args:
        payload: Raw JSON lines text
        
    Returns:
        IngestResponse with count of ingested events
    """
    if not payload or not payload.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Empty payload",
        )
    
    lines = payload.strip().split('\n')
    events_ingested = 0
    errors = 0
    bytes_received = len(payload.encode('utf-8'))
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        try:
            entry = SuricataParser.parse_line(line)
            if not entry:
                errors += 1
                continue
            
            # Handle different event types
            if isinstance(entry, SuricataFlow):
                conn = normalize_suricata_flow(entry)
                log_store._add_connection(conn)
                events_ingested += 1
                
                live_ops_service.add_recent_event({
                    "id": conn.uid,
                    "timestamp": conn.timestamp,
                    "event_type": "conn",
                    "source": "suricata",
                    "data": {
                        "src_ip": conn.src_ip,
                        "dst_ip": conn.dst_ip,
                        "src_port": conn.src_port,
                        "dst_port": conn.dst_port,
                        "proto": conn.proto,
                    }
                })
                
            elif isinstance(entry, SuricataDns):
                dns = normalize_suricata_dns(entry)
                log_store._add_dns_query(dns)
                events_ingested += 1
                
                live_ops_service.add_recent_event({
                    "id": f"dns-{dns.timestamp.isoformat()}-{dns.src_ip}",
                    "timestamp": dns.timestamp,
                    "event_type": "dns",
                    "source": "suricata",
                    "data": {
                        "src_ip": dns.src_ip,
                        "dst_ip": dns.dst_ip,
                        "query": dns.query,
                        "qtype": dns.qtype,
                    }
                })
                
            elif isinstance(entry, SuricataAlert):
                alert = normalize_suricata_alert(entry)
                log_store._add_alert(alert)
                events_ingested += 1
                
                live_ops_service.add_recent_event({
                    "id": f"alert-{alert.timestamp.isoformat()}-{alert.signature_id}",
                    "timestamp": alert.timestamp,
                    "event_type": "alert",
                    "source": "suricata",
                    "data": {
                        "src_ip": alert.src_ip,
                        "dst_ip": alert.dst_ip,
                        "signature": alert.signature,
                        "category": alert.category,
                        "severity": alert.severity,
                    }
                })
            else:
                logger.debug(f"Skipping unsupported Suricata event type: {type(entry)}")
                
        except Exception as e:
            logger.warning(f"Failed to parse Suricata line: {e}")
            errors += 1
            continue
    
    # Record stats
    live_ops_service.record_suricata_ingest(events_ingested, bytes_received, errors)
    
    return IngestResponse(
        success=errors < len(lines),
        message=f"Ingested {events_ingested} Suricata events" + (f" ({errors} errors)" if errors > 0 else ""),
        events_ingested=events_ingested,
        errors=errors,
    )


@router.get(
    "/events",
    response_model=EventsResponse,
    summary="Get incremental events",
    description="Return merged events from conn/dns/alerts timeline since a given timestamp",
)
async def get_events(
    since: Optional[str] = Query(None, description="ISO 8601 timestamp - return events after this time"),
    limit: int = Query(500, ge=1, le=5000, description="Maximum events to return (1-5000)"),
) -> EventsResponse:
    """
    Get incremental events from the merged timeline.
    
    Returns recent events (connections, DNS queries, alerts) optionally filtered
    by a since timestamp. Used by dashboards for auto-refresh functionality.
    
    Args:
        since: ISO 8601 timestamp to filter events after
        limit: Maximum number of events to return (default 500, max 5000)
        
    Returns:
        EventsResponse with list of events
    """
    since_dt = None
    if since:
        since_dt = _parse_iso_timestamp(since)
        if since_dt is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid timestamp format: {since}. Use ISO 8601 format.",
            )
    
    # Get events from live ops service
    recent_events = live_ops_service.get_recent_events(since=since_dt, limit=limit)
    
    # Convert to EventItem models
    event_items = []
    for event in recent_events:
        try:
            event_items.append(EventItem(
                id=event.get("id", "unknown"),
                timestamp=event.get("timestamp").isoformat() if isinstance(event.get("timestamp"), datetime) else str(event.get("timestamp")),
                event_type=event.get("event_type", "unknown"),
                source=event.get("source", "unknown"),
                data=event.get("data", {}),
            ))
        except Exception as e:
            logger.warning(f"Failed to format event: {e}")
            continue
    
    return EventsResponse(
        events=event_items,
        total=len(event_items),
        since=since,
    )
