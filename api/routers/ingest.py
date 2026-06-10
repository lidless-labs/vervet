"""
Ingest router for loading log files into Vervet.
Provides endpoints for loading directories of Zeek and Suricata logs.
"""
from fastapi import APIRouter, HTTPException, status, Depends, UploadFile, File
from pydantic import BaseModel, Field
from pathlib import Path
from typing import Optional, Annotated
import logging
import os
import json
import uuid
import shutil
import subprocess
import tempfile

from api.services.log_store import log_store
from api.dependencies.auth import api_key_auth
from api.config import settings
from api.parsers.pcap_converter import convert_tshark_json

logger = logging.getLogger(__name__)

router = APIRouter()

PCAP_MAX_SIZE_BYTES = 100 * 1024 * 1024
PCAP_TEMP_ROOT = Path(tempfile.gettempdir()) / "bro_hunter_pcaps"


class IngestDirectoryRequest(BaseModel):
    """Request model for directory ingestion."""

    path: str = Field(..., description="Absolute path to directory containing log files")


class IngestDirectoryResponse(BaseModel):
    """Response model for directory ingestion."""

    success: bool = Field(..., description="Whether ingestion succeeded")
    message: str = Field(..., description="Status message")
    stats: dict = Field(..., description="Ingestion statistics")


class IngestStats(BaseModel):
    """Detailed ingestion statistics."""

    file_count: int = Field(..., description="Number of files processed")
    record_count: int = Field(..., description="Total records loaded")
    time_range: tuple[Optional[str], Optional[str]] = Field(
        ..., description="Time range of loaded logs (min, max)"
    )
    unique_src_ips: int = Field(..., description="Number of unique source IPs")
    unique_dst_ips: int = Field(..., description="Number of unique destination IPs")
    connections: int = Field(..., description="Number of connections loaded")
    dns_queries: int = Field(..., description="Number of DNS queries loaded")
    alerts: int = Field(..., description="Number of alerts loaded")


def _validate_path(path: str) -> Path:
    """
    Validate and normalize path to prevent directory traversal attacks.

    Args:
        path: User-provided path string

    Returns:
        Normalized Path object

    Raises:
        HTTPException: If path is outside allowed root or is a symlink
    """
    # Resolve to absolute path, following symlinks
    resolved = Path(path).resolve()

    # Check if it's a symlink (security: could point outside allowed root)
    if Path(path).is_symlink():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Symbolic links are not allowed for security reasons",
        )

    # If log root is configured, enforce it
    if settings.log_root:
        log_root = Path(settings.log_root).resolve()

        # Ensure path is within allowed root
        try:
            resolved.relative_to(log_root)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: path must be within {log_root}",
            )

    return resolved


def _current_store_stats(file_count: int = 1) -> dict:
    """Build ingestion stats payload aligned with /ingest/directory."""
    return {
        "file_count": file_count,
        "record_count": len(log_store.connections) + len(log_store.dns_queries) + len(log_store.alerts),
        "time_range": (
            log_store.min_timestamp.isoformat() if log_store.min_timestamp else None,
            log_store.max_timestamp.isoformat() if log_store.max_timestamp else None,
        ),
        "unique_src_ips": len(log_store._src_ip_index),
        "unique_dst_ips": len(log_store._dst_ip_index),
        "connections": len(log_store.connections),
        "dns_queries": len(log_store.dns_queries),
        "alerts": len(log_store.alerts),
    }


@router.post(
    "/directory",
    response_model=IngestDirectoryResponse,
    summary="Ingest log directory",
    description="Load all Zeek and Suricata log files from a directory into memory for analysis",
)
async def ingest_directory(
    request: IngestDirectoryRequest,
    _: Annotated[str, Depends(api_key_auth)],
) -> IngestDirectoryResponse:
    """
    Load log files from a directory.

    This endpoint:
    1. Clears existing data
    2. Scans directory for Zeek (*.log.json) and Suricata (eve.json) files
    3. Parses and loads all supported log types
    4. Returns summary statistics

    Args:
        request: Directory path to ingest

    Returns:
        Ingestion summary with file count, record count, time range, and unique IPs

    Raises:
        HTTPException: If directory not found or ingestion fails
    """
    try:
        # Validate path to prevent traversal attacks
        validated_path = _validate_path(request.path)
        logger.info(f"Starting directory ingestion: {validated_path}")

        # Load directory
        stats = log_store.load_directory(str(validated_path))

        logger.info(f"Ingestion complete: {stats}")

        return IngestDirectoryResponse(
            success=True,
            message=f"Successfully loaded {stats['file_count']} files with {stats['record_count']} records",
            stats=stats,
        )

    except FileNotFoundError as e:
        logger.error(f"Directory not found: {e}")
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

    except ValueError as e:
        logger.error(f"Invalid directory path: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    except Exception as e:
        logger.error(f"Ingestion failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Ingestion failed: {str(e)}",
        )


@router.post(
    "/pcap",
    response_model=IngestDirectoryResponse,
    summary="Ingest PCAP file",
    description="Upload a .pcap/.pcapng file, convert via tshark, and load into memory",
)
async def ingest_pcap(
    _: Annotated[str, Depends(api_key_auth)],
    file: UploadFile = File(...),
) -> IngestDirectoryResponse:
    """Upload and ingest a single packet capture file."""
    if shutil.which("tshark") is None:
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail="tshark is not installed on this server. Install Wireshark/tshark to enable PCAP ingestion.",
        )

    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in {".pcap", ".pcapng"}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file type. Only .pcap and .pcapng are supported.",
        )

    ingest_dir = PCAP_TEMP_ROOT / str(uuid.uuid4())
    ingest_dir.mkdir(parents=True, exist_ok=True)
    pcap_path = ingest_dir / f"upload{suffix}"

    try:
        size = 0
        with pcap_path.open("wb") as f:
            while True:
                chunk = await file.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > PCAP_MAX_SIZE_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail="PCAP file exceeds maximum allowed size of 100MB.",
                    )
                f.write(chunk)

        try:
            tshark_result = subprocess.run(
                ["tshark", "-r", str(pcap_path), "-T", "json"],
                capture_output=True,
                text=True,
                check=False,
                timeout=300,
            )
        except subprocess.TimeoutExpired:
            raise HTTPException(
                status_code=status.HTTP_408_REQUEST_TIMEOUT,
                detail="tshark processing timed out after 300 seconds. The PCAP may be too large.",
            )

        if tshark_result.returncode != 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to parse PCAP with tshark: {tshark_result.stderr.strip() or 'unknown error'}",
            )

        tshark_json = json.loads(tshark_result.stdout or "[]")
        connections, dns_queries, alerts = convert_tshark_json(tshark_json)

        log_store.clear()
        for conn in connections:
            log_store._add_connection(conn)
        for query in dns_queries:
            log_store._add_dns_query(query)
        for alert in alerts:
            log_store._add_alert(alert)

        log_store.file_count = 1
        log_store.total_records = len(connections) + len(dns_queries) + len(alerts)

        stats = _current_store_stats(file_count=1)
        return IngestDirectoryResponse(
            success=True,
            message=f"Successfully loaded 1 file with {stats['record_count']} records",
            stats=stats,
        )

    except json.JSONDecodeError as e:
        logger.error("Invalid tshark JSON output", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not decode tshark output: {e}",
        ) from e
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"PCAP ingestion failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PCAP ingestion failed: {e!s}",
        ) from e
    finally:
        await file.close()
        shutil.rmtree(ingest_dir, ignore_errors=True)


@router.post(
    "/clear",
    summary="Clear log store",
    description="Clear all loaded logs from memory",
)
async def clear_logs(
    _: Annotated[str, Depends(api_key_auth)],
) -> dict:
    """
    Clear all loaded logs from the in-memory store.

    Returns:
        Success message
    """
    try:
        log_store.clear()
        logger.info("Log store cleared")

        return {
            "success": True,
            "message": "Log store cleared successfully",
        }

    except Exception as e:
        logger.error(f"Failed to clear log store: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to clear logs: {str(e)}",
        )


@router.get(
    "/status",
    summary="Get ingestion status",
    description="Get current status of the log store (loaded data summary)",
)
async def get_status(
    _: Annotated[str, Depends(api_key_auth)],
) -> dict:
    """
    Get current log store status.

    Returns:
        Dictionary with store statistics
    """
    time_range = log_store.get_time_range()

    return {
        "loaded": log_store.total_records > 0,
        "file_count": log_store.file_count,
        "total_records": log_store.total_records,
        "connections": len(log_store.connections),
        "dns_queries": len(log_store.dns_queries),
        "alerts": len(log_store.alerts),
        "time_range": {
            "start": time_range[0].isoformat() if time_range[0] else None,
            "end": time_range[1].isoformat() if time_range[1] else None,
        },
        "unique_ips": {
            "sources": len(log_store._src_ip_index),
            "destinations": len(log_store._dst_ip_index),
        },
    }
