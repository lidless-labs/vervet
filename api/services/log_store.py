"""
In-memory log store service for Vervet.
Provides efficient querying and filtering of parsed network logs.
"""
from pathlib import Path
from typing import Optional, Union
from datetime import datetime
from collections import defaultdict
import logging

from api.parsers.zeek_parser import ZeekParser
from api.parsers.suricata_parser import SuricataParser
from api.parsers.unified import (
    Connection,
    DnsQuery,
    Alert,
    normalize_zeek_conn,
    normalize_zeek_dns,
    normalize_suricata_flow,
    normalize_suricata_dns,
    normalize_suricata_alert,
)
from api.models.zeek import ConnLog, DnsLog
from api.models.suricata import SuricataAlert, SuricataFlow, SuricataDns

logger = logging.getLogger(__name__)


class LogStore:
    """
    In-memory store for parsed network logs.
    Stores connections, DNS queries, and alerts with efficient filtering.
    """

    def __init__(self):
        """Initialize empty log store."""
        self.connections: list[Connection] = []
        self.dns_queries: list[DnsQuery] = []
        self.alerts: list[Alert] = []

        # Metadata
        self.file_count = 0
        self.total_records = 0
        self.min_timestamp: Optional[datetime] = None
        self.max_timestamp: Optional[datetime] = None

        # Index for fast IP lookups
        self._src_ip_index: dict[str, list[int]] = defaultdict(list)
        self._dst_ip_index: dict[str, list[int]] = defaultdict(list)

        # Optional durable backing store (attached at startup for non-demo runs).
        # When present, every write is mirrored to disk and reloaded on restart.
        self._persistence = None
        # When True, per-record writes skip persistence (a bulk load persists once
        # at the end instead of committing per row).
        self._deferred = False

    def attach_persistence(self, persistence) -> None:
        """Attach a durable backing store (see api.services.persistence)."""
        self._persistence = persistence

    def rehydrate(self) -> None:
        """Reload the in-memory store from the persistence backend, if attached."""
        if not self._persistence:
            return
        connections, dns_queries, alerts = self._persistence.load_all()
        for conn in connections:
            self._add_connection(conn, persist=False)
        for query in dns_queries:
            self._add_dns_query(query, persist=False)
        for alert in alerts:
            self._add_alert(alert, persist=False)
        self.file_count = self._persistence.get_meta("file_count", 0) or 0
        self.total_records = len(connections) + len(dns_queries) + len(alerts)
        if self.total_records:
            logger.info(
                "Rehydrated %d records from %s",
                self.total_records,
                self._persistence.db_path,
            )

    def clear(self):
        """Clear all stored logs."""
        self.connections.clear()
        self.dns_queries.clear()
        self.alerts.clear()
        self._src_ip_index.clear()
        self._dst_ip_index.clear()

        self.file_count = 0
        self.total_records = 0
        self.min_timestamp = None
        self.max_timestamp = None

        if self._persistence:
            self._persistence.clear()

        logger.info("Log store cleared")

    def load_directory(self, directory_path: Union[str, Path]) -> dict:
        """
        Load all log files from a directory.

        Args:
            directory_path: Path to directory containing log files

        Returns:
            Dictionary with summary statistics:
            - file_count: Number of files processed
            - record_count: Total records loaded
            - time_range: (min_timestamp, max_timestamp)
            - unique_src_ips: Number of unique source IPs
            - unique_dst_ips: Number of unique destination IPs
        """
        directory_path = Path(directory_path)

        if not directory_path.exists():
            raise FileNotFoundError(f"Directory not found: {directory_path}")

        if not directory_path.is_dir():
            raise ValueError(f"Not a directory: {directory_path}")

        logger.info(f"Loading logs from directory: {directory_path}")

        # Clear existing data (also clears the backing store, if attached)
        self.clear()
        # Defer per-record persistence; the whole set is written once at the end.
        self._deferred = True

        files_processed = 0
        records_loaded = 0

        # Find all log files
        zeek_files = list(directory_path.glob("*.log.json")) + list(directory_path.glob("*.log"))
        suricata_files = list(directory_path.glob("eve.json"))

        # Process Zeek logs
        for file_path in zeek_files:
            try:
                log_type = ZeekParser.detect_log_type(file_path.name)

                if log_type == "conn":
                    for entry in ZeekParser.parse_file(file_path, log_type="conn"):
                        conn = normalize_zeek_conn(entry)
                        self._add_connection(conn)
                        records_loaded += 1

                elif log_type == "dns":
                    for entry in ZeekParser.parse_file(file_path, log_type="dns"):
                        query = normalize_zeek_dns(entry)
                        self._add_dns_query(query)
                        records_loaded += 1

                # Other Zeek log types can be added here as needed
                else:
                    logger.debug(f"Skipping non-core Zeek log type: {log_type}")
                    continue

                files_processed += 1
                logger.info(f"Loaded {file_path.name}: {log_type}")

            except Exception as e:
                logger.error(f"Error loading {file_path}: {e}")
                continue

        # Process Suricata logs
        for file_path in suricata_files:
            try:
                for entry in SuricataParser.parse_file(file_path):
                    if isinstance(entry, SuricataFlow):
                        conn = normalize_suricata_flow(entry)
                        self._add_connection(conn)
                        records_loaded += 1

                    elif isinstance(entry, SuricataDns):
                        query = normalize_suricata_dns(entry)
                        self._add_dns_query(query)
                        records_loaded += 1

                    elif isinstance(entry, SuricataAlert):
                        alert = normalize_suricata_alert(entry)
                        self._add_alert(alert)
                        records_loaded += 1

                files_processed += 1
                logger.info(f"Loaded {file_path.name}: suricata")

            except Exception as e:
                logger.error(f"Error loading {file_path}: {e}")
                continue

        self._deferred = False
        self.file_count = files_processed
        self.total_records = records_loaded

        # Persist the freshly loaded set in one batch. clear() already emptied the
        # backing store, so this replaces any prior data rather than appending.
        if self._persistence:
            self._persistence.bulk_insert("connections", self.connections)
            self._persistence.bulk_insert("dns_queries", self.dns_queries)
            self._persistence.bulk_insert("alerts", self.alerts)
            self._persistence.set_meta("file_count", self.file_count)

        logger.info(
            f"Loaded {files_processed} files, {records_loaded} records. "
            f"Time range: {self.min_timestamp} to {self.max_timestamp}"
        )

        return {
            "file_count": files_processed,
            "record_count": records_loaded,
            "time_range": (
                self.min_timestamp.isoformat() if self.min_timestamp else None,
                self.max_timestamp.isoformat() if self.max_timestamp else None,
            ),
            "unique_src_ips": len(self._src_ip_index),
            "unique_dst_ips": len(self._dst_ip_index),
            "connections": len(self.connections),
            "dns_queries": len(self.dns_queries),
            "alerts": len(self.alerts),
        }

    def _add_connection(self, conn: Connection, persist: bool = True):
        """Add connection to store and update indices."""
        idx = len(self.connections)
        self.connections.append(conn)

        # Update IP indices
        self._src_ip_index[conn.src_ip].append(idx)
        self._dst_ip_index[conn.dst_ip].append(idx)

        # Update timestamp range
        self._update_time_range(conn.timestamp)

        if persist and self._persistence and not self._deferred:
            self._persistence.insert_connection(conn)

    def _add_dns_query(self, query: DnsQuery, persist: bool = True):
        """Add DNS query to store."""
        self.dns_queries.append(query)
        self._update_time_range(query.timestamp)

        if persist and self._persistence and not self._deferred:
            self._persistence.insert_dns_query(query)

    def _add_alert(self, alert: Alert, persist: bool = True):
        """Add alert to store."""
        self.alerts.append(alert)
        self._update_time_range(alert.timestamp)

        if persist and self._persistence and not self._deferred:
            self._persistence.insert_alert(alert)

    def _update_time_range(self, timestamp: datetime):
        """Update min/max timestamp range."""
        if self.min_timestamp is None or timestamp < self.min_timestamp:
            self.min_timestamp = timestamp
        if self.max_timestamp is None or timestamp > self.max_timestamp:
            self.max_timestamp = timestamp

    def get_connections(
        self,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        port: Optional[int] = None,
        proto: Optional[str] = None,
        service: Optional[str] = None,
        min_duration: Optional[float] = None,
        time_start: Optional[datetime] = None,
        time_end: Optional[datetime] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> list[Connection]:
        """
        Get connections with optional filters.

        Args:
            src_ip: Filter by source IP
            dst_ip: Filter by destination IP
            port: Filter by source or destination port
            proto: Filter by protocol
            service: Filter by service
            min_duration: Filter by minimum duration
            time_start: Filter by start time
            time_end: Filter by end time
            limit: Maximum number of results
            offset: Skip first N results

        Returns:
            List of matching connections
        """
        # Use IP index for fast lookup if available
        if src_ip and not any([dst_ip, port, proto, service, min_duration, time_start, time_end]):
            indices = self._src_ip_index.get(src_ip, [])
            results = [self.connections[i] for i in indices]
        elif dst_ip and not any([src_ip, port, proto, service, min_duration, time_start, time_end]):
            indices = self._dst_ip_index.get(dst_ip, [])
            results = [self.connections[i] for i in indices]
        else:
            # Full scan with filters
            results = self.connections

            if src_ip:
                results = [c for c in results if c.src_ip == src_ip]
            if dst_ip:
                results = [c for c in results if c.dst_ip == dst_ip]
            if port:
                results = [c for c in results if c.src_port == port or c.dst_port == port]
            if proto:
                results = [c for c in results if c.proto == proto.lower()]
            if service:
                results = [c for c in results if c.service == service]
            if min_duration is not None:
                results = [c for c in results if c.duration and c.duration >= min_duration]
            if time_start:
                results = [c for c in results if c.timestamp >= time_start]
            if time_end:
                results = [c for c in results if c.timestamp <= time_end]

        # Apply pagination
        if offset:
            results = results[offset:]
        if limit:
            results = results[:limit]

        return results

    def get_dns_queries(
        self,
        src_ip: Optional[str] = None,
        query: Optional[str] = None,
        qtype: Optional[str] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> list[DnsQuery]:
        """
        Get DNS queries with optional filters.

        Args:
            src_ip: Filter by source IP
            query: Filter by query domain (substring match)
            qtype: Filter by query type
            limit: Maximum number of results
            offset: Skip first N results

        Returns:
            List of matching DNS queries
        """
        results = self.dns_queries

        if src_ip:
            results = [q for q in results if q.src_ip == src_ip]
        if query:
            results = [q for q in results if query.lower() in q.query.lower()]
        if qtype:
            results = [q for q in results if q.qtype == qtype]

        # Apply pagination
        if offset:
            results = results[offset:]
        if limit:
            results = results[:limit]

        return results

    def get_alerts(
        self,
        severity: Optional[int] = None,
        category: Optional[str] = None,
        limit: Optional[int] = None,
        offset: int = 0,
    ) -> list[Alert]:
        """
        Get alerts with optional filters.

        Args:
            severity: Filter by severity level
            category: Filter by category
            limit: Maximum number of results
            offset: Skip first N results

        Returns:
            List of matching alerts
        """
        results = self.alerts

        if severity is not None:
            results = [a for a in results if a.severity == severity]
        if category:
            results = [a for a in results if category.lower() in a.category.lower()]

        # Apply pagination
        if offset:
            results = results[offset:]
        if limit:
            results = results[:limit]

        return results

    def get_time_range(self) -> tuple[Optional[datetime], Optional[datetime]]:
        """
        Get time range of loaded logs.

        Returns:
            Tuple of (min_timestamp, max_timestamp)
        """
        return (self.min_timestamp, self.max_timestamp)

    def get_unique_ips(self) -> dict[str, list[str]]:
        """
        Get unique IP addresses.

        Returns:
            Dictionary with 'sources' and 'destinations' lists
        """
        return {
            "sources": list(self._src_ip_index.keys()),
            "destinations": list(self._dst_ip_index.keys()),
        }


# Global instance
log_store = LogStore()
