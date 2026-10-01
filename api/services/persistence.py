"""
SQLite-backed durability for the log store.

The log store keeps parsed connections/DNS queries/alerts in memory for fast
analysis. This module mirrors every write to a SQLite database on disk so that
ingested data survives a restart, and reloads it on startup. It is a pure
write-through + rehydrate backing store: the in-memory working set remains the
source of truth for queries, so analysis paths are unchanged.

Records are stored as the model's JSON so the schema is resilient to model
changes. A small key/value meta table carries counters like file_count.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from pathlib import Path
from typing import Iterable

from api.parsers.unified import Connection, DnsQuery, Alert

logger = logging.getLogger(__name__)

_TABLES = ("connections", "dns_queries", "alerts")


class LogPersistence:
    """SQLite backing store for parsed network logs (write-through + rehydrate)."""

    def __init__(self, db_path: str):
        self.db_path = str(db_path)
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        # check_same_thread=False + an explicit lock: uvicorn may run ingest on a
        # worker thread. isolation_level="" keeps Python's implicit transactions so
        # a bulk load commits once instead of per row.
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._lock = threading.Lock()
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock, self._conn:
            for table in _TABLES:
                self._conn.execute(
                    f"CREATE TABLE IF NOT EXISTS {table} "
                    "(id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT NOT NULL)"
                )
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT)"
            )

    # -- writes -------------------------------------------------------------

    def insert_connection(self, conn: Connection) -> None:
        self._insert("connections", conn.model_dump_json())

    def insert_dns_query(self, query: DnsQuery) -> None:
        self._insert("dns_queries", query.model_dump_json())

    def insert_alert(self, alert: Alert) -> None:
        self._insert("alerts", alert.model_dump_json())

    def _insert(self, table: str, payload: str) -> None:
        with self._lock, self._conn:
            self._conn.execute(f"INSERT INTO {table} (data) VALUES (?)", (payload,))

    def bulk_insert(self, table: str, models: Iterable) -> int:
        """Insert many records in a single transaction. Returns the count written."""
        rows = [(m.model_dump_json(),) for m in models]
        if not rows:
            return 0
        with self._lock, self._conn:
            self._conn.executemany(f"INSERT INTO {table} (data) VALUES (?)", rows)
        return len(rows)

    def set_meta(self, key: str, value) -> None:
        with self._lock, self._conn:
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, json.dumps(value)),
            )

    def clear(self) -> None:
        with self._lock, self._conn:
            for table in _TABLES:
                self._conn.execute(f"DELETE FROM {table}")
            self._conn.execute("DELETE FROM meta")

    # -- reads --------------------------------------------------------------

    def get_meta(self, key: str, default=None):
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key = ?", (key,)
            ).fetchone()
        return json.loads(row[0]) if row else default

    def counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        with self._lock:
            for table in _TABLES:
                counts[table] = self._conn.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0]
        return counts

    def load_all(self) -> tuple[list[Connection], list[DnsQuery], list[Alert]]:
        """Reconstruct every stored record. Malformed rows are skipped, not fatal."""
        connections: list[Connection] = []
        dns_queries: list[DnsQuery] = []
        alerts: list[Alert] = []
        with self._lock:
            for model, table, sink in (
                (Connection, "connections", connections),
                (DnsQuery, "dns_queries", dns_queries),
                (Alert, "alerts", alerts),
            ):
                for (data,) in self._conn.execute(f"SELECT data FROM {table} ORDER BY id"):
                    try:
                        sink.append(model.model_validate_json(data))
                    except Exception as exc:  # noqa: BLE001 - one bad row shouldn't nuke the load
                        logger.warning("Skipping malformed %s row: %s", table, exc)
        return connections, dns_queries, alerts

    def close(self) -> None:
        with self._lock:
            self._conn.close()
