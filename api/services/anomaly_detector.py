"""Statistical anomaly detection engine for Vervet."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from math import log2
from typing import Any
from uuid import uuid4
import ipaddress

import numpy as np

from api.services.log_store import LogStore
from api.services.baseline_profiler import BaselineProfiler


class AnomalyDetector:
    """Detect anomalies using fast, lightweight statistical methods."""

    def __init__(self, store: LogStore, baseline_profiler: BaselineProfiler):
        self.store = store
        self.baseline_profiler = baseline_profiler
        self._anomalies: list[dict[str, Any]] = []

    @staticmethod
    def _to_ts(value: Any) -> float:
        if isinstance(value, datetime):
            return value.timestamp()
        return float(value or 0.0)

    @staticmethod
    def _entropy(value: str) -> float:
        if not value:
            return 0.0
        counts = Counter(value)
        length = len(value)
        return -sum((count / length) * log2(count / length) for count in counts.values())

    @staticmethod
    def _severity_from_sigma(sigma: float) -> str:
        if sigma >= 4:
            return "critical"
        if sigma >= 3:
            return "high"
        if sigma >= 2:
            return "medium"
        return "low"

    @staticmethod
    def _is_external(ip: str) -> bool:
        try:
            return not ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def _make_anomaly(
        self,
        anomaly_type: str,
        description: str,
        severity: str,
        evidence: dict[str, Any],
        affected_hosts: list[str] | None = None,
        affected_connections: list[str] | None = None,
        mitre_techniques: list[str] | None = None,
    ) -> dict[str, Any]:
        return {
            "id": str(uuid4()),
            "type": anomaly_type,
            "severity": severity,
            "description": description,
            "evidence": evidence,
            "affected_hosts": affected_hosts or [],
            "affected_connections": affected_connections or [],
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "mitre_techniques": mitre_techniques or [],
        }

    def _volume_anomalies(self, baseline: dict[str, Any]) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        buckets: dict[int, dict[str, float]] = defaultdict(lambda: {"bytes": 0.0, "connections": 0.0})

        for conn in self.store.connections:
            ts = int(self._to_ts(conn.timestamp) // 300)
            buckets[ts]["bytes"] += float((conn.bytes_sent or 0) + (conn.bytes_recv or 0))
            buckets[ts]["connections"] += 1

        if not buckets:
            return anomalies

        byte_values = np.array([b["bytes"] for b in buckets.values()], dtype=float)
        conn_values = np.array([b["connections"] for b in buckets.values()], dtype=float)
        byte_mean = baseline["traffic_volume"].get("bytes_per_hour_mean", 0.0)
        byte_std = max(1.0, baseline["traffic_volume"].get("bytes_per_hour_std", 0.0))
        conn_mean = baseline["traffic_volume"].get("connections_per_hour_mean", 0.0)
        conn_std = max(1.0, baseline["traffic_volume"].get("connections_per_hour_std", 0.0))

        for idx, bucket in enumerate(buckets.items()):
            bucket_id, data = bucket
            sigma_bytes = abs((data["bytes"] - byte_mean) / byte_std)
            sigma_conns = abs((data["connections"] - conn_mean) / conn_std)
            sigma = max(sigma_bytes, sigma_conns)
            if sigma > 2:
                anomalies.append(
                    self._make_anomaly(
                        "volume",
                        f"Volume spike in bucket {bucket_id}",
                        self._severity_from_sigma(sigma),
                        {
                            "metric": "bucket_volume",
                            "bytes": data["bytes"],
                            "connections": data["connections"],
                            "baseline_bytes": byte_mean,
                            "baseline_connections": conn_mean,
                            "deviation": float(sigma),
                            "z_bytes": float(sigma_bytes),
                            "z_connections": float(sigma_conns),
                        },
                        mitre_techniques=["T1499"],
                    )
                )
            if idx > 200:
                break

        return anomalies

    def _protocol_anomalies(self, baseline: dict[str, Any]) -> list[dict[str, Any]]:
        current_counts = Counter((c.proto or "unknown").lower() for c in self.store.connections)
        total = max(1, len(self.store.connections))
        baseline_dist = baseline.get("protocol_distribution", {})

        chi_sq = 0.0
        for proto in set(current_counts.keys()) | set(baseline_dist.keys()):
            observed = current_counts.get(proto, 0)
            expected = baseline_dist.get(proto, 0.0) * total
            if expected > 0:
                chi_sq += ((observed - expected) ** 2) / expected

        if chi_sq <= 10:
            return []

        return [
            self._make_anomaly(
                "protocol",
                "Protocol distribution diverges from baseline",
                "medium" if chi_sq < 20 else "high",
                {
                    "metric": "chi_squared",
                    "value": float(chi_sq),
                    "baseline": baseline_dist,
                    "current": {k: v / total for k, v in current_counts.items()},
                    "deviation": float(chi_sq),
                },
                mitre_techniques=["T1071"],
            )
        ]

    def _port_anomalies(self, baseline: dict[str, Any]) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        baseline_ports = {p["port"] for p in baseline.get("port_profile", {}).get("top_dst_ports", [])}
        current_ports = Counter(int(c.dst_port or 0) for c in self.store.connections)

        new_ports = [p for p in current_ports if p not in baseline_ports]
        if new_ports:
            top_new = sorted(new_ports, key=lambda p: current_ports[p], reverse=True)[:10]
            anomalies.append(
                self._make_anomaly(
                    "port",
                    f"Detected {len(new_ports)} destination ports not present in baseline",
                    "medium",
                    {
                        "metric": "new_ports",
                        "value": top_new,
                        "baseline": sorted(list(baseline_ports))[:20],
                        "deviation": float(len(new_ports)),
                    },
                    mitre_techniques=["T1046"],
                )
            )

        for port, count in current_ports.items():
            if port in baseline_ports and count > max(20, len(self.store.connections) * 0.2):
                anomalies.append(
                    self._make_anomaly(
                        "port",
                        f"Port {port} usage spike",
                        "low",
                        {"metric": "port_spike", "value": count, "baseline": "normal", "deviation": float(count)},
                    )
                )
                break

        return anomalies

    def _dns_anomalies(self) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        dns_queries = self.store.dns_queries
        if not dns_queries:
            return anomalies

        lengths = np.array([len((q.query or "")) for q in dns_queries], dtype=float)
        mean_len = float(np.mean(lengths))
        std_len = float(np.std(lengths)) if float(np.std(lengths)) > 0 else 1.0
        per_host = Counter(q.src_ip for q in dns_queries)

        for query in dns_queries[:500]:
            qname = (query.query or "").lower()
            z = abs((len(qname) - mean_len) / std_len)
            entropy = self._entropy(qname.split(".")[0])
            if z > 3 or entropy > 3.5:
                anomalies.append(
                    self._make_anomaly(
                        "dns",
                        f"Suspicious DNS query: {qname}",
                        "high" if entropy > 4.0 else "medium",
                        {
                            "metric": "dns_query_anomaly",
                            "value": qname,
                            "baseline": {"mean_length": mean_len},
                            "deviation": float(max(z, entropy)),
                            "zscore": float(z),
                            "entropy": float(entropy),
                        },
                        affected_hosts=[query.src_ip],
                        mitre_techniques=["T1071.004"],
                    )
                )

        if per_host:
            host_values = np.array(list(per_host.values()), dtype=float)
            host_mean = float(np.mean(host_values))
            host_std = float(np.std(host_values)) if float(np.std(host_values)) > 0 else 1.0
            for ip, count in per_host.items():
                z = (count - host_mean) / host_std
                if z > 3:
                    anomalies.append(
                        self._make_anomaly(
                            "dns",
                            f"Unusual DNS query volume from host {ip}",
                            "medium",
                            {
                                "metric": "host_dns_volume",
                                "value": count,
                                "baseline": host_mean,
                                "deviation": float(z),
                            },
                            affected_hosts=[ip],
                        )
                    )

        return anomalies

    def _behavioral_and_host_anomalies(self, baseline: dict[str, Any]) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        baseline_hosts = {h["ip"] for h in baseline.get("host_profile", {}).get("top_talkers", [])}
        duration_mean = baseline.get("duration_stats", {}).get("mean", 0.0)
        duration_std = max(1.0, baseline.get("duration_stats", {}).get("std", 0.0))

        host_destinations: dict[str, set[str]] = defaultdict(set)
        host_protocols: dict[str, set[str]] = defaultdict(set)

        for conn in self.store.connections:
            host_destinations[conn.src_ip].add(conn.dst_ip)
            host_protocols[conn.src_ip].add((conn.proto or "unknown").lower())

            if self._is_external(conn.dst_ip) and conn.dst_ip not in baseline_hosts:
                anomalies.append(
                    self._make_anomaly(
                        "behavioral",
                        f"New external host observed: {conn.dst_ip}",
                        "low",
                        {"metric": "new_external_host", "value": conn.dst_ip, "baseline": "known hosts", "deviation": 1.0},
                        affected_hosts=[conn.src_ip, conn.dst_ip],
                        affected_connections=[conn.uid],
                        mitre_techniques=["T1046"],
                    )
                )

            duration = float(conn.duration or 0.0)
            z_duration = abs((duration - duration_mean) / duration_std)
            if z_duration > 3:
                anomalies.append(
                    self._make_anomaly(
                        "behavioral",
                        "Connection duration outlier detected",
                        "medium",
                        {
                            "metric": "duration",
                            "value": duration,
                            "baseline": duration_mean,
                            "deviation": float(z_duration),
                        },
                        affected_hosts=[conn.src_ip, conn.dst_ip],
                        affected_connections=[conn.uid],
                    )
                )

            sent = float(conn.bytes_sent or 0)
            recv = float(conn.bytes_recv or 0)
            if sent > 0 and recv > 0:
                ratio = max(sent / recv, recv / sent)
                if ratio > 25:
                    anomalies.append(
                        self._make_anomaly(
                            "behavioral",
                            "Asymmetric transfer ratio anomaly",
                            "medium",
                            {"metric": "byte_ratio", "value": ratio, "baseline": "~1.0-10.0", "deviation": ratio},
                            affected_hosts=[conn.src_ip, conn.dst_ip],
                            affected_connections=[conn.uid],
                            mitre_techniques=["T1041"],
                        )
                    )

        for host, dsts in host_destinations.items():
            if len(dsts) > 50:
                anomalies.append(
                    self._make_anomaly(
                        "host",
                        f"Host {host} high fan-out behavior",
                        "high",
                        {"metric": "fan_out", "value": len(dsts), "baseline": "< 50", "deviation": float(len(dsts))},
                        affected_hosts=[host],
                        mitre_techniques=["T1021"],
                    )
                )

        return anomalies

    def _temporal_anomalies(self) -> list[dict[str, Any]]:
        anomalies: list[dict[str, Any]] = []
        if not self.store.connections:
            return anomalies

        hour_counts = Counter()
        bucket_counts = Counter()
        for conn in self.store.connections:
            ts = datetime.fromtimestamp(self._to_ts(conn.timestamp), tz=timezone.utc)
            hour_counts[ts.hour] += 1
            bucket_counts[int(self._to_ts(conn.timestamp) // 300)] += 1

        # Activity outside normal hours (simple heuristic)
        off_hours = sum(v for h, v in hour_counts.items() if h < 6 or h > 21)
        total = sum(hour_counts.values())
        if total > 0 and (off_hours / total) > 0.35:
            anomalies.append(
                self._make_anomaly(
                    "temporal",
                    "Elevated off-hours activity detected",
                    "medium",
                    {
                        "metric": "off_hours_ratio",
                        "value": off_hours / total,
                        "baseline": 0.2,
                        "deviation": (off_hours / total) - 0.2,
                    },
                    mitre_techniques=["T1071"],
                )
            )

        values = np.array(list(bucket_counts.values()), dtype=float)
        mean = float(np.mean(values))
        std = float(np.std(values)) if float(np.std(values)) > 0 else 1.0
        for bucket, count in bucket_counts.items():
            z = (count - mean) / std
            if z > 3:
                anomalies.append(
                    self._make_anomaly(
                        "temporal",
                        f"Traffic burst detected in bucket {bucket}",
                        self._severity_from_sigma(float(z)),
                        {"metric": "burst", "value": count, "baseline": mean, "deviation": float(z)},
                    )
                )

        return anomalies

    def detect(self) -> dict[str, Any]:
        baseline = self.baseline_profiler.current_baseline or self.baseline_profiler._load_from_disk()
        if not baseline:
            baseline = self.baseline_profiler.build_baseline()

        anomalies: list[dict[str, Any]] = []
        anomalies.extend(self._volume_anomalies(baseline))
        anomalies.extend(self._protocol_anomalies(baseline))
        anomalies.extend(self._port_anomalies(baseline))
        anomalies.extend(self._dns_anomalies())
        anomalies.extend(self._behavioral_and_host_anomalies(baseline))
        anomalies.extend(self._temporal_anomalies())

        # Keep payload manageable and deterministic for UI rendering.
        anomalies = anomalies[:500]
        self._anomalies = anomalies

        severity_counts = Counter(a["severity"] for a in anomalies)
        type_counts = Counter(a["type"] for a in anomalies)

        return {
            "total": len(anomalies),
            "by_severity": dict(severity_counts),
            "by_type": dict(type_counts),
            "anomalies": anomalies,
        }

    def list_anomalies(self) -> list[dict[str, Any]]:
        return self._anomalies

    def get_anomaly(self, anomaly_id: str) -> dict[str, Any] | None:
        for anomaly in self._anomalies:
            if anomaly["id"] == anomaly_id:
                return anomaly
        return None


anomaly_detector: AnomalyDetector | None = None
