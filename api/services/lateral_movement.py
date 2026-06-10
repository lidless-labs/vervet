"""
Lateral movement detection service.
Identifies internal-to-internal connections on SMB, RDP, WMI, SSH.
Flags credential spray patterns and multi-target scanning.
"""
import ipaddress
import random
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Optional

LATERAL_PORTS = {
    445: "SMB",
    3389: "RDP",
    135: "WMI/DCOM",
    22: "SSH",
    5985: "WinRM",
    5986: "WinRM-SSL",
    139: "NetBIOS",
}


@dataclass
class LateralDetection:
    src_ip: str
    targets: list[dict] = field(default_factory=list)  # [{ip, port, service, ts}]
    target_count: int = 0
    services_used: list[str] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    timespan_minutes: float = 0
    risk_score: float = 0.0
    risk_level: str = "low"
    pattern: str = "unknown"
    mitre: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class LateralMovementDetector:
    def __init__(self):
        self.detections: list[LateralDetection] = []

    def analyze(self, connections: list[dict] | None = None) -> list[LateralDetection]:
        if connections is None:
            return self.detections

        # Group by source IP
        by_source: dict[str, list[dict]] = {}
        for conn in connections:
            src = conn.get("src_ip", "")
            if not self._is_internal(src):
                continue
            dst = conn.get("dst_ip", "")
            if not self._is_internal(dst):
                continue
            port = conn.get("dst_port", 0)
            if port not in LATERAL_PORTS:
                continue
            by_source.setdefault(src, []).append(conn)

        detections = []
        for src_ip, conns in by_source.items():
            unique_targets = {c["dst_ip"] for c in conns}
            if len(unique_targets) < 2:
                continue

            services = list({LATERAL_PORTS.get(c["dst_port"], "Unknown") for c in conns})
            timestamps = sorted(c.get("ts", "") for c in conns)
            targets = [
                {"ip": c["dst_ip"], "port": c["dst_port"],
                 "service": LATERAL_PORTS.get(c["dst_port"], "Unknown"),
                 "ts": c.get("ts", "")}
                for c in conns
            ]

            try:
                first = datetime.fromisoformat(timestamps[0])
                last = datetime.fromisoformat(timestamps[-1])
                timespan = (last - first).total_seconds() / 60
            except (ValueError, IndexError):
                timespan = 0

            # Risk scoring
            risk = 0.0
            pattern_parts = []
            mitre = []

            # Multi-target
            target_count = len(unique_targets)
            if target_count >= 10:
                risk += 40
                pattern_parts.append("mass_scan")
            elif target_count >= 5:
                risk += 25
                pattern_parts.append("multi_target")
            else:
                risk += 10

            # Speed
            if timespan > 0 and target_count / (timespan + 0.01) > 0.5:
                risk += 20
                pattern_parts.append("rapid")

            # Multiple services
            if len(services) >= 3:
                risk += 15
                pattern_parts.append("multi_service")
                mitre.append("T1021 - Remote Services")

            # Specific service risks
            if "SMB" in services:
                risk += 10
                mitre.append("T1021.002 - SMB/Windows Admin Shares")
            if "RDP" in services:
                risk += 10
                mitre.append("T1021.001 - Remote Desktop Protocol")
            if "WMI/DCOM" in services:
                risk += 15
                mitre.append("T1047 - Windows Management Instrumentation")

            if not mitre:
                mitre.append("T1570 - Lateral Tool Transfer")

            risk = min(risk, 100)
            if risk >= 70:
                risk_level = "critical"
            elif risk >= 50:
                risk_level = "high"
            elif risk >= 30:
                risk_level = "medium"
            else:
                risk_level = "low"

            detection = LateralDetection(
                src_ip=src_ip,
                targets=targets,
                target_count=target_count,
                services_used=services,
                first_seen=timestamps[0] if timestamps else "",
                last_seen=timestamps[-1] if timestamps else "",
                timespan_minutes=round(timespan, 1),
                risk_score=round(risk, 1),
                risk_level=risk_level,
                pattern="_".join(pattern_parts) if pattern_parts else "low_volume",
                mitre=mitre,
            )
            detections.append(detection)

        self.detections = sorted(detections, key=lambda d: -d.risk_score)
        return self.detections

    def get_stats(self) -> dict:
        total = len(self.detections)
        levels = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        total_hosts = set()
        patterns = {}
        for d in self.detections:
            levels[d.risk_level] = levels.get(d.risk_level, 0) + 1
            total_hosts.add(d.src_ip)
            for t in d.targets:
                total_hosts.add(t["ip"])
            patterns[d.pattern] = patterns.get(d.pattern, 0) + 1
        return {
            "total_detections": total,
            "hosts_involved": len(total_hosts),
            "risk_levels": levels,
            "patterns": patterns,
        }

    def _is_internal(self, ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def generate_demo_data(self) -> list[LateralDetection]:
        now = datetime.now()
        connections = []
        # Attacker doing mass scan
        for _ in range(25):
            connections.append({
                "src_ip": "198.19.1.105",
                "dst_ip": f"198.19.1.{random.randint(1,254)}",
                "dst_port": random.choice([445, 3389, 135]),
                "ts": (now - timedelta(minutes=random.randint(1, 30))).isoformat(),
            })
        # Moderate lateral movement
        for _ in range(8):
            connections.append({
                "src_ip": "198.19.2.50",
                "dst_ip": f"198.19.2.{random.choice([10,20,30,40,50])}",
                "dst_port": random.choice([445, 22]),
                "ts": (now - timedelta(minutes=random.randint(30, 120))).isoformat(),
            })
        # Normal admin
        for _ in range(3):
            connections.append({
                "src_ip": "198.19.1.10",
                "dst_ip": f"198.19.1.{random.choice([20,21])}",
                "dst_port": 22,
                "ts": (now - timedelta(minutes=random.randint(60, 480))).isoformat(),
            })

        self.analyze(connections)
        return self.detections


lateral_detector = LateralMovementDetector()
