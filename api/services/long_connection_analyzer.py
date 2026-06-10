"""
Long Connection Analysis Engine

Detects suspicious long-duration connections that may indicate:
- Data exfiltration (slow and steady data transfer)
- Persistent backdoor/RAT connections
- Covert channels
- Tunneling protocols

Scoring methodology:
- Duration (longer = more suspicious for certain protocols)
- Data transfer characteristics (volume, direction)
- Protocol context (some protocols shouldn't be long-lived)
- Destination reputation (external IPs, unusual ports)
"""

import ipaddress
from typing import List, Dict, Set
from dataclasses import dataclass
from collections import defaultdict

from api.parsers.unified import Connection
from api.models.threat import ThreatLevel, MitreMapping
from api.config.mitre_framework import mitre_framework


@dataclass
class LongConnectionResult:
    """Result of long connection analysis."""
    connection: Connection
    duration_seconds: float
    score: float  # 0-100
    confidence: float  # 0-1
    threat_level: ThreatLevel
    reasons: List[str]
    indicators: List[str]
    mitre_techniques: List[str]
    mitre_mappings: List[MitreMapping]

    # Detailed metrics
    bytes_per_second: float
    is_bidirectional: bool
    data_ratio: float  # sent/received ratio


# Protocol-specific duration thresholds (seconds)
PROTOCOL_DURATION_THRESHOLDS = {
    # HTTP/HTTPS should be short-lived (unless streaming)
    "http": 300,      # 5 minutes
    "https": 300,

    # DNS should be very short
    "dns": 5,         # 5 seconds

    # SSH can be long but sustained data transfer is suspicious
    "ssh": 3600,      # 1 hour

    # Database connections can be long
    "mysql": 7200,    # 2 hours
    "postgres": 7200,

    # SMB/CIFS
    "smb": 1800,      # 30 minutes

    # Default for unknown protocols
    "default": 1800,  # 30 minutes
}

# Bytes per second thresholds for sustained transfer
SUSTAINED_TRANSFER_THRESHOLD = 1024  # 1 KB/s minimum for exfil

# Non-routable / private IP ranges used in documentation and fixtures.
PRIVATE_IP_RANGES = [
    ("198.18.0.0", "198.19.255.255"),
    ("192.0.2.0", "192.0.2.255"),
    ("198.51.100.0", "198.51.100.255"),
    ("203.0.113.0", "203.0.113.255"),
    ("127.0.0.0", "127.255.255.255"),
]


class LongConnectionAnalyzer:
    """
    Analyzes connection duration and data transfer patterns to detect:
    - Data exfiltration
    - Persistent backdoors
    - Covert channels
    - Protocol misuse

    Maps detections to MITRE ATT&CK techniques:
    - T1041: Exfiltration Over C2 Channel
    - T1030: Data Transfer Size Limits
    - T1029: Scheduled Transfer
    - T1071: Application Layer Protocol (misuse)
    """

    def __init__(
        self,
        min_duration_seconds: float = 300.0,  # 5 minutes minimum
        min_score_threshold: float = 50.0,
        sustained_transfer_threshold: float = SUSTAINED_TRANSFER_THRESHOLD,
    ):
        """
        Initialize the analyzer.

        Args:
            min_duration_seconds: Minimum duration to analyze
            min_score_threshold: Minimum score to report
            sustained_transfer_threshold: Bytes/sec for "sustained transfer"
        """
        self.min_duration = min_duration_seconds
        self.min_score_threshold = min_score_threshold
        self.sustained_threshold = sustained_transfer_threshold

    def analyze_connections(
        self,
        connections: List[Connection],
    ) -> List[LongConnectionResult]:
        """
        Analyze connections for suspicious long-duration patterns.

        Args:
            connections: List of connections to analyze

        Returns:
            List of suspicious long connections with scores
        """
        results = []

        for conn in connections:
            # Skip if duration is None or too short
            if not conn.duration or conn.duration < self.min_duration:
                continue

            result = self._analyze_connection(conn)
            if result and result.score >= self.min_score_threshold:
                results.append(result)

        # Sort by score descending
        results.sort(key=lambda x: x.score, reverse=True)
        return results

    def _analyze_connection(self, conn: Connection) -> LongConnectionResult:
        """Analyze a single long connection."""
        duration = conn.duration or 0.0
        bytes_sent = conn.bytes_sent or 0
        bytes_recv = conn.bytes_recv or 0
        total_bytes = bytes_sent + bytes_recv

        # Calculate metrics
        bytes_per_second = total_bytes / duration if duration > 0 else 0
        is_bidirectional = bytes_sent > 0 and bytes_recv > 0
        data_ratio = bytes_sent / bytes_recv if bytes_recv > 0 else float('inf')

        # Component scores
        duration_score = self._score_duration(conn, duration)
        transfer_score = self._score_transfer_pattern(
            bytes_sent, bytes_recv, bytes_per_second, duration
        )
        protocol_score = self._score_protocol_context(conn, duration)
        destination_score = self._score_destination(conn)

        # Weighted total score (0-100)
        total_score = (
            duration_score * 0.30 +
            transfer_score * 0.35 +
            protocol_score * 0.20 +
            destination_score * 0.15
        )

        # Confidence based on data completeness
        confidence = self._calculate_confidence(conn, bytes_per_second)

        # Threat level
        threat_level = self._score_to_threat_level(total_score)

        # Reasons (explainability)
        reasons = self._build_reasons(
            conn, duration, bytes_per_second,
            duration_score, transfer_score, protocol_score, destination_score
        )

        # Indicators
        indicators = self._build_indicators(
            conn, duration, bytes_sent, bytes_recv, bytes_per_second
        )

        # MITRE mapping
        mitre_techniques = self._map_to_mitre(
            conn, duration, bytes_sent, bytes_recv, bytes_per_second
        )
        mitre_mappings = self._build_mitre_mappings(
            conn, mitre_techniques, confidence, indicators
        )

        return LongConnectionResult(
            connection=conn,
            duration_seconds=duration,
            score=total_score,
            confidence=confidence,
            threat_level=threat_level,
            reasons=reasons,
            indicators=indicators,
            mitre_techniques=mitre_techniques,
            mitre_mappings=mitre_mappings,
            bytes_per_second=bytes_per_second,
            is_bidirectional=is_bidirectional,
            data_ratio=data_ratio,
        )

    def _score_duration(self, conn: Connection, duration: float) -> float:
        """
        Score based on connection duration relative to protocol expectations.

        Longer connections are more suspicious for certain protocols (HTTP, DNS).
        """
        service = (conn.service or "default").lower()
        threshold = PROTOCOL_DURATION_THRESHOLDS.get(
            service,
            PROTOCOL_DURATION_THRESHOLDS["default"]
        )

        if duration < threshold:
            return 0.0

        # Score increases with duration beyond threshold
        ratio = duration / threshold
        if ratio >= 10:
            return 100.0
        elif ratio >= 5:
            return 80.0
        elif ratio >= 3:
            return 60.0
        elif ratio >= 2:
            return 40.0
        else:
            return 20.0

    def _score_transfer_pattern(
        self,
        bytes_sent: int,
        bytes_recv: int,
        bytes_per_second: float,
        duration: float,
    ) -> float:
        """
        Score based on data transfer characteristics.

        Suspicious patterns:
        - High sustained upload (exfiltration)
        - Very low but continuous transfer (covert channel)
        - Imbalanced bidirectional (asymmetric exfil)
        """
        score = 0.0

        # High sustained upload (exfiltration)
        upload_rate = bytes_sent / duration if duration > 0 else 0
        if upload_rate >= 1024 * 1024:  # 1 MB/s
            score += 40.0
        elif upload_rate >= 100 * 1024:  # 100 KB/s
            score += 30.0
        elif upload_rate >= 10 * 1024:  # 10 KB/s
            score += 20.0
        elif upload_rate >= 1024:  # 1 KB/s
            score += 10.0

        # Very low but continuous transfer (covert channel)
        if 0 < bytes_per_second < 100 and duration > 1800:  # < 100 bytes/sec for 30+ min
            score += 30.0

        # Large total transfer
        total_bytes = bytes_sent + bytes_recv
        if total_bytes >= 100 * 1024 * 1024:  # 100 MB
            score += 20.0
        elif total_bytes >= 10 * 1024 * 1024:  # 10 MB
            score += 10.0

        # Imbalanced bidirectional (one-way heavy)
        if bytes_sent > 0 and bytes_recv > 0:
            ratio = max(bytes_sent, bytes_recv) / min(bytes_sent, bytes_recv)
            if ratio >= 10:  # 10:1 imbalance
                score += 10.0

        return min(score, 100.0)

    def _score_protocol_context(self, conn: Connection, duration: float) -> float:
        """
        Score based on protocol-specific expectations.

        Some protocols should never be long-lived:
        - DNS (should be instant)
        - HTTP (unless streaming)
        """
        service = (conn.service or "").lower()
        dst_port = conn.dst_port

        score = 0.0

        # DNS should be very short
        if service == "dns" or dst_port == 53:
            if duration > 60:  # More than 1 minute is very suspicious
                score += 90.0
            elif duration > 10:
                score += 70.0
            elif duration > 5:
                score += 50.0

        # HTTP/HTTPS long connections
        elif service in ["http", "https"] or dst_port in [80, 443, 8080, 8443]:
            if duration > 3600:  # 1 hour
                score += 60.0
            elif duration > 1800:  # 30 minutes
                score += 40.0
            elif duration > 900:  # 15 minutes
                score += 20.0

        # SSH with high data transfer
        elif service == "ssh" or dst_port == 22:
            bytes_sent = conn.bytes_sent or 0
            if duration > 3600 and bytes_sent > 10 * 1024 * 1024:  # 1hr + 10MB
                score += 50.0

        # Non-standard ports
        elif dst_port > 49152:  # Ephemeral/dynamic ports
            score += 20.0

        return min(score, 100.0)

    def _score_destination(self, conn: Connection) -> float:
        """
        Score based on destination characteristics.

        More suspicious:
        - External IPs
        - Unusual ports
        - Multiple destination ports from same source
        """
        score = 0.0

        # External destination
        if not self._is_private_ip(conn.dst_ip):
            score += 50.0

        # Non-standard port
        dst_port = conn.dst_port
        standard_ports = {
            20, 21, 22, 23, 25, 53, 80, 110, 143, 443,
            3306, 3389, 5432, 8080, 8443
        }
        if dst_port not in standard_ports:
            score += 30.0

        # High-numbered port
        if dst_port > 49152:
            score += 20.0

        return min(score, 100.0)

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in a private / non-routable range."""
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def _calculate_confidence(
        self,
        conn: Connection,
        bytes_per_second: float,
    ) -> float:
        """Calculate confidence in the detection."""
        confidence = 0.6  # Base confidence

        # Higher confidence with more data
        total_bytes = (conn.bytes_sent or 0) + (conn.bytes_recv or 0)
        if total_bytes >= 10 * 1024 * 1024:  # 10 MB
            confidence += 0.2
        elif total_bytes >= 1024 * 1024:  # 1 MB
            confidence += 0.1

        # Service identification
        if conn.service:
            confidence += 0.1

        # Sustained transfer (not just idle connection)
        if bytes_per_second >= 100:
            confidence += 0.1

        return min(confidence, 1.0)

    def _score_to_threat_level(self, score: float) -> ThreatLevel:
        """Convert numeric score to threat level."""
        if score >= 80:
            return ThreatLevel.CRITICAL
        elif score >= 60:
            return ThreatLevel.HIGH
        elif score >= 40:
            return ThreatLevel.MEDIUM
        else:
            return ThreatLevel.LOW

    def _build_reasons(
        self,
        conn: Connection,
        duration: float,
        bytes_per_second: float,
        duration_score: float,
        transfer_score: float,
        protocol_score: float,
        destination_score: float,
    ) -> List[str]:
        """Build human-readable reasons for the score."""
        reasons = []

        # Duration
        hours = duration / 3600
        if hours >= 1:
            reasons.append(f"Long connection duration: {hours:.1f} hours ({duration_score:.0f} pts)")
        else:
            minutes = duration / 60
            reasons.append(f"Long connection duration: {minutes:.0f} minutes ({duration_score:.0f} pts)")

        # Transfer pattern
        if transfer_score >= 40:
            upload_mb = (conn.bytes_sent or 0) / (1024 * 1024)
            reasons.append(f"High data upload: {upload_mb:.1f} MB ({transfer_score:.0f} pts)")
        elif transfer_score >= 20:
            reasons.append(f"Sustained data transfer ({transfer_score:.0f} pts)")

        # Protocol context
        if protocol_score >= 60:
            service = conn.service or "unknown"
            reasons.append(f"Unusual duration for {service} protocol ({protocol_score:.0f} pts)")

        # Destination
        if destination_score >= 50:
            reasons.append(f"External destination {conn.dst_ip}:{conn.dst_port} ({destination_score:.0f} pts)")

        # Transfer rate
        if bytes_per_second >= 1024 * 1024:
            reasons.append(f"High transfer rate: {bytes_per_second/(1024*1024):.2f} MB/s")
        elif bytes_per_second >= 1024:
            reasons.append(f"Transfer rate: {bytes_per_second/1024:.2f} KB/s")

        return reasons

    def _build_indicators(
        self,
        conn: Connection,
        duration: float,
        bytes_sent: int,
        bytes_recv: int,
        bytes_per_second: float,
    ) -> List[str]:
        """Build specific threat indicators."""
        indicators = []

        # Duration indicator
        indicators.append(f"Duration: {duration:.0f}s ({duration/3600:.2f}h)")

        # Volume indicators
        indicators.append(f"Sent: {bytes_sent:,} bytes ({bytes_sent/(1024*1024):.2f} MB)")
        indicators.append(f"Received: {bytes_recv:,} bytes ({bytes_recv/(1024*1024):.2f} MB)")
        indicators.append(f"Rate: {bytes_per_second:,.0f} bytes/sec")

        # Direction
        if bytes_sent > bytes_recv * 2:
            indicators.append("Primarily outbound traffic (potential exfiltration)")
        elif bytes_recv > bytes_sent * 2:
            indicators.append("Primarily inbound traffic")
        else:
            indicators.append("Bidirectional traffic")

        # Service/port
        if conn.service:
            indicators.append(f"Protocol: {conn.service}")
        indicators.append(f"Destination port: {conn.dst_port}")

        return indicators

    def _map_to_mitre(
        self,
        conn: Connection,
        duration: float,
        bytes_sent: int,
        bytes_recv: int,
        bytes_per_second: float,
    ) -> List[str]:
        """Map long connection to MITRE ATT&CK techniques."""
        techniques = []

        # High upload = exfiltration
        upload_rate = bytes_sent / duration if duration > 0 else 0
        if upload_rate >= 1024:  # 1 KB/s sustained
            techniques.append("T1041")  # Exfiltration Over C2 Channel

        # Low sustained transfer = covert channel
        if 0 < bytes_per_second < 100 and duration > 1800:
            techniques.append("T1030")  # Data Transfer Size Limits

        # Long duration = persistent connection
        if duration > 3600:  # 1 hour
            techniques.append("T1071")  # Application Layer Protocol

            # Protocol-specific C2 techniques
            service = (conn.service or "").lower()
            if service in ["http", "https"] or conn.dst_port in [80, 443, 8080, 8443]:
                techniques.append("T1071.001")  # Web Protocols
            elif service == "dns" or conn.dst_port == 53:
                techniques.append("T1071.004")  # DNS

        # Scheduled/regular transfer
        if bytes_per_second > 0 and duration > 1800:
            techniques.append("T1029")  # Scheduled Transfer

        # Large transfer to external IP
        if not self._is_private_ip(conn.dst_ip) and bytes_sent > 10 * 1024 * 1024:
            techniques.append("T1048")  # Exfiltration Over Alternative Protocol

        return sorted(list(set(techniques)))

    def _build_mitre_mappings(
        self,
        conn: Connection,
        technique_ids: List[str],
        confidence: float,
        indicators: List[str],
    ) -> List[MitreMapping]:
        """Build full MITRE mapping objects with evidence."""
        mappings = []

        for tech_id in technique_ids:
            technique = mitre_framework.get_technique(tech_id)
            if not technique:
                continue

            tactics = mitre_framework.get_tactics_for_technique(tech_id)
            tactic = tactics[0] if tactics else None

            evidence = [
                f"Long connection: {conn.src_ip}:{conn.src_port} → {conn.dst_ip}:{conn.dst_port}",
                f"Duration: {conn.duration:.0f} seconds",
                f"Bytes sent: {conn.bytes_sent:,}",
                f"Bytes received: {conn.bytes_recv:,}",
            ]
            if conn.service:
                evidence.append(f"Service: {conn.service}")

            observed_behaviors = []
            if "T1041" in tech_id or "T1048" in tech_id:
                observed_behaviors.append("Sustained outbound data transfer")
            if "T1030" in tech_id:
                observed_behaviors.append("Small consistent data transfers (covert channel)")
            if "T1071" in tech_id:
                observed_behaviors.append("Long-duration application layer connection")

            # conn.timestamp is a datetime; MitreMapping expects a float epoch.
            ts = conn.timestamp
            timestamp = ts.timestamp() if hasattr(ts, "timestamp") else (float(ts) if ts else 0.0)

            mapping = MitreMapping(
                technique_id=tech_id,
                technique_name=technique.name,
                tactic=tactic.name if tactic else "Unknown",
                tactic_id=tactic.tactic_id if tactic else "Unknown",
                confidence=confidence,
                evidence=evidence,
                observed_behaviors=observed_behaviors,
                detection_count=1,
                first_detected=timestamp,
                last_detected=timestamp,
                affected_hosts=[conn.src_ip],
            )
            mappings.append(mapping)

        return mappings
