"""
Unified Threat Scoring Engine

Aggregates threat intelligence from multiple detection sources:
- Beaconing detection (C2 communication)
- DNS threat analysis (tunneling, DGA, fast-flux)
- Suricata IDS/IPS alerts
- Long connection analysis (exfiltration)

Provides:
- Unified per-host threat scores
- Cross-detection correlation
- Evidence chains linking multiple detections
- Comprehensive MITRE ATT&CK mapping
- Attack timeline reconstruction
"""

from typing import List, Dict, Set, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from datetime import datetime

from api.models.threat import ThreatScore, ThreatLevel, ThreatIndicator, IndicatorType, MitreMapping
from api.models.beacon import BeaconResult
from api.models.dns_threat import (
    DnsTunnelingResult,
    DgaResult,
    DnsFastFluxResult,
    SuspiciousDnsPattern,
)
from api.services.beacon_analyzer import BeaconAnalyzer
from api.services.dns_analyzer import DnsAnalyzer
from api.services.suricata_analyzer import SuricataAnalyzer, AlertScore
from api.services.long_connection_analyzer import (
    LongConnectionAnalyzer,
    LongConnectionResult,
)
from api.services.log_store import LogStore
from api.models.suricata import SuricataAlert
from api.config.mitre_framework import mitre_framework


def _get_score(obj) -> float:
    """Extract score from any threat object, handling different score field names."""
    for attr in ('score', 'tunneling_score', 'dga_score', 'fast_flux_score', 'suspicion_score'):
        val = getattr(obj, attr, None)
        if val is not None:
            return float(val)
    return 0.0


def _score_to_threat_level(score: float) -> ThreatLevel:
    """Map a 0-100 detection score to a threat level."""
    if score >= 80:
        return ThreatLevel.CRITICAL
    if score >= 60:
        return ThreatLevel.HIGH
    if score >= 40:
        return ThreatLevel.MEDIUM
    return ThreatLevel.LOW


def _as_epoch(ts) -> float:
    """Coerce a timestamp (datetime, float, or None) to a float Unix epoch."""
    if ts is None:
        return 0.0
    if hasattr(ts, "timestamp"):
        return ts.timestamp()
    try:
        return float(ts)
    except (TypeError, ValueError):
        return 0.0


def _mappings_from_technique_ids(technique_ids, confidence, host, ts, evidence):
    """Build MitreMapping objects from bare technique-ID strings.

    Beacons carry only technique IDs (not full mappings), so expand them via
    the MITRE framework for the consolidated per-host view."""
    mappings = []
    for tech_id in technique_ids or []:
        technique = mitre_framework.get_technique(tech_id)
        if not technique:
            continue
        tactics = mitre_framework.get_tactics_for_technique(tech_id)
        tactic = tactics[0] if tactics else None
        mappings.append(MitreMapping(
            technique_id=tech_id,
            technique_name=technique.name,
            tactic=tactic.name if tactic else "Unknown",
            tactic_id=tactic.tactic_id if tactic else "Unknown",
            confidence=confidence,
            evidence=list(evidence),
            observed_behaviors=[],
            detection_count=1,
            first_detected=ts,
            last_detected=ts,
            affected_hosts=[host],
        ))
    return mappings


def _to_suricata_alert(alert) -> SuricataAlert:
    """Adapt a unified Alert (as held by the log store) to the raw SuricataAlert
    shape the Suricata analyzer and indicator builder expect."""
    if isinstance(alert, SuricataAlert):
        return alert
    ts = alert.timestamp
    ts_str = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
    return SuricataAlert(
        timestamp=ts_str,
        event_type="alert",
        src_ip=alert.src_ip,
        src_port=alert.src_port,
        dest_ip=alert.dst_ip,
        dest_port=alert.dst_port,
        proto=alert.proto,
        alert={
            "signature": alert.signature,
            "signature_id": alert.signature_id,
            "category": alert.category,
            "severity": alert.severity,
            "action": alert.action,
        },
    )


@dataclass
class HostThreatProfile:
    """Complete threat profile for a host."""
    ip: str
    score: float  # 0-1 (normalized)
    threat_level: ThreatLevel
    confidence: float  # 0-1

    # Detection counts
    beacon_count: int = 0
    dns_threat_count: int = 0
    alert_count: int = 0
    long_connection_count: int = 0

    # Evidence from each detection type
    beacons: List[BeaconResult] = field(default_factory=list)
    dns_threats: List[Dict] = field(default_factory=list)  # Mixed DNS threat types
    alerts: List[AlertScore] = field(default_factory=list)
    long_connections: List[LongConnectionResult] = field(default_factory=list)

    # Aggregated analysis
    all_reasons: List[str] = field(default_factory=list)
    all_indicators: List[ThreatIndicator] = field(default_factory=list)
    mitre_techniques: Set[str] = field(default_factory=set)
    mitre_mappings: List[MitreMapping] = field(default_factory=list)

    # Attack narrative
    attack_timeline: List[Dict] = field(default_factory=list)
    attack_summary: str = ""

    # Related entities
    related_ips: Set[str] = field(default_factory=set)
    related_domains: Set[str] = field(default_factory=set)

    # Temporal data
    first_seen: float = 0.0
    last_seen: float = 0.0


@dataclass
class ThreatCorrelation:
    """Correlation between multiple threat detections."""
    correlation_type: str  # e.g., "beacon_with_dns_exfil", "scanning_then_exploit"
    hosts: List[str]
    score: float
    confidence: float
    description: str
    evidence: List[str]
    mitre_techniques: List[str]
    timeline: List[Dict]


class UnifiedThreatEngine:
    """
    Unified threat scoring and correlation engine.

    Aggregates detections from:
    - Beaconing analysis
    - DNS threat analysis
    - Suricata alerts
    - Long connection analysis

    Provides unified per-host risk scores with full evidence chains.
    """

    def __init__(self, log_store: LogStore):
        """
        Initialize the unified threat engine.

        Args:
            log_store: LogStore instance with loaded data
        """
        self.log_store = log_store

        # Initialize all analyzers
        self.beacon_analyzer = BeaconAnalyzer()
        self.dns_analyzer = DnsAnalyzer()
        self.suricata_analyzer = SuricataAnalyzer()
        self.long_conn_analyzer = LongConnectionAnalyzer()

        # Cache for analysis results
        self._beacons: List[BeaconResult] = []
        self._dns_threats: Dict[str, List] = {}
        self._alerts: List[AlertScore] = []
        self._long_connections: List[LongConnectionResult] = []

    def analyze_all(self) -> Dict[str, HostThreatProfile]:
        """
        Run all detection engines and aggregate results.

        Returns:
            Dict mapping IP addresses to HostThreatProfile
        """
        # Run all analyzers
        self._run_all_analyzers()

        # Build per-host threat profiles
        host_profiles = self._build_host_profiles()

        # Correlate detections across hosts
        correlations = self._correlate_threats(host_profiles)

        # Enhance profiles with correlation data
        self._apply_correlations(host_profiles, correlations)

        return host_profiles

    def _run_all_analyzers(self):
        """Run all detection engines."""
        # Beaconing detection
        self._beacons = self.beacon_analyzer.analyze_connections(
            self.log_store.connections
        )

        # DNS threat detection
        dns_queries_by_src = defaultdict(list)
        for query in self.log_store.dns_queries:
            dns_queries_by_src[query.src_ip].append(query)

        self._dns_threats = {
            "tunneling": [],
            "dga": [],
            "fast_flux": [],
            "suspicious": [],
        }

        for src_ip, queries in dns_queries_by_src.items():
            # Tunneling
            tunneling = self.dns_analyzer.detect_dns_tunneling(queries)
            self._dns_threats["tunneling"].extend(tunneling)

            # DGA
            dga = self.dns_analyzer.detect_dga_domains(queries)
            self._dns_threats["dga"].extend(dga)

            # Fast-flux
            fast_flux = self.dns_analyzer.detect_fast_flux(queries)
            self._dns_threats["fast_flux"].extend(fast_flux)

            # Suspicious patterns
            suspicious = self.dns_analyzer.detect_suspicious_patterns(queries)
            self._dns_threats["suspicious"].extend(suspicious)

        # Suricata alerts. The log store holds unified Alert objects, but the
        # Suricata analyzer (and the downstream indicator builder) work on the
        # raw SuricataAlert shape, so adapt before scoring.
        suricata_alerts = [_to_suricata_alert(a) for a in self.log_store.alerts]
        self._alerts = self.suricata_analyzer.analyze_alerts(suricata_alerts)

        # Long connections
        self._long_connections = self.long_conn_analyzer.analyze_connections(
            self.log_store.connections
        )

    def _build_host_profiles(self) -> Dict[str, HostThreatProfile]:
        """Build per-host threat profiles from all detections."""
        profiles: Dict[str, HostThreatProfile] = {}

        # Process beacons
        for beacon in self._beacons:
            src_ip = beacon.src_ip
            if src_ip not in profiles:
                profiles[src_ip] = self._create_profile(src_ip)

            profile = profiles[src_ip]
            profile.beacon_count += 1
            profile.beacons.append(beacon)
            profile.mitre_techniques.update(beacon.mitre_techniques)
            profile.related_ips.add(beacon.dst_ip)

            # Update temporal bounds
            self._update_temporal_bounds(profile, beacon.first_seen, beacon.last_seen)

            # Add to timeline
            profile.attack_timeline.append({
                "timestamp": beacon.first_seen,
                "type": "beacon",
                "description": f"C2 beacon to {beacon.dst_ip}:{beacon.dst_port}",
                "score": beacon.beacon_score,
            })

        # Process DNS threats
        for threat_type, threats in self._dns_threats.items():
            for threat in threats:
                src_ip = threat.src_ip
                if src_ip not in profiles:
                    profiles[src_ip] = self._create_profile(src_ip)

                profile = profiles[src_ip]
                profile.dns_threat_count += 1
                profile.dns_threats.append({
                    "type": threat_type,
                    "data": threat,
                })
                profile.mitre_techniques.update(threat.mitre_techniques)

                # Add domains
                if hasattr(threat, "domain"):
                    profile.related_domains.add(threat.domain)

                # Add to timeline
                timestamp = threat.first_seen if hasattr(threat, "first_seen") else 0.0
                profile.attack_timeline.append({
                    "timestamp": timestamp,
                    "type": f"dns_{threat_type}",
                    "description": self._describe_dns_threat(threat_type, threat),
                    "score": _get_score(threat),
                })

                self._update_temporal_bounds(profile, timestamp, timestamp)

        # Process alerts
        for alert_score in self._alerts:
            alert = alert_score.alert  # SuricataAlert (uses dest_ip, not dst_ip)
            src_ip = alert.src_ip
            dst_ip = alert.dest_ip

            timestamp = self.suricata_analyzer._parse_timestamp(alert.timestamp)
            timeline_entry = {
                "timestamp": timestamp,
                "type": "alert",
                "description": alert.alert.get("signature", "Unknown alert"),
                "score": alert_score.score,
            }

            # The alert involves both endpoints; surface it on each host's
            # profile so the attacker and the victim both reflect the activity.
            for ip, peer in ((src_ip, dst_ip), (dst_ip, src_ip)):
                if ip not in profiles:
                    profiles[ip] = self._create_profile(ip)
                profile = profiles[ip]
                profile.alert_count += 1
                profile.alerts.append(alert_score)
                profile.mitre_techniques.update(alert_score.mitre_techniques)
                profile.related_ips.add(peer)
                profile.attack_timeline.append(dict(timeline_entry))
                self._update_temporal_bounds(profile, timestamp, timestamp)

        # Process long connections
        for long_conn in self._long_connections:
            conn = long_conn.connection
            src_ip = conn.src_ip
            if src_ip not in profiles:
                profiles[src_ip] = self._create_profile(src_ip)

            profile = profiles[src_ip]
            profile.long_connection_count += 1
            profile.long_connections.append(long_conn)
            profile.mitre_techniques.update(long_conn.mitre_techniques)
            profile.related_ips.add(conn.dst_ip)

            # Timeline (conn.timestamp is a datetime; the timeline and temporal
            # bounds use float epochs, matching the alert/beacon entries)
            ts = conn.timestamp
            timestamp = ts.timestamp() if hasattr(ts, "timestamp") else (float(ts) if ts else 0.0)
            profile.attack_timeline.append({
                "timestamp": timestamp,
                "type": "long_connection",
                "description": f"Long connection to {conn.dst_ip}:{conn.dst_port} ({long_conn.duration_seconds:.0f}s)",
                "score": long_conn.score,
            })

            self._update_temporal_bounds(profile, timestamp, timestamp)

        # Finalize all profiles
        for profile in profiles.values():
            self._finalize_profile(profile)

        return profiles

    def _create_profile(self, ip: str) -> HostThreatProfile:
        """Create a new host threat profile."""
        return HostThreatProfile(
            ip=ip,
            score=0.0,
            threat_level=ThreatLevel.INFO,
            confidence=0.0,
        )

    def _update_temporal_bounds(
        self,
        profile: HostThreatProfile,
        first: float,
        last: float,
    ):
        """Update first_seen and last_seen timestamps."""
        if profile.first_seen == 0.0 or first < profile.first_seen:
            profile.first_seen = first
        if last > profile.last_seen:
            profile.last_seen = last

    def _describe_dns_threat(self, threat_type: str, threat) -> str:
        """Generate description for DNS threat."""
        if threat_type == "tunneling":
            return f"DNS tunneling to {threat.domain}"
        elif threat_type == "dga":
            return f"DGA domain: {threat.domain}"
        elif threat_type == "fast_flux":
            return f"Fast-flux DNS: {threat.domain}"
        elif threat_type == "suspicious":
            return f"Suspicious DNS: {threat.pattern_type}"
        return "DNS threat detected"

    def _finalize_profile(self, profile: HostThreatProfile):
        """Finalize profile by calculating aggregate scores and building narrative."""
        # Sort timeline
        profile.attack_timeline.sort(key=lambda x: x["timestamp"])

        # Calculate unified score (0-1 normalized)
        scores = []

        # Beacon scores (0-100 scale)
        for beacon in profile.beacons:
            scores.append(beacon.beacon_score / 100.0)

        # DNS threat scores (0-100 scale)
        for dns_threat in profile.dns_threats:
            threat_data = dns_threat["data"]
            scores.append(_get_score(threat_data) / 100.0)

        # Alert scores (0-100 scale)
        for alert_score in profile.alerts:
            scores.append(alert_score.score / 100.0)

        # Long connection scores (0-100 scale)
        for long_conn in profile.long_connections:
            scores.append(long_conn.score / 100.0)

        # Aggregate score (max + average for multiple detections)
        if scores:
            max_score = max(scores)
            avg_score = sum(scores) / len(scores)
            # Weight: 70% max, 30% average (multiple detections increase score)
            profile.score = max_score * 0.7 + avg_score * 0.3
        else:
            profile.score = 0.0

        # Boost score for multiple detection types
        detection_types = sum([
            1 if profile.beacon_count > 0 else 0,
            1 if profile.dns_threat_count > 0 else 0,
            1 if profile.alert_count > 0 else 0,
            1 if profile.long_connection_count > 0 else 0,
        ])
        if detection_types >= 3:
            profile.score = min(profile.score * 1.2, 1.0)
        elif detection_types >= 2:
            profile.score = min(profile.score * 1.1, 1.0)

        # Threat level
        profile.threat_level = self._score_to_threat_level(profile.score)

        # Confidence (more detections = higher confidence)
        profile.confidence = min(0.5 + (detection_types * 0.15), 1.0)

        # Build reasons
        profile.all_reasons = self._build_aggregate_reasons(profile)

        # Build indicators
        profile.all_indicators = self._build_aggregate_indicators(profile)

        # Consolidate MITRE mappings
        profile.mitre_mappings = self._consolidate_mitre_mappings(profile)

        # Build attack summary
        profile.attack_summary = self._build_attack_summary(profile)

    def _score_to_threat_level(self, score: float) -> ThreatLevel:
        """Convert 0-1 score to threat level."""
        if score >= 0.8:
            return ThreatLevel.CRITICAL
        elif score >= 0.6:
            return ThreatLevel.HIGH
        elif score >= 0.4:
            return ThreatLevel.MEDIUM
        elif score >= 0.2:
            return ThreatLevel.LOW
        else:
            return ThreatLevel.INFO

    def _build_aggregate_reasons(self, profile: HostThreatProfile) -> List[str]:
        """Build unified list of reasons."""
        reasons = []

        if profile.beacon_count > 0:
            reasons.append(f"{profile.beacon_count} beaconing pattern(s) detected (C2 communication)")

        if profile.dns_threat_count > 0:
            reasons.append(f"{profile.dns_threat_count} DNS-based threat(s) detected")

        if profile.alert_count > 0:
            reasons.append(f"{profile.alert_count} IDS/IPS alert(s) triggered")

        if profile.long_connection_count > 0:
            reasons.append(f"{profile.long_connection_count} suspicious long connection(s)")

        if len(profile.mitre_techniques) > 0:
            reasons.append(f"{len(profile.mitre_techniques)} MITRE ATT&CK technique(s) observed")

        # Detection type diversity
        detection_types = sum([
            1 if profile.beacon_count > 0 else 0,
            1 if profile.dns_threat_count > 0 else 0,
            1 if profile.alert_count > 0 else 0,
            1 if profile.long_connection_count > 0 else 0,
        ])
        if detection_types >= 3:
            reasons.append("Multiple attack vectors detected (coordinated attack)")

        return reasons

    def _build_aggregate_indicators(self, profile: HostThreatProfile) -> List[ThreatIndicator]:
        """Build unified list of threat indicators."""
        indicators = []

        # Beacon indicators
        for beacon in profile.beacons:
            indicators.append(ThreatIndicator(
                indicator_type=IndicatorType.IP_ADDRESS,
                value=f"{beacon.dst_ip}:{beacon.dst_port}",
                description=(
                    f"Beaconing to {beacon.dst_ip}:{beacon.dst_port} over "
                    f"{beacon.connection_count} connections (score {beacon.beacon_score:.0f})"
                ),
                severity=_score_to_threat_level(beacon.beacon_score),
                source="analysis",
                detection_time=_as_epoch(beacon.first_seen),
                log_source="conn",
                context={
                    "confidence": f"{beacon.confidence:.2f}",
                    "connection_count": str(beacon.connection_count),
                    "jitter_pct": f"{beacon.jitter_pct:.1f}",
                },
                mitre_technique=(beacon.mitre_techniques[0] if beacon.mitre_techniques else None),
            ))

        # DNS indicators
        for dns_threat in profile.dns_threats:
            threat_data = dns_threat["data"]
            threat_type = dns_threat["type"]
            # Some DNS findings (e.g. host-level "suspicious" patterns) have no
            # single domain; fall back to the host so the indicator still has a value.
            domain = getattr(threat_data, "domain", None)
            value = domain or getattr(threat_data, "src_ip", None) or "dns-anomaly"
            score_val = _get_score(threat_data)
            try:
                indicators.append(ThreatIndicator(
                    indicator_type=IndicatorType.DOMAIN if domain else IndicatorType.BEHAVIOR,
                    value=str(value),
                    description=f"DNS {threat_type} detected for {value}",
                    severity=_score_to_threat_level(score_val),
                    source="analysis",
                    detection_time=_as_epoch(getattr(threat_data, "first_seen", 0.0)),
                    log_source="dns",
                    context={
                        "threat_type": str(threat_type),
                        "confidence": f"{getattr(threat_data, 'confidence', 0.5):.2f}",
                    },
                ))
            except Exception:
                pass  # Skip malformed DNS indicators

        # Alert indicators (top 5 by score)
        top_alerts = sorted(profile.alerts, key=lambda x: x.score, reverse=True)[:5]
        for alert_score in top_alerts:
            alert = alert_score.alert
            indicators.append(ThreatIndicator(
                indicator_type=IndicatorType.BEHAVIOR,
                value=alert.alert.get("signature", "Unknown"),
                description=(
                    f"Suricata alert: {alert.alert.get('signature', 'Unknown')} "
                    f"(category {alert.alert.get('category', 'Unknown')})"
                ),
                severity=alert_score.threat_level,
                source="suricata",
                detection_time=self.suricata_analyzer._parse_timestamp(alert.timestamp),
                log_source="suricata",
                context={
                    "category": str(alert.alert.get("category", "Unknown")),
                    "confidence": f"{alert_score.confidence:.2f}",
                },
                mitre_technique=(alert_score.mitre_techniques[0] if alert_score.mitre_techniques else None),
            ))

        # Long connection indicators
        for long_conn in profile.long_connections:
            conn = long_conn.connection
            indicators.append(ThreatIndicator(
                indicator_type=IndicatorType.IP_ADDRESS,
                value=f"{conn.dst_ip}:{conn.dst_port}",
                description=(
                    f"Long connection to {conn.dst_ip}:{conn.dst_port} "
                    f"({long_conn.duration_seconds:.0f}s, {conn.bytes_sent:,} bytes sent)"
                ),
                severity=long_conn.threat_level,
                source="analysis",
                detection_time=_as_epoch(conn.timestamp),
                log_source="conn",
                context={
                    "confidence": f"{long_conn.confidence:.2f}",
                    "duration_seconds": f"{long_conn.duration_seconds:.0f}",
                },
                mitre_technique=(long_conn.mitre_techniques[0] if long_conn.mitre_techniques else None),
            ))

        return indicators

    def _consolidate_mitre_mappings(self, profile: HostThreatProfile) -> List[MitreMapping]:
        """Consolidate MITRE mappings from all detections."""
        # Collect all mappings
        all_mappings: Dict[str, List[MitreMapping]] = defaultdict(list)

        # From beacons (BeaconResult carries technique IDs, not full mappings)
        for beacon in profile.beacons:
            if getattr(beacon, "mitre_mappings", None):
                for mapping in beacon.mitre_mappings:
                    all_mappings[mapping.technique_id].append(mapping)
            else:
                for mapping in _mappings_from_technique_ids(
                    getattr(beacon, "mitre_techniques", []),
                    confidence=beacon.confidence,
                    host=beacon.src_ip,
                    ts=_as_epoch(beacon.first_seen),
                    evidence=[
                        f"Beaconing to {beacon.dst_ip}:{beacon.dst_port} "
                        f"({beacon.connection_count} connections)"
                    ],
                ):
                    all_mappings[mapping.technique_id].append(mapping)

        # From DNS threats
        for dns_threat in profile.dns_threats:
            threat_data = dns_threat["data"]
            if hasattr(threat_data, "mitre_mappings"):
                for mapping in threat_data.mitre_mappings:
                    all_mappings[mapping.technique_id].append(mapping)

        # From alerts
        for alert_score in profile.alerts:
            for mapping in alert_score.mitre_mappings:
                all_mappings[mapping.technique_id].append(mapping)

        # From long connections
        for long_conn in profile.long_connections:
            for mapping in long_conn.mitre_mappings:
                all_mappings[mapping.technique_id].append(mapping)

        # Merge mappings for each technique
        consolidated = []
        for tech_id, mappings in all_mappings.items():
            if not mappings:
                continue

            # Use first mapping as template
            base = mappings[0]

            # Aggregate evidence and behaviors
            all_evidence = []
            all_behaviors = set()
            all_hosts = set()
            detection_count = len(mappings)
            first_detected = min(m.first_detected for m in mappings)
            last_detected = max(m.last_detected for m in mappings)
            avg_confidence = sum(m.confidence for m in mappings) / len(mappings)

            for mapping in mappings:
                all_evidence.extend(mapping.evidence)
                all_behaviors.update(mapping.observed_behaviors)
                all_hosts.update(mapping.affected_hosts)

            consolidated_mapping = MitreMapping(
                technique_id=tech_id,
                technique_name=base.technique_name,
                tactic=base.tactic,
                tactic_id=base.tactic_id,
                confidence=avg_confidence,
                evidence=all_evidence[:10],  # Limit to top 10
                observed_behaviors=sorted(list(all_behaviors)),
                detection_count=detection_count,
                first_detected=first_detected,
                last_detected=last_detected,
                affected_hosts=sorted(list(all_hosts)),
            )
            consolidated.append(consolidated_mapping)

        # Sort by detection count (most observed first)
        consolidated.sort(key=lambda x: x.detection_count, reverse=True)
        return consolidated

    def _build_attack_summary(self, profile: HostThreatProfile) -> str:
        """Build narrative summary of attack."""
        parts = []

        parts.append(f"Host {profile.ip} shows {profile.threat_level.value.upper()} threat activity.")

        # Detection summary
        detections = []
        if profile.beacon_count > 0:
            detections.append(f"{profile.beacon_count} C2 beacon(s)")
        if profile.dns_threat_count > 0:
            detections.append(f"{profile.dns_threat_count} DNS threat(s)")
        if profile.alert_count > 0:
            detections.append(f"{profile.alert_count} IDS alert(s)")
        if profile.long_connection_count > 0:
            detections.append(f"{profile.long_connection_count} long connection(s)")

        if detections:
            parts.append(f"Detected: {', '.join(detections)}.")

        # MITRE techniques
        if profile.mitre_techniques:
            top_techniques = list(profile.mitre_techniques)[:5]
            parts.append(f"MITRE ATT&CK techniques: {', '.join(top_techniques)}.")

        # Timeline
        if profile.first_seen > 0:
            duration = profile.last_seen - profile.first_seen
            if duration > 3600:
                parts.append(f"Activity observed over {duration/3600:.1f} hours.")
            else:
                parts.append(f"Activity observed over {duration/60:.0f} minutes.")

        return " ".join(parts)

    def _correlate_threats(
        self,
        profiles: Dict[str, HostThreatProfile],
    ) -> List[ThreatCorrelation]:
        """Find correlations between threats across hosts."""
        correlations = []

        # Correlation 1: Beacon + DNS exfiltration from same host
        for ip, profile in profiles.items():
            if profile.beacon_count > 0 and profile.dns_threat_count > 0:
                dns_exfil = [
                    t for t in profile.dns_threats
                    if t["type"] == "tunneling" and _get_score(t["data"]) >= 70
                ]
                if dns_exfil:
                    correlations.append(ThreatCorrelation(
                        correlation_type="beacon_with_dns_exfil",
                        hosts=[ip],
                        score=0.9,
                        confidence=0.85,
                        description=f"Host {ip} shows both C2 beaconing and DNS exfiltration",
                        evidence=[
                            f"{profile.beacon_count} beacons detected",
                            f"{len(dns_exfil)} DNS tunneling patterns",
                        ],
                        mitre_techniques=["T1071", "T1071.004", "T1048.003"],
                        timeline=[],
                    ))

        # Correlation 2: Multiple hosts beaconing to same destination
        beacon_destinations: Dict[str, List[str]] = defaultdict(list)
        for ip, profile in profiles.items():
            for beacon in profile.beacons:
                beacon_destinations[f"{beacon.dst_ip}:{beacon.dst_port}"].append(ip)

        for dest, sources in beacon_destinations.items():
            if len(sources) >= 2:
                correlations.append(ThreatCorrelation(
                    correlation_type="multi_host_beacon_cluster",
                    hosts=sources,
                    score=0.95,
                    confidence=0.9,
                    description=f"{len(sources)} hosts beaconing to common C2: {dest}",
                    evidence=[f"Hosts: {', '.join(sources)}"],
                    mitre_techniques=["T1071"],
                    timeline=[],
                ))

        return correlations

    def _apply_correlations(
        self,
        profiles: Dict[str, HostThreatProfile],
        correlations: List[ThreatCorrelation],
    ):
        """Enhance profiles with correlation data."""
        for correlation in correlations:
            for ip in correlation.hosts:
                if ip in profiles:
                    profile = profiles[ip]
                    # Boost score for correlated threats
                    profile.score = min(profile.score * 1.15, 1.0)
                    profile.all_reasons.append(
                        f"Correlation: {correlation.description}"
                    )

    def get_host_profile(self, ip: str) -> Optional[HostThreatProfile]:
        """Get threat profile for a specific host."""
        profiles = self.analyze_all()
        return profiles.get(ip)

    def get_top_threats(self, limit: int = 10) -> List[HostThreatProfile]:
        """Get top N threats by score."""
        profiles = self.analyze_all()
        sorted_profiles = sorted(
            profiles.values(),
            key=lambda x: x.score,
            reverse=True,
        )
        return sorted_profiles[:limit]

    def get_threats_by_level(
        self,
        threat_level: ThreatLevel,
    ) -> List[HostThreatProfile]:
        """Get all threats at a specific threat level."""
        profiles = self.analyze_all()
        return [
            p for p in profiles.values()
            if p.threat_level == threat_level
        ]

    def get_mitre_attack_overview(self) -> Dict:
        """Get overview of all observed MITRE ATT&CK techniques."""
        profiles = self.analyze_all()

        technique_counts: Dict[str, int] = defaultdict(int)
        tactic_counts: Dict[str, int] = defaultdict(int)
        affected_hosts: Dict[str, Set[str]] = defaultdict(set)

        for profile in profiles.values():
            for tech_id in profile.mitre_techniques:
                technique_counts[tech_id] += 1
                affected_hosts[tech_id].add(profile.ip)

                # Get tactics for technique
                technique = mitre_framework.get_technique(tech_id)
                if technique:
                    for tactic_id in technique.tactics:
                        tactic_counts[tactic_id] += 1

        return {
            "techniques": dict(technique_counts),
            "tactics": dict(tactic_counts),
            "affected_hosts": {
                tech_id: list(hosts)
                for tech_id, hosts in affected_hosts.items()
            },
        }
