"""
Threat Intelligence Feed Integration.

Supports:
- AlienVault OTX (Open Threat Exchange)
- AbuseIPDB
- Local blocklist files

All lookups are async with caching to avoid rate limits.
"""
import os
import time
import logging
import json
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict

import httpx

logger = logging.getLogger(__name__)

# Cache TTL in seconds (1 hour)
CACHE_TTL = 3600


@dataclass
class ThreatIntelResult:
    """Result from a threat intelligence lookup."""
    indicator: str
    indicator_type: str  # ip, domain, hash
    source: str  # otx, abuseipdb, local
    malicious: bool
    confidence: float  # 0-1
    categories: List[str] = field(default_factory=list)
    description: str = ""
    first_seen: str = ""
    last_seen: str = ""
    references: List[str] = field(default_factory=list)
    raw: Dict = field(default_factory=dict)


@dataclass
class IntelSummary:
    """Aggregated intel for an indicator across all sources."""
    indicator: str
    indicator_type: str
    sources_checked: int = 0
    sources_flagged: int = 0
    max_confidence: float = 0.0
    is_malicious: bool = False
    results: List[ThreatIntelResult] = field(default_factory=list)
    categories: Set[str] = field(default_factory=set)


class ThreatIntelService:
    """Aggregates threat intelligence from multiple feeds."""

    def __init__(self):
        self.otx_key = os.environ.get("VERVET_OTX_KEY", "")
        self.abuseipdb_key = os.environ.get("VERVET_ABUSEIPDB_KEY", "")
        self._cache: Dict[str, tuple] = {}  # key -> (result, timestamp)
        self._local_blocklist: Set[str] = set()
        self._load_local_blocklist()

    def _load_local_blocklist(self):
        """Load local blocklist from file if exists."""
        blocklist_path = os.path.join(
            os.path.dirname(__file__), "..", "config", "blocklist.txt"
        )
        if os.path.exists(blocklist_path):
            with open(blocklist_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self._local_blocklist.add(line.lower())
            logger.info(f"Loaded {len(self._local_blocklist)} local blocklist entries")

    def _cache_get(self, key: str) -> Optional[ThreatIntelResult]:
        """Get cached result if not expired."""
        if key in self._cache:
            result, ts = self._cache[key]
            if time.time() - ts < CACHE_TTL:
                return result
            del self._cache[key]
        return None

    def _cache_set(self, key: str, result: ThreatIntelResult):
        """Cache a result."""
        self._cache[key] = (result, time.time())

    async def lookup_ip(self, ip: str) -> IntelSummary:
        """Look up an IP address across all configured sources."""
        summary = IntelSummary(indicator=ip, indicator_type="ip")

        # Local blocklist
        if ip.lower() in self._local_blocklist:
            summary.results.append(ThreatIntelResult(
                indicator=ip,
                indicator_type="ip",
                source="local_blocklist",
                malicious=True,
                confidence=1.0,
                description="Found in local blocklist",
            ))
            summary.sources_checked += 1
            summary.sources_flagged += 1

        # AbuseIPDB
        if self.abuseipdb_key:
            result = await self._lookup_abuseipdb(ip)
            if result:
                summary.results.append(result)
                summary.sources_checked += 1
                if result.malicious:
                    summary.sources_flagged += 1
                    summary.categories.update(result.categories)

        # AlienVault OTX
        if self.otx_key:
            result = await self._lookup_otx_ip(ip)
            if result:
                summary.results.append(result)
                summary.sources_checked += 1
                if result.malicious:
                    summary.sources_flagged += 1
                    summary.categories.update(result.categories)

        # Aggregate
        if summary.results:
            summary.max_confidence = max(r.confidence for r in summary.results)
            summary.is_malicious = any(r.malicious for r in summary.results)

        return summary

    async def lookup_domain(self, domain: str) -> IntelSummary:
        """Look up a domain across all configured sources."""
        summary = IntelSummary(indicator=domain, indicator_type="domain")

        # Local blocklist
        if domain.lower() in self._local_blocklist:
            summary.results.append(ThreatIntelResult(
                indicator=domain,
                indicator_type="domain",
                source="local_blocklist",
                malicious=True,
                confidence=1.0,
                description="Found in local blocklist",
            ))
            summary.sources_checked += 1
            summary.sources_flagged += 1

        # AlienVault OTX
        if self.otx_key:
            result = await self._lookup_otx_domain(domain)
            if result:
                summary.results.append(result)
                summary.sources_checked += 1
                if result.malicious:
                    summary.sources_flagged += 1
                    summary.categories.update(result.categories)

        if summary.results:
            summary.max_confidence = max(r.confidence for r in summary.results)
            summary.is_malicious = any(r.malicious for r in summary.results)

        return summary

    async def bulk_lookup(self, indicators: List[Dict[str, str]]) -> List[IntelSummary]:
        """Bulk lookup multiple indicators. Each dict has 'value' and 'type' keys."""
        results = []
        for ind in indicators:
            value = ind.get("value", "")
            ind_type = ind.get("type", "ip")
            if ind_type == "ip":
                results.append(await self.lookup_ip(value))
            elif ind_type == "domain":
                results.append(await self.lookup_domain(value))
        return results

    async def _lookup_abuseipdb(self, ip: str) -> Optional[ThreatIntelResult]:
        """Query AbuseIPDB for an IP."""
        cache_key = f"abuseipdb:{ip}"
        cached = self._cache_get(cache_key)
        if cached:
            return cached

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                    headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                )
                if resp.status_code != 200:
                    logger.warning(f"AbuseIPDB returned {resp.status_code} for {ip}")
                    return None

                data = resp.json().get("data", {})
                abuse_score = data.get("abuseConfidenceScore", 0)
                # Extract unique category IDs from verbose reports
                cat_ids = set()
                for report in data.get("reports", []):
                    for cat_id in report.get("categories", []):
                        cat_ids.add(cat_id)
                categories = [str(c) for c in sorted(cat_ids)]

                result = ThreatIntelResult(
                    indicator=ip,
                    indicator_type="ip",
                    source="abuseipdb",
                    malicious=abuse_score >= 50,
                    confidence=abuse_score / 100.0,
                    categories=categories,
                    description=f"Abuse score: {abuse_score}%, {data.get('totalReports', 0)} reports",
                    last_seen=data.get("lastReportedAt", ""),
                    raw=data,
                )
                self._cache_set(cache_key, result)
                return result

        except Exception as e:
            logger.error(f"AbuseIPDB lookup failed for {ip}: {e}")
            return None

    async def _lookup_otx_ip(self, ip: str) -> Optional[ThreatIntelResult]:
        """Query AlienVault OTX for an IP."""
        cache_key = f"otx:ip:{ip}"
        cached = self._cache_get(cache_key)
        if cached:
            return cached

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                    headers={"X-OTX-API-KEY": self.otx_key},
                )
                if resp.status_code != 200:
                    return None

                data = resp.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                pulses = data.get("pulse_info", {}).get("pulses", [])
                categories = list(set(
                    tag for p in pulses[:5] for tag in p.get("tags", [])
                ))[:10]

                result = ThreatIntelResult(
                    indicator=ip,
                    indicator_type="ip",
                    source="otx",
                    malicious=pulse_count > 0,
                    confidence=min(pulse_count / 10.0, 1.0),
                    categories=categories,
                    description=f"Found in {pulse_count} OTX pulse(s)",
                    references=[p.get("name", "") for p in pulses[:3]],
                    raw={"pulse_count": pulse_count},
                )
                self._cache_set(cache_key, result)
                return result

        except Exception as e:
            logger.error(f"OTX lookup failed for {ip}: {e}")
            return None

    async def _lookup_otx_domain(self, domain: str) -> Optional[ThreatIntelResult]:
        """Query AlienVault OTX for a domain."""
        cache_key = f"otx:domain:{domain}"
        cached = self._cache_get(cache_key)
        if cached:
            return cached

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
                    headers={"X-OTX-API-KEY": self.otx_key},
                )
                if resp.status_code != 200:
                    return None

                data = resp.json()
                pulse_count = data.get("pulse_info", {}).get("count", 0)
                pulses = data.get("pulse_info", {}).get("pulses", [])
                categories = list(set(
                    tag for p in pulses[:5] for tag in p.get("tags", [])
                ))[:10]

                result = ThreatIntelResult(
                    indicator=domain,
                    indicator_type="domain",
                    source="otx",
                    malicious=pulse_count > 0,
                    confidence=min(pulse_count / 10.0, 1.0),
                    categories=categories,
                    description=f"Found in {pulse_count} OTX pulse(s)",
                    references=[p.get("name", "") for p in pulses[:3]],
                    raw={"pulse_count": pulse_count},
                )
                self._cache_set(cache_key, result)
                return result

        except Exception as e:
            logger.error(f"OTX domain lookup failed for {domain}: {e}")
            return None

    def get_status(self) -> Dict:
        """Get threat intel service status."""
        return {
            "sources": {
                "abuseipdb": {"configured": bool(self.abuseipdb_key), "type": "api"},
                "otx": {"configured": bool(self.otx_key), "type": "api"},
                "local_blocklist": {
                    "configured": len(self._local_blocklist) > 0,
                    "entries": len(self._local_blocklist),
                    "type": "file",
                },
            },
            "cache_entries": len(self._cache),
            "cache_ttl_seconds": CACHE_TTL,
        }
