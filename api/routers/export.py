"""
IOC Export Router - Export threat indicators in CSV, STIX 2.1, and OpenIOC formats.
"""
import csv
import io
import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Query, Response
from fastapi.responses import StreamingResponse

from api.services.log_store import LogStore, log_store
from api.services.unified_threat_engine import UnifiedThreatEngine
from api.models.threat import ThreatLevel

router = APIRouter()


def _get_engine() -> UnifiedThreatEngine:
    return UnifiedThreatEngine(log_store)


def _severity_filter(level: ThreatLevel, min_severity: str) -> bool:
    """Check if threat level meets minimum severity."""
    order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    return order.get(level.value, 0) >= order.get(min_severity, 0)


def _collect_iocs(min_severity: str = "low", types: Optional[str] = None, limit: int = 1000):
    """Collect IOCs from the threat engine."""
    engine = _get_engine()
    profiles = engine.analyze_all()

    type_filter = set(types.split(",")) if types else None
    iocs = []

    for ip, profile in profiles.items():
        if not _severity_filter(profile.threat_level, min_severity):
            continue

        # IP indicator
        if type_filter is None or "ip" in type_filter:
            iocs.append({
                "indicator": ip,
                "type": "ip",
                "severity": profile.threat_level.value,
                "score": round(profile.score * 100, 1),
                "first_seen": datetime.fromtimestamp(profile.first_seen, tz=timezone.utc).isoformat() if profile.first_seen else "",
                "last_seen": datetime.fromtimestamp(profile.last_seen, tz=timezone.utc).isoformat() if profile.last_seen else "",
                "mitre_techniques": ",".join(sorted(profile.mitre_techniques)),
                "source": "vervet",
                "context": profile.attack_summary,
                "beacon_count": profile.beacon_count,
                "dns_threat_count": profile.dns_threat_count,
                "alert_count": profile.alert_count,
            })

        # Domain indicators from DNS threats
        if type_filter is None or "domain" in type_filter:
            for domain in sorted(profile.related_domains):
                iocs.append({
                    "indicator": domain,
                    "type": "domain",
                    "severity": profile.threat_level.value,
                    "score": round(profile.score * 100, 1),
                    "first_seen": datetime.fromtimestamp(profile.first_seen, tz=timezone.utc).isoformat() if profile.first_seen else "",
                    "last_seen": datetime.fromtimestamp(profile.last_seen, tz=timezone.utc).isoformat() if profile.last_seen else "",
                    "mitre_techniques": ",".join(sorted(profile.mitre_techniques)),
                    "source": "vervet",
                    "context": f"Related to {ip}",
                    "beacon_count": 0,
                    "dns_threat_count": profile.dns_threat_count,
                    "alert_count": 0,
                })

        if len(iocs) >= limit:
            break

    return iocs[:limit]


@router.get("/iocs")
async def export_iocs(
    format: str = Query("csv", regex="^(csv|stix|openioc)$"),
    min_severity: str = Query("low", regex="^(info|low|medium|high|critical)$"),
    types: Optional[str] = Query(None, description="Comma-separated: ip,domain,hash"),
    limit: int = Query(1000, ge=1, le=10000),
):
    """Export IOCs in CSV, STIX 2.1, or OpenIOC format."""
    iocs = _collect_iocs(min_severity=min_severity, types=types, limit=limit)

    if format == "csv":
        return _export_csv(iocs)
    elif format == "stix":
        return _export_stix(iocs)
    elif format == "openioc":
        return _export_openioc(iocs)


def _export_csv(iocs: list) -> StreamingResponse:
    """Export as CSV."""
    output = io.StringIO()
    fields = ["indicator", "type", "severity", "score", "first_seen", "last_seen", "mitre_techniques", "source", "context"]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for ioc in iocs:
        writer.writerow(ioc)

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vervet-iocs.csv"},
    )


def _export_stix(iocs: list) -> Response:
    """Export as STIX 2.1 Bundle."""
    objects = []

    # Identity for Vervet
    identity_id = "identity--" + str(uuid.uuid5(uuid.NAMESPACE_URL, "vervet"))
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "modified": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "name": "Vervet",
        "identity_class": "tool",
    })

    severity_to_confidence = {"critical": 95, "high": 80, "medium": 60, "low": 40, "info": 20}

    for ioc in iocs:
        indicator_id = "indicator--" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"vervet:{ioc['indicator']}"))

        # Build STIX pattern
        if ioc["type"] == "ip":
            pattern = f"[ipv4-addr:value = '{ioc['indicator']}']"
        elif ioc["type"] == "domain":
            pattern = f"[domain-name:value = '{ioc['indicator']}']"
        elif ioc["type"] == "hash":
            pattern = f"[file:hashes.'SHA-256' = '{ioc['indicator']}']"
        else:
            pattern = f"[artifact:payload_bin = '{ioc['indicator']}']"

        labels = [ioc["severity"]]
        if ioc.get("mitre_techniques"):
            labels.extend(ioc["mitre_techniques"].split(",")[:3])

        obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "modified": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "name": f"{ioc['type'].upper()}: {ioc['indicator']}",
            "description": ioc.get("context", ""),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": ioc.get("first_seen") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "labels": labels,
            "confidence": severity_to_confidence.get(ioc["severity"], 50),
            "created_by_ref": identity_id,
        }
        objects.append(obj)

    bundle = {
        "type": "bundle",
        "id": "bundle--" + str(uuid.uuid4()),
        "objects": objects,
    }

    return Response(
        content=json.dumps(bundle, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=vervet-iocs.stix.json"},
    )


def _export_openioc(iocs: list) -> Response:
    """Export as OpenIOC XML."""
    lines = [
        '<?xml version="1.0" encoding="utf-8"?>',
        f'<ioc xmlns="http://schemas.mandiant.com/2010/ioc" id="{uuid.uuid4()}" last-modified="{datetime.now(timezone.utc).isoformat()}">',
        '  <short_description>Vervet IOC Export</short_description>',
        '  <description>Indicators of Compromise exported from Vervet threat analysis</description>',
        '  <definition>',
        '    <Indicator operator="OR">',
    ]

    for ioc in iocs:
        if ioc["type"] == "ip":
            search = "PortItem/remoteIP"
            content_type = "IP"
        elif ioc["type"] == "domain":
            search = "DnsEntryItem/RecordName"
            content_type = "string"
        elif ioc["type"] == "hash":
            search = "FileItem/Sha256sum"
            content_type = "sha256"
        else:
            search = "Network/String"
            content_type = "string"

        lines.append(f'      <IndicatorItem condition="is">')
        lines.append(f'        <Context document="ioc" search="{search}" type="mir" />')
        lines.append(f'        <Content type="{content_type}">{ioc["indicator"]}</Content>')
        lines.append(f'        <Comment>{ioc["severity"]} severity - {ioc.get("context", "")}</Comment>')
        lines.append(f'      </IndicatorItem>')

    lines.extend([
        '    </Indicator>',
        '  </definition>',
        '</ioc>',
    ])

    xml_content = "\n".join(lines)
    return Response(
        content=xml_content,
        media_type="application/xml",
        headers={"Content-Disposition": "attachment; filename=vervet-iocs.xml"},
    )
