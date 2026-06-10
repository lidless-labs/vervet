"""
Data models for Vervet API.
Provides Pydantic models for log parsing, validation, and threat analysis.
"""
from api.models.zeek import *
from api.models.suricata import *
from api.models.threat import *
from api.models.beacon import *
from api.models.dns_threat import *

__all__ = [
    # Zeek models
    "ConnLog",
    "DnsLog",
    "HttpLog",
    "SslLog",
    "X509Log",
    "FilesLog",
    "NoticeLog",
    "WeirdLog",
    "DpdLog",
    "SmtpLog",
    # Suricata models
    "SuricataAlert",
    "SuricataFlow",
    "SuricataDns",
    "SuricataHttp",
    "SuricataTls",
    # Threat models
    "ThreatScore",
    "ThreatIndicator",
    "HuntResult",
    "MitreMapping",
    # Beacon models
    "BeaconResult",
    "BeaconDetailedResult",
    "BeaconIntervalHistogram",
    # DNS threat models
    "DnsTunnelingResult",
    "DgaResult",
    "DnsFastFluxResult",
    "SuspiciousDnsPattern",
    "DnsThreatSummary",
]
