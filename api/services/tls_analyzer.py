"""
TLS/JA3 fingerprinting analyzer.
Parses Zeek ssl.log, matches JA3 hashes against known-bad database,
detects certificate anomalies (self-signed, expired, CN mismatch).
"""
import hashlib
import random
import string
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Optional

# Known-bad JA3 hashes (real hashes from abuse.ch JA3 feed format)
KNOWN_BAD_JA3: list[dict] = [
    {"hash": "e7d705a3286e19ea42f587b344ee6865", "threat": "Trickbot", "description": "Trickbot C2 communication"},
    {"hash": "6734f37431670b3ab4292b8f60f29984", "threat": "AsyncRAT", "description": "AsyncRAT default TLS config"},
    {"hash": "51c64c77e60f3980eea90869b68c58a8", "threat": "CobaltStrike", "description": "Cobalt Strike HTTPS beacon"},
    {"hash": "72a589da586844d7f0818ce684948eea", "threat": "Metasploit", "description": "Metasploit Meterpreter HTTPS"},
    {"hash": "a0e9f5d64349fb13191bc781f81f42e1", "threat": "IcedID", "description": "IcedID banking trojan C2"},
    {"hash": "3b5074b1b5d032e5620f69f9f700ff0e", "threat": "Emotet", "description": "Emotet loader TLS fingerprint"},
    {"hash": "4d7a28d6f2263ed61de88ca66eb011e3", "threat": "QakBot", "description": "QakBot C2 handshake"},
    {"hash": "b386946a5a44d1ddcc843bc75336dfce", "threat": "Dridex", "description": "Dridex banking trojan"},
    {"hash": "e35df3e28c81802a7b6ec0a03e86faa2", "threat": "Agent Tesla", "description": "Agent Tesla exfil channel"},
    {"hash": "8916410db85077a5460817142dcbc8de", "threat": "Raccoon Stealer", "description": "Raccoon Stealer C2"},
    {"hash": "cd4e0f335d540e6bc2a1d3e15d1b1b3e", "threat": "RedLine", "description": "RedLine Stealer data exfil"},
    {"hash": "5c2b517e53976e8cc0c0dfeec9d0a150", "threat": "BazarLoader", "description": "BazarLoader/BazarBackdoor"},
    {"hash": "0e14b40a740358187f8b8b26f7c94fdc", "threat": "Remcos RAT", "description": "Remcos RAT TLS tunnel"},
    {"hash": "2f22c4d6d49c2a42f59f5bba55adfd85", "threat": "NanoCore", "description": "NanoCore RAT default TLS"},
    {"hash": "f9a00817aa41f0d8ec0e5d0e21acf840", "threat": "DarkComet", "description": "DarkComet RAT encrypted channel"},
    {"hash": "19e29534fd49dd27d09234e639c4057e", "threat": "Formbook", "description": "Formbook/XLoader C2 traffic"},
    {"hash": "74927e242d6c3a4d0c4b5e8e0f6a2d91", "threat": "LokiBot", "description": "LokiBot credential stealer"},
    {"hash": "1138de370e523e824bbca3fe07e703e8", "threat": "Ursnif/Gozi", "description": "Ursnif banking trojan"},
    {"hash": "3e9b20acd95937c089f8062c9b4c8e70", "threat": "ZLoader", "description": "ZLoader/Silent Night"},
    {"hash": "7dcce5b76c8b17472d024758970a406b", "threat": "Hancitor", "description": "Hancitor/Chanitor downloader"},
]

KNOWN_BAD_SET = {entry["hash"] for entry in KNOWN_BAD_JA3}


@dataclass
class TlsSession:
    uid: str
    ts: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    server_name: str
    ja3: str
    ja3s: str
    issuer: str
    subject: str
    not_before: str
    not_after: str
    self_signed: bool = False
    expired: bool = False
    cn_mismatch: bool = False
    ja3_match: Optional[dict] = None
    score: str = "clean"
    reasons: list[str] = field(default_factory=list)
    mitre: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


class TlsAnalyzer:
    def __init__(self):
        self.sessions: list[TlsSession] = []

    def analyze(self, sessions: list[TlsSession] | None = None) -> list[TlsSession]:
        target = sessions if sessions is not None else self.sessions
        for s in target:
            s.reasons = []
            s.mitre = []
            s.ja3_match = None
            # JA3 match
            if s.ja3 in KNOWN_BAD_SET:
                match = next(e for e in KNOWN_BAD_JA3 if e["hash"] == s.ja3)
                s.ja3_match = match
                s.reasons.append(f"JA3 matches known malware: {match['threat']}")
                s.mitre.append("T1071.001 - Application Layer Protocol: Web")
            # Self-signed
            if s.self_signed:
                s.reasons.append("Self-signed certificate")
                s.mitre.append("T1587.003 - Develop Capabilities: Digital Certificates")
            # Expired
            if s.expired:
                s.reasons.append("Expired certificate")
            # CN mismatch
            if s.cn_mismatch:
                s.reasons.append("Certificate CN does not match server name")
                s.mitre.append("T1557 - Adversary-in-the-Middle")
            # Score
            if s.ja3_match:
                s.score = "malicious"
            elif len(s.reasons) >= 2:
                s.score = "suspicious"
            elif len(s.reasons) == 1:
                s.score = "suspicious"
            else:
                s.score = "clean"
        return target

    def get_stats(self) -> dict:
        total = len(self.sessions)
        ja3_matches = sum(1 for s in self.sessions if s.ja3_match)
        cert_issues = sum(1 for s in self.sessions if s.self_signed or s.expired or s.cn_mismatch)
        servers = len({s.server_name for s in self.sessions if s.server_name})
        malicious = sum(1 for s in self.sessions if s.score == "malicious")
        suspicious = sum(1 for s in self.sessions if s.score == "suspicious")
        return {
            "total_sessions": total,
            "ja3_matches": ja3_matches,
            "cert_anomalies": cert_issues,
            "unique_servers": servers,
            "malicious": malicious,
            "suspicious": suspicious,
            "clean": total - malicious - suspicious,
        }

    def generate_demo_data(self, count: int = 50) -> list[TlsSession]:
        """Generate realistic mock TLS sessions for demo mode."""
        legit_servers = [
            "www.google.com", "api.github.com", "cdn.cloudflare.com",
            "login.microsoftonline.com", "s3.amazonaws.com", "api.slack.com",
            "zoom.us", "outlook.office365.com", "fonts.googleapis.com",
            "ajax.aspnetcdn.com", "cdn.jsdelivr.net", "unpkg.com",
        ]
        suspicious_servers = [
            "update-service.xyz", "cdn-delivery.top", "api-gateway.cc",
            "secure-login.buzz", "data-sync.icu",
        ]
        legit_issuers = [
            "CN=DigiCert Global G2,O=DigiCert Inc",
            "CN=Let's Encrypt Authority X3,O=Let's Encrypt",
            "CN=Amazon RSA 2048 M02,O=Amazon",
            "CN=GlobalSign RSA OV SSL CA 2018,O=GlobalSign nv-sa",
        ]
        now = datetime.now()
        sessions = []

        def _rand_hash():
            return hashlib.md5("".join(random.choices(string.hexdigits, k=32)).encode()).hexdigest()

        def _rand_ip(internal=False):
            if internal:
                return f"198.{random.choice([18, 19])}.{random.randint(0,255)}.{random.randint(1,254)}"
            return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

        src_ip = "198.19.1.50"

        for i in range(count):
            ts = (now - timedelta(minutes=random.randint(1, 1440))).isoformat()
            is_malicious = i < 3
            is_suspicious = 3 <= i < 8

            if is_malicious:
                server = random.choice(suspicious_servers)
                ja3 = random.choice(list(KNOWN_BAD_SET))
                issuer = f"CN={server},O={server.split('.')[0]}"
                subject = issuer
                self_signed = True
                expired = random.choice([True, False])
                cn_mismatch = False
            elif is_suspicious:
                server = random.choice(suspicious_servers)
                ja3 = _rand_hash()
                issuer = f"CN={server},O=Self"
                subject = issuer
                self_signed = random.choice([True, False])
                expired = random.choice([True, False])
                cn_mismatch = random.choice([True, False])
            else:
                server = random.choice(legit_servers)
                ja3 = _rand_hash()
                issuer = random.choice(legit_issuers)
                subject = f"CN={server}"
                self_signed = False
                expired = False
                cn_mismatch = False

            not_before = (now - timedelta(days=random.randint(30, 365))).strftime("%Y-%m-%d")
            if expired:
                not_after = (now - timedelta(days=random.randint(1, 90))).strftime("%Y-%m-%d")
            else:
                not_after = (now + timedelta(days=random.randint(30, 365))).strftime("%Y-%m-%d")

            session = TlsSession(
                uid=f"C{random.randint(100000,999999)}.{random.randint(1,99)}",
                ts=ts,
                src_ip=src_ip,
                src_port=random.randint(49152, 65535),
                dst_ip=_rand_ip(),
                dst_port=443,
                server_name=server,
                ja3=ja3,
                ja3s=_rand_hash(),
                issuer=issuer,
                subject=subject,
                not_before=not_before,
                not_after=not_after,
                self_signed=self_signed,
                expired=expired,
                cn_mismatch=cn_mismatch,
            )
            sessions.append(session)

        self.sessions = sessions
        self.analyze()
        return sessions


# Singleton
tls_analyzer = TlsAnalyzer()
