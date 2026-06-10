"""
HTTP anomaly detection service.
Detects unusual user-agents, methods, large POSTs, directory traversal, suspicious URIs.
"""
import random
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import Optional

SUSPICIOUS_USER_AGENTS = [
    "python-requests/2.28.0", "curl/7.88.1", "Go-http-client/1.1",
    "Wget/1.21", "sqlmap/1.7", "Nikto/2.5", "DirBuster/1.0",
    "Hydra/9.5", "", "Mozilla/4.0 (compatible; MSIE 6.0)",
    "masscan/1.3", "Nmap Scripting Engine", "ZmEu",
]

NORMAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edge/120.0.0.0",
]

SUSPICIOUS_METHODS = {"PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT", "PATCH"}

TRAVERSAL_PATTERNS = ["../", "..\\", "%2e%2e", "%252e", "/etc/passwd", "/proc/self", "cmd.exe", "powershell"]

SUSPICIOUS_URI_PATTERNS = [
    "/admin", "/wp-login", "/phpmyadmin", "/.env", "/.git",
    "/shell", "/cmd", "/exec", "/eval", "/debug",
    "/actuator", "/api/console", "/solr", "/manager/html",
]


@dataclass
class HttpSession:
    uid: str
    ts: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    method: str
    uri: str
    user_agent: str
    status_code: int
    request_body_len: int
    response_body_len: int
    anomalies: list[str] = field(default_factory=list)
    score: str = "clean"
    mitre: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class HttpAnalyzer:
    def __init__(self):
        self.sessions: list[HttpSession] = []

    def analyze(self, sessions: list[HttpSession] | None = None) -> list[HttpSession]:
        target = sessions if sessions is not None else self.sessions
        for s in target:
            s.anomalies = []
            s.mitre = []

            # Unusual user-agent
            if s.user_agent in SUSPICIOUS_USER_AGENTS or not s.user_agent:
                s.anomalies.append(f"Suspicious user-agent: {s.user_agent or '(empty)'}")
                s.mitre.append("T1071.001 - Web Protocols")

            # Unusual method
            if s.method.upper() in SUSPICIOUS_METHODS:
                s.anomalies.append(f"Unusual HTTP method: {s.method}")

            # Large POST (potential exfil)
            if s.method.upper() == "POST" and s.request_body_len > 1_000_000:
                s.anomalies.append(f"Large POST body: {s.request_body_len:,} bytes")
                s.mitre.append("T1048 - Exfiltration Over Alternative Protocol")

            # Directory traversal
            uri_lower = s.uri.lower()
            for pattern in TRAVERSAL_PATTERNS:
                if pattern in uri_lower:
                    s.anomalies.append(f"Directory traversal attempt: {pattern}")
                    s.mitre.append("T1083 - File and Directory Discovery")
                    break

            # Suspicious URI
            for pattern in SUSPICIOUS_URI_PATTERNS:
                if pattern in uri_lower:
                    s.anomalies.append(f"Suspicious URI pattern: {pattern}")
                    s.mitre.append("T1190 - Exploit Public-Facing Application")
                    break

            # Score
            if len(s.anomalies) >= 3:
                s.score = "malicious"
            elif len(s.anomalies) >= 1:
                s.score = "suspicious"
            else:
                s.score = "clean"

        return target

    def get_stats(self) -> dict:
        total = len(self.sessions)
        anomalous = sum(1 for s in self.sessions if s.anomalies)
        methods = {}
        uas = {}
        for s in self.sessions:
            methods[s.method] = methods.get(s.method, 0) + 1
            ua_short = (s.user_agent or "(empty)")[:50]
            uas[ua_short] = uas.get(ua_short, 0) + 1
        return {
            "total_requests": total,
            "anomalies_found": anomalous,
            "top_methods": sorted(methods.items(), key=lambda x: -x[1])[:10],
            "top_user_agents": sorted(uas.items(), key=lambda x: -x[1])[:10],
            "malicious": sum(1 for s in self.sessions if s.score == "malicious"),
            "suspicious": sum(1 for s in self.sessions if s.score == "suspicious"),
        }

    def generate_demo_data(self, count: int = 80) -> list[HttpSession]:
        now = datetime.now()
        sessions = []
        src_ip = "198.19.1.50"
        normal_uris = ["/", "/index.html", "/api/v1/users", "/assets/main.css", "/favicon.ico", "/api/health"]

        for i in range(count):
            ts = (now - timedelta(minutes=random.randint(1, 1440))).isoformat()
            is_attack = i < 5
            is_scan = 5 <= i < 12

            if is_attack:
                method = random.choice(["POST", "PUT", "GET"])
                uri = random.choice([
                    "/../../etc/passwd", "/admin/exec?cmd=id", "/.env",
                    "/wp-login.php", "/api/console",
                ])
                ua = random.choice(SUSPICIOUS_USER_AGENTS)
                body_len = random.randint(0, 5_000_000) if method == "POST" else 0
                status = random.choice([200, 403, 500])
            elif is_scan:
                method = random.choice(["GET", "HEAD", "OPTIONS", "TRACE"])
                uri = random.choice(SUSPICIOUS_URI_PATTERNS + normal_uris)
                ua = random.choice(SUSPICIOUS_USER_AGENTS[:6])
                body_len = 0
                status = random.choice([200, 301, 404])
            else:
                method = random.choice(["GET", "GET", "GET", "POST", "HEAD"])
                uri = random.choice(normal_uris)
                ua = random.choice(NORMAL_USER_AGENTS)
                body_len = random.randint(100, 50000) if method == "POST" else 0
                status = 200

            session = HttpSession(
                uid=f"C{random.randint(100000,999999)}.{random.randint(1,99)}",
                ts=ts, src_ip=src_ip, src_port=random.randint(49152, 65535),
                dst_ip=f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}",
                dst_port=random.choice([80, 443, 8080, 8443]),
                method=method, uri=uri, user_agent=ua,
                status_code=status, request_body_len=body_len,
                response_body_len=random.randint(200, 500000),
            )
            sessions.append(session)

        self.sessions = sessions
        self.analyze()
        return sessions


http_analyzer = HttpAnalyzer()
