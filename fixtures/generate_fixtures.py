#!/usr/bin/env python3
"""
Generate realistic fixture data for Vervet - Zeek and Suricata logs.
Creates JSON log files with diverse, realistic network traffic patterns.
"""
import json
import random
from datetime import datetime, timedelta

# Base timestamp - 7 days ago
BASE_TIME = datetime.now() - timedelta(days=7)

# Realistic IP addresses for internal/external hosts
INTERNAL_IPS = [
    "192.0.2.10", "192.0.2.15", "192.0.2.20", "192.0.2.25",
    "203.0.113.5", "203.0.113.10", "203.0.113.15", "198.18.161.100"
]

EXTERNAL_IPS = [
    "93.184.216.34",  # example.com
    "142.250.185.46",  # google.com
    "104.244.42.129",  # twitter.com
    "157.240.3.35",  # facebook.com
    "185.199.108.153",  # github.com
    "151.101.1.69",  # reddit.com
    "13.107.42.14",  # microsoft.com
    "23.50.91.12",  # suspicious
    "45.33.32.156",  # scanner
]

DOMAINS = [
    "google.com", "facebook.com", "twitter.com", "reddit.com", "github.com",
    "microsoft.com", "amazon.com", "netflix.com", "youtube.com", "apple.com",
    "malicious-site.ru", "phishing-example.xyz", "suspicious-domain.tk"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "curl/7.68.0",
    "python-requests/2.28.1",
    "Suspicious-Scanner/1.0"
]

CONN_STATES = ["SF", "S0", "S1", "REJ", "RSTO", "RSTOS0", "RSTR", "SH", "SHR"]
PROTOCOLS = ["tcp", "udp", "icmp"]


def random_timestamp(offset_hours=0):
    """Generate random timestamp with optional hour offset."""
    return (BASE_TIME + timedelta(hours=offset_hours, minutes=random.randint(0, 59))).timestamp()


def random_uid():
    """Generate Zeek-style UID."""
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    return "C" + "".join(random.choice(chars) for _ in range(17))


def generate_conn_logs(count=50):
    """Generate connection log entries."""
    logs = []
    for i in range(count):
        src_ip = random.choice(INTERNAL_IPS)
        dst_ip = random.choice(EXTERNAL_IPS)
        proto = random.choice(PROTOCOLS)

        # Varied port patterns
        if proto == "tcp":
            dst_port = random.choice([80, 443, 22, 3389, 8080, 8443, 445, 139, 3306, 5432])
        elif proto == "udp":
            dst_port = random.choice([53, 123, 161, 514, 1900])
        else:
            dst_port = 0

        log = {
            "ts": random_timestamp(i // 3),
            "uid": random_uid(),
            "id_orig_h": src_ip,
            "id_orig_p": random.randint(49152, 65535),
            "id_resp_h": dst_ip,
            "id_resp_p": dst_port,
            "proto": proto,
            "service": random.choice(["http", "https", "ssh", "dns", None]),
            "duration": round(random.uniform(0.001, 120.0), 3),
            "orig_bytes": random.randint(100, 100000),
            "resp_bytes": random.randint(100, 500000),
            "conn_state": random.choice(CONN_STATES),
            "missed_bytes": 0 if random.random() > 0.1 else random.randint(0, 1000),
            "orig_pkts": random.randint(1, 500),
            "resp_pkts": random.randint(1, 500),
        }
        logs.append(log)
    return logs


def generate_dns_logs(count=50):
    """Generate DNS query log entries."""
    logs = []
    for i in range(count):
        query_type = random.choice(["A", "AAAA", "MX", "TXT", "CNAME", "PTR"])
        domain = random.choice(DOMAINS)

        log = {
            "ts": random_timestamp(i // 3),
            "uid": random_uid(),
            "id_orig_h": random.choice(INTERNAL_IPS),
            "id_orig_p": random.randint(49152, 65535),
            "id_resp_h": "8.8.8.8" if random.random() > 0.3 else "1.1.1.1",
            "id_resp_p": 53,
            "proto": "udp",
            "trans_id": random.randint(1, 65535),
            "query": domain,
            "qclass": 1,
            "qclass_name": "C_INTERNET",
            "qtype": {"A": 1, "AAAA": 28, "MX": 15, "TXT": 16, "CNAME": 5, "PTR": 12}[query_type],
            "qtype_name": query_type,
            "rcode": 0 if random.random() > 0.1 else random.choice([2, 3, 5]),
            "rcode_name": "NOERROR" if random.random() > 0.1 else random.choice(["SERVFAIL", "NXDOMAIN", "REFUSED"]),
            "AA": random.choice([True, False]),
            "RD": True,
            "RA": True,
        }

        if log["rcode"] == 0 and query_type == "A":
            log["answers"] = [random.choice(EXTERNAL_IPS)]
            log["TTLs"] = [random.randint(60, 86400)]

        logs.append(log)
    return logs


def generate_http_logs(count=50):
    """Generate HTTP request log entries."""
    logs = []
    uris = ["/", "/index.html", "/api/data", "/login", "/admin", "/wp-admin", "/uploads/shell.php", "/api/users"]
    methods = ["GET", "POST", "PUT", "DELETE", "HEAD"]

    for i in range(count):
        method = random.choice(methods)
        uri = random.choice(uris)
        status = random.choice([200, 301, 302, 400, 401, 403, 404, 500, 502, 503])

        log = {
            "ts": random_timestamp(i // 3),
            "uid": random_uid(),
            "id_orig_h": random.choice(INTERNAL_IPS),
            "id_orig_p": random.randint(49152, 65535),
            "id_resp_h": random.choice(EXTERNAL_IPS),
            "id_resp_p": random.choice([80, 443, 8080]),
            "method": method,
            "host": random.choice(DOMAINS),
            "uri": uri,
            "version": "1.1",
            "user_agent": random.choice(USER_AGENTS),
            "request_body_len": random.randint(0, 10000) if method in ["POST", "PUT"] else 0,
            "response_body_len": random.randint(100, 100000),
            "status_code": status,
            "status_msg": {200: "OK", 301: "Moved", 302: "Found", 400: "Bad Request",
                          401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
                          500: "Internal Server Error"}. get(status, "Unknown"),
        }
        logs.append(log)
    return logs


def generate_ssl_logs(count=50):
    """Generate SSL/TLS handshake log entries."""
    logs = []
    versions = ["TLSv12", "TLSv13", "TLSv11", "SSLv3"]
    ciphers = [
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        "TLS_AES_128_GCM_SHA256",
        "TLS_CHACHA20_POLY1305_SHA256"
    ]

    for i in range(count):
        domain = random.choice(DOMAINS)
        log = {
            "ts": random_timestamp(i // 3),
            "uid": random_uid(),
            "id_orig_h": random.choice(INTERNAL_IPS),
            "id_orig_p": random.randint(49152, 65535),
            "id_resp_h": random.choice(EXTERNAL_IPS),
            "id_resp_p": 443,
            "version": random.choice(versions),
            "cipher": random.choice(ciphers),
            "server_name": domain,
            "established": random.random() > 0.05,
            "subject": f"CN={domain}",
            "issuer": random.choice(["CN=Let's Encrypt", "CN=DigiCert", "CN=GlobalSign"]),
        }
        logs.append(log)
    return logs


def generate_x509_logs(count=50):
    """Generate X.509 certificate log entries."""
    logs = []
    for i in range(count):
        domain = random.choice(DOMAINS)
        not_before = BASE_TIME - timedelta(days=random.randint(30, 730))
        not_after = not_before + timedelta(days=random.randint(365, 825))

        log = {
            "ts": random_timestamp(i // 3),
            "fingerprint": "".join(random.choice("0123456789abcdef") for _ in range(40)),
            "certificate_version": 3,
            "certificate_subject": f"CN={domain}",
            "certificate_issuer": random.choice(["CN=Let's Encrypt Authority X3", "CN=DigiCert SHA2 Secure Server CA"]),
            "certificate_not_valid_before": not_before.timestamp(),
            "certificate_not_valid_after": not_after.timestamp(),
            "certificate_key_alg": "rsaEncryption",
            "certificate_sig_alg": "sha256WithRSAEncryption",
            "certificate_key_type": "rsa",
            "certificate_key_length": random.choice([2048, 4096]),
            "san_dns": [domain, f"www.{domain}"] if random.random() > 0.3 else None,
        }
        logs.append(log)
    return logs


def generate_files_logs(count=50):
    """Generate file transfer log entries."""
    logs = []
    mime_types = [
        "text/html", "application/json", "application/pdf",
        "application/zip", "application/x-executable",
        "application/x-dosexec", "text/plain"
    ]

    for i in range(count):
        mime = random.choice(mime_types)
        log = {
            "ts": random_timestamp(i // 3),
            "fuid": "F" + "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(17)),
            "tx_hosts": [random.choice(EXTERNAL_IPS)],
            "rx_hosts": [random.choice(INTERNAL_IPS)],
            "source": random.choice(["HTTP", "SMTP", "FTP"]),
            "depth": 0,
            "mime_type": mime,
            "filename": f"file_{i}.{mime.split('/')[-1][:3]}",
            "seen_bytes": random.randint(1024, 10485760),
            "total_bytes": random.randint(1024, 10485760),
            "missing_bytes": 0,
            "timedout": False,
        }

        if random.random() > 0.5:
            log["md5"] = "".join(random.choice("0123456789abcdef") for _ in range(32))
            log["sha1"] = "".join(random.choice("0123456789abcdef") for _ in range(40))
            log["sha256"] = "".join(random.choice("0123456789abcdef") for _ in range(64))

        logs.append(log)
    return logs


def generate_notice_logs(count=50):
    """Generate notice/alert log entries."""
    logs = []
    notice_types = [
        "Scan::Port_Scan", "Scan::Address_Scan", "SSH::Login",
        "HTTP::SQL_Injection_Attacker", "Malware::Detected",
        "Intel::Notice", "SSL::Invalid_Server_Cert"
    ]

    for i in range(count):
        src = random.choice(INTERNAL_IPS if random.random() > 0.3 else EXTERNAL_IPS)
        dst = random.choice(EXTERNAL_IPS if src in INTERNAL_IPS else INTERNAL_IPS)

        log = {
            "ts": random_timestamp(i // 3),
            "uid": random_uid() if random.random() > 0.2 else None,
            "id_orig_h": src,
            "id_orig_p": random.randint(1, 65535),
            "id_resp_h": dst,
            "id_resp_p": random.randint(1, 65535),
            "proto": random.choice(["tcp", "udp"]),
            "note": random.choice(notice_types),
            "msg": f"Suspicious activity detected from {src}",
            "actions": [random.choice(["Notice::ACTION_LOG", "Notice::ACTION_EMAIL"])],
        }
        logs.append(log)
    return logs


def generate_suricata_alerts(count=30):
    """Generate Suricata eve.json alert entries."""
    alerts = []
    categories = [
        "Attempted Administrator Privilege Gain",
        "Potentially Bad Traffic",
        "Misc activity",
        "Attempted Information Leak",
        "A Network Trojan was detected"
    ]

    signatures = [
        "ET SCAN Suspicious inbound to mySQL port 3306",
        "ET POLICY PE EXE or DLL Windows file download HTTP",
        "ET MALWARE Known Malware C2 Traffic",
        "ET SCAN Nmap Scripting Engine User-Agent Detected",
        "ET POLICY Suspicious inbound to SMB port 445",
        "ET EXPLOIT Possible SQL Injection",
        "ET SCAN SSH Brute Force",
    ]

    for i in range(count):
        src = random.choice(EXTERNAL_IPS)
        dst = random.choice(INTERNAL_IPS)
        proto = random.choice(["TCP", "UDP"])

        alert = {
            "timestamp": (BASE_TIME + timedelta(hours=i // 2, minutes=random.randint(0, 59))).isoformat() + "Z",
            "flow_id": random.randint(100000, 9999999),
            "event_type": "alert",
            "src_ip": src,
            "src_port": random.randint(1024, 65535),
            "dest_ip": dst,
            "dest_port": random.choice([22, 80, 443, 445, 3306, 3389, 8080]),
            "proto": proto,
            "alert": {
                "action": random.choice(["allowed", "blocked"]),
                "gid": 1,
                "signature_id": random.randint(2000000, 2999999),
                "rev": random.randint(1, 10),
                "signature": random.choice(signatures),
                "category": random.choice(categories),
                "severity": random.randint(1, 3),
            },
            "flow": {
                "pkts_toserver": random.randint(1, 100),
                "pkts_toclient": random.randint(1, 100),
                "bytes_toserver": random.randint(100, 50000),
                "bytes_toclient": random.randint(100, 50000),
            },
        }
        alerts.append(alert)

    return alerts


def main():
    """Generate all fixture files."""
    print("Generating Zeek log fixtures...")

    fixtures = {
        "conn.log.json": generate_conn_logs(50),
        "dns.log.json": generate_dns_logs(50),
        "http.log.json": generate_http_logs(50),
        "ssl.log.json": generate_ssl_logs(50),
        "x509.log.json": generate_x509_logs(50),
        "files.log.json": generate_files_logs(50),
        "notice.log.json": generate_notice_logs(50),
    }

    for filename, data in fixtures.items():
        with open(filename, "w") as f:
            for entry in data:
                f.write(json.dumps(entry) + "\n")
        print(f"  ✓ Created {filename} ({len(data)} entries)")

    print("\nGenerating Suricata eve.json fixtures...")
    suricata_alerts = generate_suricata_alerts(30)
    with open("eve.json", "w") as f:
        for alert in suricata_alerts:
            f.write(json.dumps(alert) + "\n")
    print(f"  ✓ Created eve.json ({len(suricata_alerts)} alerts)")

    print("\n✅ All fixtures generated successfully!")


if __name__ == "__main__":
    main()
