# Architecture

## System Overview

Vervet is a full-stack network threat hunting platform. The frontend provides interactive dashboards for exploring threats, while the backend handles log parsing, threat scoring, and MITRE ATT&CK correlation.

## Tech Stack

### Frontend
- **React 18** with TypeScript for type-safe component development
- **Vite** for lightning-fast development and optimized production builds
- **Tailwind CSS** for styling with 5 theme variants
- **Zustand** for global state management
- Runs on **port 5186**

### Backend
- **FastAPI** with async/await for high-concurrency REST APIs
- **Python 3.9+** for data processing and threat analysis
- **Pydantic** for request/response validation
- Runs on **port 8000**

## Data Flow

The threat hunting pipeline follows this path:

```
Import Zeek/Suricata Logs
    |
    v
Parse Logs (extract flows, DNS, SSL, HTTP)
    |
    v
Extract Indicators (IPs, domains, SSL certs, hashes)
    |
    v
Threat Scoring (behavior patterns, reputation, confidence)
    |
    v
MITRE ATT&CK Mapping (techniques and tactics)
    |
    v
Correlation & Clustering (group related threats)
    |
    v
Dashboard Visualization (themes and drill-down views)
```

## Frontend (React)

Responsibilities:
- User input (log upload, filter selection)
- Dashboard rendering (threat list, drill-downs, flow views)
- Theme variant selection and switching
- Client-side caching via Zustand

**Key Flows:**
1. User uploads Zeek or Suricata logs
2. Frontend sends to backend API for parsing
3. Backend returns indexed threats and indicators
4. Frontend renders dashboards with drill-down capability
5. User explores flows, DNS queries, SSL certificates per threat

## Backend (FastAPI)

Responsibilities:
- Log file parsing (Zeek and Suricata formats)
- Indicator extraction (IPs, domains, file hashes, SSL certs)
- Threat scoring (behavior analysis, confidence calculation)
- MITRE ATT&CK technique correlation
- API endpoint routing and validation
- In-memory or file-based threat cache

**Key Flows:**
1. Accept log file upload
2. Parse into structured events
3. Extract threat indicators
4. Calculate threat scores with explanations
5. Map to MITRE techniques
6. Return indexed threat data
7. Support drill-down queries (flows by IP, DNS lookups, SSL chains)

## In-Memory Data Model

Threats are indexed and cached in memory for fast exploration:

```json
{
  "threat_id": "uuid",
  "indicator": "192.0.2.1",
  "indicator_type": "ip",
  "score": 85,
  "score_components": {
    "reputation": 0.6,
    "beaconing": 0.9,
    "evidence_weight": 0.7
  },
  "reasoning": "Periodic outbound connections to high-risk ASN",
  "mitre": {
    "techniques": ["C2: Remote Access", "Exfiltration: Command and Control"],
    "tactics": ["command-and-control"]
  },
  "flows": [
    {
      "src_ip": "192.0.2.50",
      "dst_ip": "192.0.2.1",
      "dst_port": 443,
      "protocol": "tcp",
      "bytes_out": 2048,
      "packets_out": 24,
      "timestamps": ["2026-02-09T10:15:00Z", "2026-02-09T11:15:00Z"]
    }
  ],
  "dns_lookups": [
    {
      "query": "command.example.com",
      "response": ["192.0.2.1"],
      "query_type": "A"
    }
  ],
  "ssl_certs": [
    {
      "subject": "*.example.com",
      "issuer": "Self-Signed",
      "valid_from": "2025-01-01",
      "valid_to": "2026-01-01"
    }
  ]
}
```

## Log Parsers

### Zeek Parser
Reads TSV-formatted Zeek logs (conn.log, dns.log, ssl.log, http.log) and normalizes to internal representation.

### Suricata Parser
Reads eve.json (JSON format) and extracts flow metadata, alerts, and payload information.

## Threat Scoring Formula

```
Score = (reputation * 0.4 + behavior * 0.4 + evidence * 0.2) * 100

where:
  reputation: IOC reputation across threat feeds (0-1)
  behavior: Detected pattern strength (beaconing, tunneling, etc.) (0-1)
  evidence: Amount of supporting data and diversity (0-1)
```

Lower confidence scores are marked for manual review.

## API Endpoints

### POST /upload
Upload and parse a log file.

**Request:**
```json
{
  "log_format": "zeek",
  "file": <binary>
}
```

**Response:**
```json
{
  "session_id": "uuid",
  "threats_found": 42,
  "indicators_count": 156,
  "parsing_duration_ms": 1250
}
```

### GET /threats?session_id={id}
Fetch all threats from a parsed session.

**Response:**
```json
{
  "threats": [
    {
      "id": "uuid",
      "indicator": "192.0.2.1",
      "score": 85,
      "reasoning": "...",
      "mitre": {...}
    }
  ],
  "total": 42
}
```

### GET /threat/{threat_id}/flows
Get network flows associated with a threat.

**Response:**
```json
{
  "flows": [
    {
      "src_ip": "192.0.2.50",
      "dst_ip": "192.0.2.1",
      "dst_port": 443,
      "protocol": "tcp",
      "duration_seconds": 45,
      "bytes_out": 2048
    }
  ]
}
```

## 5 Variants

Each variant wraps the same core pages in a unique visual identity:

| Variant | Theme | Use Case |
|---------|-------|----------|
| **Tactical** | Dark slate, red accents | Security operations center |
| **Analyst** | Clean white, blue accents | Intelligence analysis |
| **Terminal** | Pure black, matrix green | Hacker / OSINT style |
| **Command** | OD green, amber accents | Military-style command |
| **Cyber** | Neon cyan/magenta, glow | Cyberpunk aesthetic |

All variants share the same data model and API. Switching themes is instant.

## Offline Capability

Vervet processes logs entirely on the client and server. After importing a log file, all threat analysis is cached and can be reviewed offline.
