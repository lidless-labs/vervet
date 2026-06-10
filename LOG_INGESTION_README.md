# Log Ingestion Engine - Vervet

## Overview

The log ingestion engine is the data backbone of Vervet, providing:
- **Streaming parsers** for Zeek and Suricata logs (handles files >100MB)
- **Unified data models** for cross-platform analysis
- **In-memory queryable store** with filtering and pagination
- **REST API endpoints** for data ingestion and querying

## Architecture

```
fixtures/              # Sample log files for testing
api/
  parsers/
    zeek_parser.py      # Zeek JSON log parser (conn, dns, http, ssl, etc.)
    suricata_parser.py  # Suricata eve.json parser (alert, flow, dns, http, tls)
    unified.py          # Unified models + normalization layer
  services/
    log_store.py        # In-memory queryable data store
  routers/
    ingest.py           # POST /api/ingest/directory
    data.py             # GET /api/data/connections, /summary, /dns, /alerts
  tests/
    test_parsers.py     # Unit tests for all parsers
```

## Features

### Zeek Parser (`api/parsers/zeek_parser.py`)

Supports all major Zeek log types:
- **conn.log** - TCP/UDP/ICMP connections
- **dns.log** - DNS queries and responses
- **http.log** - HTTP requests and responses
- **ssl.log** - TLS handshakes
- **x509.log** - X.509 certificates
- **files.log** - File transfers
- **notice.log** - Security notices
- **weird.log** - Unusual network activity
- **dpd.log** - Dynamic protocol detection
- **smtp.log** - Email traffic

**Streaming Support:**
- Reads files line-by-line to handle large files (>100MB)
- Does not load entire file into memory
- Configurable error threshold (default: 100 errors before stopping)

**Error Handling:**
- Validates each entry against Pydantic schema
- Logs warnings for malformed entries
- Continues parsing after errors
- Returns iterator for memory efficiency

**Example Usage:**
```python
from api.parsers.zeek_parser import ZeekParser

# Parse connection log
for conn in ZeekParser.parse_file("conn.log.json", log_type="conn"):
    print(f"{conn.id_orig_h}:{conn.id_orig_p} -> {conn.id_resp_h}:{conn.id_resp_p}")

# Auto-detect log type from filename
for entry in ZeekParser.parse_file("dns.log.json"):
    print(f"DNS query: {entry.query}")
```

### Suricata Parser (`api/parsers/suricata_parser.py`)

Supports Suricata eve.json event types:
- **alert** - IDS/IPS alerts
- **flow** - Network flows
- **dns** - DNS queries
- **http** - HTTP transactions
- **tls** - TLS handshakes

**Event Type Routing:**
- Routes events based on `event_type` field
- Filters events by type for efficient parsing
- Handles embedded metadata (HTTP headers, TLS certs, etc.)

**Timestamp Handling:**
- Parses ISO 8601 timestamps
- Handles multiple timestamp formats
- Falls back to dateutil parser if needed

**Example Usage:**
```python
from api.parsers.suricata_parser import SuricataParser

# Parse all event types
for event in SuricataParser.parse_file("eve.json"):
    print(f"{event.event_type}: {event.src_ip} -> {event.dest_ip}")

# Extract only alerts
for alert in SuricataParser.extract_alerts("eve.json"):
    print(f"Alert: {alert.alert['signature']}")
```

### Unified Models (`api/parsers/unified.py`)

Provides cross-platform normalized models:

**Connection Model:**
```python
class Connection:
    uid: str              # Unique ID
    src_ip: str           # Source IP
    src_port: int         # Source port
    dst_ip: str           # Destination IP
    dst_port: int         # Destination port
    proto: str            # Protocol (tcp/udp/icmp)
    service: str          # Detected service
    duration: float       # Connection duration
    bytes_sent: int       # Bytes from source
    bytes_recv: int       # Bytes to source
    timestamp: datetime   # Timestamp
    tags: list[str]       # Classification tags
    source: str           # Log source (zeek/suricata)
```

**Normalization Functions:**
- `normalize_zeek_conn()` - Zeek conn.log → Connection
- `normalize_zeek_dns()` - Zeek dns.log → DnsQuery
- `normalize_suricata_flow()` - Suricata flow → Connection
- `normalize_suricata_dns()` - Suricata DNS → DnsQuery
- `normalize_suricata_alert()` - Suricata alert → Alert

**Example:**
```python
from api.parsers.unified import normalize_zeek_conn

conn = normalize_zeek_conn(zeek_entry)
print(f"Unified: {conn.src_ip}:{conn.src_port} -> {conn.dst_ip}:{conn.dst_port}")
```

### In-Memory Log Store (`api/services/log_store.py`)

Efficient in-memory storage with:
- **IP address indexing** for fast lookups
- **Filtering** by IP, port, protocol, service, duration, time range
- **Pagination** support (limit/offset)
- **Time range tracking**
- **Summary statistics**

**Storage:**
- `connections[]` - Normalized connection records
- `dns_queries[]` - DNS query records
- `alerts[]` - IDS alert records

**Indices:**
- `_src_ip_index` - Fast source IP lookup
- `_dst_ip_index` - Fast destination IP lookup

**Example Usage:**
```python
from api.services.log_store import log_store

# Load directory
stats = log_store.load_directory("/path/to/logs")
print(f"Loaded {stats['record_count']} records from {stats['file_count']} files")

# Query connections
tcp_conns = log_store.get_connections(proto="tcp", limit=100)
long_conns = log_store.get_connections(min_duration=60.0)
filtered = log_store.get_connections(src_ip="192.0.2.10", dst_port=443)

# Get DNS queries
dns = log_store.get_dns_queries(query="google.com")

# Get alerts
critical_alerts = log_store.get_alerts(severity=1)
```

## API Endpoints

### Ingestion Endpoints (`/api/ingest`)

**POST /api/ingest/directory**
Load log files from a directory.

Request:
```json
{
  "path": "/path/to/logs"
}
```

Response:
```json
{
  "success": true,
  "message": "Successfully loaded 8 files with 1234 records",
  "stats": {
    "file_count": 8,
    "record_count": 1234,
    "time_range": ["2026-01-28T18:55:37Z", "2026-01-29T09:16:37Z"],
    "unique_src_ips": 45,
    "unique_dst_ips": 67,
    "connections": 890,
    "dns_queries": 234,
    "alerts": 110
  }
}
```

**POST /api/ingest/clear**
Clear all loaded logs.

**GET /api/ingest/status**
Get current store status.

### Data Query Endpoints (`/api/data`)

**GET /api/data/connections**
Query connections with filters.

Query Parameters:
- `src_ip` - Source IP filter
- `dst_ip` - Destination IP filter
- `port` - Port filter (source or dest)
- `proto` - Protocol filter (tcp/udp/icmp)
- `service` - Service filter
- `min_duration` - Minimum duration filter (seconds)
- `limit` - Page size (1-1000, default 100)
- `offset` - Page offset (default 0)

Response:
```json
{
  "total": 890,
  "limit": 100,
  "offset": 0,
  "connections": [...]
}
```

**GET /api/data/summary**
Get aggregate statistics.

Response:
```json
{
  "total_connections": 890,
  "unique_src_ips": 45,
  "unique_dst_ips": 67,
  "time_range": {"start": "...", "end": "..."},
  "protocol_breakdown": {"tcp": 456, "udp": 234, "icmp": 200},
  "service_breakdown": {"https": 123, "dns": 89, "ssh": 45},
  "top_sources": [{"ip": "192.0.2.10", "count": 234}],
  "top_destinations": [{"ip": "8.8.8.8", "count": 89}]
}
```

**GET /api/data/dns**
Query DNS records.

Query Parameters:
- `src_ip` - Source IP filter
- `query` - Domain substring filter
- `qtype` - Query type filter (A, AAAA, etc.)
- `limit`, `offset` - Pagination

**GET /api/data/alerts**
Query IDS alerts.

Query Parameters:
- `severity` - Severity filter (1=high, 2=medium, 3=low)
- `category` - Category filter
- `limit`, `offset` - Pagination

## Testing

### Unit Tests (`api/tests/test_parsers.py`)

Comprehensive test suite covering:

**Zeek Parser Tests:**
- Log type detection from filenames
- Timestamp parsing (epoch float → datetime)
- Parsing conn.log, dns.log, http.log
- Single line parsing
- Entry validation
- Error handling with malformed JSON

**Suricata Parser Tests:**
- Event type routing (alert, flow, dns, http, tls)
- Timestamp parsing (ISO 8601)
- Alert extraction
- Single line parsing
- Entry validation

**Unified Model Tests:**
- Zeek → unified Connection normalization
- Zeek → unified DnsQuery normalization
- Suricata → unified Alert normalization

**Integration Tests:**
- Full directory ingestion workflow
- Connection filtering by protocol, IP, port
- DNS query filtering

**Run Tests:**
```bash
pytest api/tests/test_parsers.py -v
```

### Fixture Data

Sample logs in `fixtures/`:
- `conn.log.json` - 50 Zeek connection records
- `dns.log.json` - 50 Zeek DNS queries
- `http.log.json` - 50 Zeek HTTP requests
- `ssl.log.json` - Zeek TLS handshakes
- `x509.log.json` - Zeek X.509 certificates
- `files.log.json` - Zeek file transfers
- `notice.log.json` - Zeek security notices
- `eve.json` - 30 Suricata events (alerts)

## Performance

- **Streaming parser** - Handles 100MB+ files without memory issues
- **IP indexing** - O(1) lookups for single IP filters
- **Configurable error threshold** - Stops after 100 errors by default
- **Efficient filtering** - Index-optimized queries when possible

## Error Handling

All parsers implement robust error handling:
- **JSON decode errors** - Logged as warnings, parsing continues
- **Schema validation errors** - Invalid entries skipped
- **Missing required fields** - Entry rejected with warning
- **Malformed timestamps** - Logged and fallback to current time
- **File not found** - Raises FileNotFoundError
- **Invalid log type** - Raises ValueError

Errors are logged with:
- File path and line number
- Error type and message
- Entry that failed to parse

## Future Enhancements

Potential improvements:
- Database persistence (PostgreSQL/TimescaleDB)
- Live log tailing/streaming
- Log rotation handling
- File upload via browser
- More Zeek log types (software.log, pe.log, etc.)
- Suricata fileinfo parsing
- Advanced time-series queries
- Export to CSV/JSON

## Dependencies

Core dependencies (see `requirements.txt`):
- `fastapi==0.109.0` - Web framework
- `pydantic==2.5.3` - Data validation
- `python-dateutil==2.8.2` - Timestamp parsing
- `pytest==7.4.4` - Testing

## Implementation Checklist

✅ Zeek parser - all log types (conn, dns, http, ssl, x509, files, notice, weird, dpd, smtp)
✅ Suricata parser - event_type routing (alert, flow, dns, http, tls)
✅ Unified models - Connection, DnsQuery, Alert
✅ Normalization functions - Zeek/Suricata → unified
✅ In-memory log store - filtering, pagination, indexing
✅ Streaming JSON parser - handles files >100MB
✅ Zeek timestamp handling - epoch float → datetime
✅ Suricata timestamp handling - ISO 8601 → datetime
✅ POST /api/ingest/directory - returns stats (file count, record count, time range, unique IPs)
✅ GET /api/data/connections - paginated with filters (src_ip, dst_ip, port, proto, service, min_duration)
✅ GET /api/data/summary - total connections, unique IPs, time range, protocol/service breakdown
✅ Unit tests - validates parsing of each log type against fixtures
✅ Error handling - malformed/incomplete entries logged and skipped

All acceptance criteria met! 🎯
