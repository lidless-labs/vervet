# Configuration

## Frontend Configuration

### Environment Variables

Create a `.env` file in the `web/` directory:

```bash
VITE_API_BASE=http://localhost:8000
VITE_APP_PORT=5186
```

| Variable | Description | Default |
|----------|-------------|---------|
| `VITE_API_BASE` | Backend API URL | http://localhost:8000 |
| `VITE_APP_PORT` | Frontend port | 5186 |

### Theme Variants

The app supports 5 theme variants. Accessible at:
- `http://localhost:5186/` - Variant selector
- `http://localhost:5186/tactical` - Tactical theme
- `http://localhost:5186/analyst` - Analyst theme
- `http://localhost:5186/terminal` - Terminal theme
- `http://localhost:5186/command` - Command theme
- `http://localhost:5186/cyber` - Cyber Noir theme

## Backend Configuration

### Environment Variables

Create a `.env` file in the `api/` directory:

```bash
LOG_CACHE_DIR=./data/cache
ZEEK_LOG_DIR=./data/zeek
SURICATA_LOG_DIR=./data/suricata
MAX_FILE_SIZE_MB=500
THREAT_SCORE_THRESHOLD=60
MITRE_DATA_PATH=./data/mitre-attack.json
```

| Variable | Description | Default |
|----------|-------------|---------|
| `LOG_CACHE_DIR` | Directory for parsed log cache | ./data/cache |
| `ZEEK_LOG_DIR` | Directory for Zeek logs | ./data/zeek |
| `SURICATA_LOG_DIR` | Directory for Suricata logs | ./data/suricata |
| `MAX_FILE_SIZE_MB` | Max uploadable file size | 500 |
| `THREAT_SCORE_THRESHOLD` | Minimum score to display | 60 |
| `MITRE_DATA_PATH` | MITRE ATT&CK data file | ./data/mitre-attack.json |

## Running the Application

### Frontend

```bash
cd web
npm install
npm run dev
```

Starts dev server on `http://localhost:5186`

### Backend

```bash
cd api
pip install -r requirements.txt
python main.py
```

Starts API server on `http://localhost:8000`

### Both Together

```bash
# Terminal 1: Frontend
cd web && npm run dev

# Terminal 2: Backend
cd api && python main.py
```

## Log Format Reference

### Zeek Logs

Place these files in `api/data/zeek/`:

**conn.log**
```
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	conn
ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	...
```

**dns.log**
```
#path dns
ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	trans_id	rtt	query	qclass	qclass_name	qtype	qtype_name	rcode	rcode_name	AA	TC	RD	RA	Z	answers	TTLs	rejected
```

**ssl.log**
```
#path ssl
ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	version	cipher	curve	server_name	session_id	subject	issuer	client_cert	client_key	...
```

### Suricata eve.json

Place this file in `api/data/suricata/`:

```json
{"timestamp":"2026-02-09T10:15:00.123456+0000","flow_id":1234567890,"event_type":"flow","src_ip":"192.0.2.50","dest_ip":"192.0.2.1","src_port":54321,"dest_port":443,"proto":"TCP","flow":{"pkts_toserver":24,"pkts_toclient":18,"bytes_toserver":2048,"bytes_toclient":4096,"start":"2026-02-09T10:15:00.123456+0000","end":"2026-02-09T10:15:45.654321+0000","age":45,"state":"established","reason":"timeout"}}
```

## Threat Scoring Configuration

Edit scoring weights in `api/scoring/config.py`:

```python
SCORING_WEIGHTS = {
    'reputation': 0.4,    # IOC reputation score weight
    'behavior': 0.4,      # Behavioral pattern weight
    'evidence': 0.2,      # Evidence count weight
}

BEHAVIOR_PATTERNS = {
    'beaconing': {
        'enabled': True,
        'interval_threshold_seconds': 300,
        'regularity_threshold': 0.8,
    },
    'dns_tunneling': {
        'enabled': True,
        'subdomain_threshold': 5,
    },
    'fast_flux': {
        'enabled': True,
        'ip_change_threshold': 10,
    },
}

THREAT_SCORE_THRESHOLD = 60  # Minimum score to flag as threat
```

## MITRE ATT&CK Data

The app loads MITRE ATT&CK from `api/data/mitre-attack.json`. This file maps threat behaviors to techniques.

To update with latest MITRE data:
```bash
# Download from https://github.com/mitre/cti
curl -O https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
```

## Logging

Backend logs to console by default. Configure with `.env`:

```bash
LOG_LEVEL=INFO
LOG_FORMAT=json
```

## Production Deployment

For production, build the frontend:

```bash
cd web
npm run build
npm run preview
```

Backend production setup:

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:8000 main:app
```

Expose ports via your reverse proxy (Nginx, Apache, etc.):
- Frontend on port 5186
- Backend API on port 8000 (or as configured)
