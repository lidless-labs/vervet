# Unified Threat Scoring - Quick Start Guide

## What Was Built

A complete unified threat scoring engine that:
- Aggregates detections from beacons, DNS threats, Suricata alerts, and long connections
- Provides per-host risk scores with evidence chains
- Maps all detections to MITRE ATT&CK techniques
- Generates attack narratives and timelines
- Exposes REST API endpoints

## Files Created

### Core Implementation (2,272 lines)
```
api/config/mitre_framework.py          362 lines - MITRE ATT&CK framework
api/services/suricata_analyzer.py      582 lines - Suricata alert analysis
api/services/long_connection_analyzer.py 590 lines - Long connection detection
api/services/unified_threat_engine.py  738 lines - Unified scoring engine
```

### API Layer (386 lines)
```
api/routers/analysis.py                386 lines - REST API endpoints
```

### Tests (1,203 lines)
```
api/tests/test_suricata_analyzer.py    321 lines - 26 test cases
api/tests/test_long_connection_analyzer.py 391 lines - 25 test cases
api/tests/test_unified_threat_engine.py 491 lines - 25 test cases
```

### Documentation (3,000+ lines)
```
UNIFIED_THREAT_SCORING.md              - Complete implementation guide
TASK_COMPLETE_UNIFIED_SCORING.md       - Task completion summary
UNIFIED_SCORING_README.md              - This file
```

**Total: 6,861+ lines**

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Tests
```bash
# Test Suricata analyzer
pytest api/tests/test_suricata_analyzer.py -v

# Test long connection analyzer
pytest api/tests/test_long_connection_analyzer.py -v

# Test unified engine
pytest api/tests/test_unified_threat_engine.py -v

# Run all tests
pytest api/tests/test_*_analyzer.py api/tests/test_unified_*.py -v
```

### 3. Start Server
```bash
cd api
uvicorn main:app --reload
```

### 4. Test Endpoints
```bash
# Get all threats
curl http://localhost:8000/api/v1/analysis/threats | jq

# Get specific host threat profile
curl http://localhost:8000/api/v1/analysis/threats/192.0.2.100 | jq

# Get all threat indicators
curl http://localhost:8000/api/v1/analysis/indicators | jq

# Get MITRE ATT&CK mappings
curl http://localhost:8000/api/v1/analysis/mitre | jq

# Get MITRE overview
curl http://localhost:8000/api/v1/analysis/mitre/overview | jq

# Get statistics
curl http://localhost:8000/api/v1/analysis/stats | jq
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/v1/analysis/threats` | List all host threat scores |
| `GET /api/v1/analysis/threats/{ip}` | Detailed host profile |
| `GET /api/v1/analysis/indicators` | All threat indicators |
| `GET /api/v1/analysis/mitre` | MITRE technique mappings |
| `GET /api/v1/analysis/mitre/overview` | MITRE aggregate stats |
| `GET /api/v1/analysis/stats` | Detection engine statistics |

## Key Features

### ✅ Unified Scoring
- Per-host normalized scores (0-1)
- Aggregates beacons, DNS, alerts, long connections
- Multi-detection boost for coordinated attacks
- Threat levels: critical, high, medium, low, info

### ✅ MITRE ATT&CK Mapping
- 24 techniques mapped
- 12 tactics covered
- Automatic signature-to-technique mapping
- Evidence chains for each technique
- Detection counts per technique

### ✅ Explainable Scores
- Human-readable reasons
- Specific indicators
- Component score breakdowns
- Confidence scoring

### ✅ Attack Narratives
- Chronological timelines
- Natural language summaries
- Related IPs and domains
- First/last seen timestamps

### ✅ Threat Correlation
- Beacon + DNS exfil detection
- Multi-host beacon clusters
- Exploit chain identification

## Architecture

```
┌─────────────────────────────────────────────┐
│      Unified Threat Engine                 │
│                                             │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐   │
│  │ Beacon   │ │   DNS    │ │ Suricata │   │
│  │ Analyzer │ │ Analyzer │ │ Analyzer │   │
│  └──────────┘ └──────────┘ └──────────┘   │
│                                             │
│  ┌──────────┐ ┌─────────────────────────┐ │
│  │Long Conn │ │ MITRE ATT&CK Framework  │ │
│  │ Analyzer │ │ (24 techniques)         │ │
│  └──────────┘ └─────────────────────────┘ │
│                                             │
│         ┌──────────────────┐               │
│         │  Host Threat     │               │
│         │  Profiles        │               │
│         └──────────────────┘               │
└─────────────────────────────────────────────┘
```

## Usage Example

```python
from api.services.unified_threat_engine import UnifiedThreatEngine
from api.services.log_store import LogStore

# Initialize
log_store = LogStore()
# ... load logs ...

# Analyze
engine = UnifiedThreatEngine(log_store)
profiles = engine.analyze_all()

# Get top threats
for threat in engine.get_top_threats(limit=10):
    print(f"{threat.ip}: {threat.score:.2f} ({threat.threat_level.value})")
    print(f"  Beacons: {threat.beacon_count}")
    print(f"  DNS Threats: {threat.dns_threat_count}")
    print(f"  Alerts: {threat.alert_count}")
    print(f"  MITRE: {', '.join(list(threat.mitre_techniques)[:5])}")
```

## Scoring Methodology

### Suricata Alert Scoring (0-100)
- **Severity (35%)**: Alert severity level
- **Category (35%)**: Alert category mapping
- **Frequency (20%)**: Repeated alert boost
- **Context (10%)**: Port/protocol anomalies

### Long Connection Scoring (0-100)
- **Duration (30%)**: Duration vs. protocol expectations
- **Transfer (35%)**: Upload patterns and volume
- **Protocol (20%)**: Context-based suspicion
- **Destination (15%)**: External IPs, unusual ports

### Unified Host Score (0-1)
1. Collect all detection scores
2. Normalize to 0-1
3. Calculate: `max * 0.7 + avg * 0.3`
4. Apply multi-detection boost

## MITRE Coverage

### Tactics (12)
- TA0001: Initial Access
- TA0007: Discovery
- TA0008: Lateral Movement
- TA0010: Exfiltration
- TA0011: Command and Control
- ... and 7 more

### Techniques (24)
- **C2**: T1071, T1071.001, T1071.004, T1573, T1090, T1095
- **Exfil**: T1041, T1048, T1048.003, T1029, T1030
- **Discovery**: T1046, T1018, T1590, T1590.002
- **Defense Evasion**: T1568, T1568.001, T1568.002, T1001
- **Initial Access**: T1190, T1133
- **Lateral Movement**: T1021, T1021.001, T1021.004

## Testing

### Test Coverage
- 76 test cases total
- 26 tests for Suricata analyzer
- 25 tests for long connection analyzer
- 25 tests for unified threat engine

### Test Categories
- Scoring algorithms
- MITRE technique mapping
- Pattern detection
- Evidence chain construction
- API query methods
- Edge cases and error handling

## Integration Points

### Data Sources
- ✅ BeaconAnalyzer (existing)
- ✅ DnsAnalyzer (existing)
- ✅ LogStore (existing)
- ✅ Suricata Parser (existing)
- ✅ Zeek Parser (existing)

### API Structure
- ✅ FastAPI routers
- ✅ Pydantic models
- ✅ Dependency injection
- ✅ CORS configured

## Performance

- **In-memory analysis**: Fast processing
- **Efficient indexing**: IP-based lookups
- **Lazy evaluation**: Only runs on API calls
- **Pagination support**: Large result sets
- **Caching ready**: Results can be cached

## Next Steps

1. **Deploy**: Start API server
2. **Integrate Frontend**: Connect React components
3. **Visualize**: Add threat score dashboards
4. **Monitor**: Track threat levels over time
5. **Tune**: Adjust thresholds based on environment

## Documentation

- **UNIFIED_THREAT_SCORING.md**: Complete technical documentation
- **TASK_COMPLETE_UNIFIED_SCORING.md**: Implementation summary
- **Inline Docstrings**: Comprehensive code documentation

## Support

All code includes:
- Type hints for IDE support
- Comprehensive docstrings
- Error handling
- Input validation
- Clear separation of concerns

## Status

✅ **Production Ready**

All components are:
- ✅ Fully implemented
- ✅ Well-documented
- ✅ Thoroughly tested
- ✅ Type-safe
- ✅ Integrated with existing code

---

**Built for Vervet - Network Threat Hunting Platform**
