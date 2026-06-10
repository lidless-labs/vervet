# Beacon Detection Feature

## Overview

The beacon detection feature identifies hosts making periodic callbacks to external IPs, a hallmark of C2 (command and control) communication. This is the signature capability of AC Hunter.

## Implementation

### Core Components

#### 1. Models (`api/models/beacon.py`)
- **BeaconResult**: Core beacon detection result with scoring and metadata
- **BeaconDetailedResult**: Extended result with interval histograms for visualization
- **BeaconIntervalHistogram**: Histogram data for interval distribution analysis

#### 2. Analyzer Service (`api/services/beacon_analyzer.py`)
- **BeaconAnalyzer**: Main analysis engine
  - Groups connections by src_ip → dst_ip:dst_port pairs
  - Calculates statistical metrics on connection intervals
  - Scores beacon likelihood using multi-factor analysis
  - Filters out known-good periodic traffic

#### 3. Allowlist Configuration (`api/config/allowlists.py`)
- **BeaconAllowlist**: Filters known-good periodic traffic
  - Common DNS resolvers (Google, Cloudflare, Quad9, OpenDNS)
  - Common NTP servers
  - Configurable custom allowlists

#### 4. API Endpoints (`api/routers/hunt.py`)
- `GET /api/hunt/beacons` - List all detected beacons (paginated, sorted by score)
- `GET /api/hunt/beacons/{src_ip}/{dst_ip}` - Detailed analysis for specific pair
- `GET /api/hunt/beacons/stats` - Summary statistics

## Statistical Analysis Methods

### 1. Interval Regularity (40 points)
- **Coefficient of Variation (Jitter)**: `(std_dev / mean) * 100`
- Low jitter (< 5%) = highly regular intervals = high score
- Beacons with < 20% jitter are considered suspicious

### 2. Connection Count & Coverage (25 points)
- More connections = higher confidence
- 100+ connections = maximum points
- Minimum 10 connections required

### 3. Time Span Coverage (15 points)
- Longer observation periods = higher confidence
- 24+ hours = maximum points
- Minimum 1 hour required

### 4. Data Size Consistency (10 points)
- **Coefficient of Variation on Data Sizes**
- Consistent data sizes indicate automated behavior
- < 10% CV = maximum points

### 5. Interval Distribution Entropy (10 points)
- Histogram entropy analysis
- Lower entropy (more concentrated) = higher score
- Uses log2 entropy calculation

## Scoring Algorithm

```
Beacon Score =
  Regularity Score (0-40) +
  Count Score (0-25) +
  Coverage Score (0-15) +
  Data Consistency Score (0-10) +
  Histogram Score (0-10)

Total: 0-100 points
```

### Score Thresholds
- **90-100**: Critical - Very high confidence beacon
- **80-89**: High - Strong beacon characteristics
- **70-79**: Medium - Likely beacon behavior
- **< 70**: Not flagged (below default threshold)

## Configurable Parameters

```python
BeaconAnalyzer(
    min_connections=10,        # Minimum connections to consider
    max_jitter_pct=20.0,       # Maximum jitter for high-confidence
    min_time_span_hours=1.0,   # Minimum observation period
    score_threshold=70.0,      # Minimum score to report
)
```

## MITRE ATT&CK Mappings

Detected beacons are automatically mapped to:
- **T1071**: Application Layer Protocol (all beacons)
- **T1071.001**: Web Protocols (HTTP/HTTPS beacons)
- **T1071.004**: DNS (DNS-based beacons)
- **T1573**: Encrypted Channel (high-score HTTPS beacons)

## Explainability

Every beacon result includes:
- **Reasons**: Human-readable explanations of why it was flagged
- **Statistical Metrics**: Jitter, intervals, data sizes
- **Confidence Score**: Based on sample size and observation period

Example reasons:
- "Very low jitter (2.3%) indicates highly regular intervals"
- "150 connections provide strong evidence"
- "Observed over 24.5 hours (full day+)"

## API Usage Examples

### List All Beacons
```bash
GET /api/hunt/beacons?min_score=70&limit=50
```

Response:
```json
{
  "beacons": [
    {
      "src_ip": "192.0.2.100",
      "dst_ip": "203.0.113.50",
      "dst_port": 443,
      "connection_count": 150,
      "avg_interval_seconds": 60.2,
      "jitter_pct": 3.5,
      "beacon_score": 92.3,
      "confidence": 0.85,
      "reasons": [
        "Very low jitter (3.5%) indicates highly regular intervals",
        "150 connections provide strong evidence",
        "Observed over 24.8 hours (full day+)"
      ],
      "mitre_techniques": ["T1071", "T1071.001", "T1573"]
    }
  ],
  "total": 5,
  "returned": 5
}
```

### Detailed Analysis
```bash
GET /api/hunt/beacons/192.0.2.100/203.0.113.50
```

Returns full interval histogram for visualization.

### Summary Statistics
```bash
GET /api/hunt/beacons/stats?min_score=70
```

Returns aggregate statistics and top beacons.

## Performance

- **Target**: Analyze 100k+ connections in under 5 seconds
- **Implementation**: Uses efficient grouping and indexing
- **Memory**: In-memory analysis, no database required for MVP

## Testing

### Unit Tests (`api/tests/test_beacon.py`)
Comprehensive test suite with synthetic data:
- Perfect beacon (0% jitter) - verifies high score
- Low jitter beacon (5%) - verifies detection
- Moderate jitter beacon (15%) - verifies scoring
- High jitter (80%) - verifies non-detection
- Allowlist filtering - verifies DNS/NTP exclusion
- Data size consistency - verifies scoring impact
- MITRE mappings - verifies technique assignment
- Multiple beacons - verifies separation
- Time span requirements - verifies thresholds

### Verification Script
```bash
python3 verify_beacon_implementation.py
```

Checks all components without requiring dependencies.

### Performance Test
```bash
python3 test_beacon_performance.py
```

Generates 100k connections and measures analysis time.

## False Positive Prevention

### Allowlist Filtering
Automatically excludes:
- DNS queries to known resolvers (8.8.8.8, 1.1.1.1, etc.)
- NTP traffic (port 123)
- Custom allowlist entries

### Configurable Thresholds
Adjust parameters to reduce false positives:
- Increase `min_connections` for more evidence
- Decrease `max_jitter_pct` for stricter regularity
- Increase `min_time_span_hours` for longer observation
- Increase `score_threshold` for higher confidence

## Future Enhancements

Potential improvements (out of scope for MVP):
- Machine learning-based classification
- Real-time streaming detection
- Automated alerting/response
- Historical trend analysis
- Geographic IP analysis
- Threat intelligence integration

## References

- AC Hunter: https://www.activecountermeasures.com/ac-hunter/
- MITRE ATT&CK: https://attack.mitre.org/
- C2 Beaconing Detection Techniques
