# DNS Threat Detection

**Detect DNS-based C2 communication and data exfiltration channels.**

Vervet's DNS threat detection analyzes DNS queries to identify:
- **DNS Tunneling** — Data exfiltration via encoded subdomains or TXT records
- **DGA Domains** — Algorithmically generated domains for C2 communication
- **Fast-Flux DNS** — Rapidly changing IP addresses to evade detection
- **Suspicious Patterns** — Unusual query types, NXDOMAIN abuse, high query rates

---

## Features

### DNS Tunneling Detection

Identifies DNS queries used for data exfiltration or C2 channels.

**Detection Methods:**
- **Subdomain entropy analysis** — High entropy indicates encoded data
- **Subdomain length analysis** — Long subdomains carry more data
- **Query volume tracking** — High volume suggests active tunneling
- **Uniqueness analysis** — Many unique subdomains indicate data encoding
- **TXT record abuse** — TXT queries can exfiltrate large amounts of data
- **NXDOMAIN patterns** — Some tools use NXDOMAIN responses for data encoding

**Scoring Components:**
- Subdomain entropy (30 points)
- Subdomain length (20 points)
- Query volume (15 points)
- Subdomain diversity (15 points)
- TXT record usage (10 points)
- NXDOMAIN responses (5 points)
- Unusual query types (5 points)

**MITRE ATT&CK Mapping:**
- T1071.004 — Application Layer Protocol: DNS
- T1048.003 — Exfiltration Over Alternative Protocol: DNS
- T1041 — Exfiltration Over C2 Channel

### DGA Domain Detection

Identifies algorithmically generated domains used by malware for C2.

**Detection Methods:**
- **Entropy analysis** — High entropy indicates random generation
- **Bigram frequency** — Low bigram score = not English-like
- **Consonant-to-vowel ratio** — High ratio suggests non-linguistic generation
- **Digit presence** — Unusual digit ratios in legitimate domains
- **Meaningful parts** — Lack of recognizable word components
- **TLD analysis** — Suspicious TLDs commonly used by malware
- **NXDOMAIN rate** — DGA probing generates many failed lookups

**Scoring Components:**
- Domain entropy (25 points)
- Bigram analysis (25 points)
- Consonant ratio (15 points)
- Digit presence (10 points)
- Meaningful parts (10 points)
- TLD analysis (10 points)
- NXDOMAIN responses (5 points)

**MITRE ATT&CK Mapping:**
- T1071.004 — Application Layer Protocol: DNS
- T1568.002 — Dynamic Resolution: Domain Generation Algorithms

### Fast-Flux DNS Detection

Identifies rapidly changing DNS records used to evade detection.

**Detection Methods:**
- **IP diversity** — High number of unique IPs returned
- **Change rate analysis** — Rapid IP rotation over time
- **TTL analysis** — Low TTL enables fast rotation
- **Geographic diversity** — IPs from multiple countries/ASNs

**Scoring Components:**
- Number of unique IPs (40 points)
- IP change rate (30 points)
- Low TTL values (20 points)
- Observation period (10 points)

**MITRE ATT&CK Mapping:**
- T1071.004 — Application Layer Protocol: DNS
- T1568.001 — Dynamic Resolution: Fast Flux DNS

### Suspicious DNS Patterns

Catches unusual DNS behavior that doesn't fit specific categories.

**Pattern Types:**

1. **Excessive NXDOMAIN**
   - High rate of failed DNS lookups
   - May indicate scanning, probing, or DGA activity
   - MITRE: T1046 (Network Service Discovery), T1590.002 (DNS enumeration)

2. **Unusual Query Types**
   - Non-standard query types (NULL, CAA, DNSKEY, etc.)
   - May indicate reconnaissance or tunneling
   - MITRE: T1590.002 (DNS enumeration), T1071.004 (DNS protocol)

3. **High Query Rate**
   - Abnormally high queries to single domain
   - May indicate automated tunneling, exfiltration, or beaconing
   - MITRE: T1071.004 (DNS protocol), T1041 (C2 exfiltration)

---

## API Endpoints

### Get DNS Threat Summary

```http
GET /api/v1/hunt/dns/threats
```

**Query Parameters:**
- `tunneling_threshold` (float, default: 60.0) — Minimum tunneling score
- `dga_threshold` (float, default: 65.0) — Minimum DGA score
- `fast_flux_threshold` (float, default: 70.0) — Minimum fast-flux score
- `min_queries_tunneling` (int, default: 10) — Minimum queries for tunneling
- `min_queries_dga` (int, default: 3) — Minimum queries for DGA
- `min_queries_fast_flux` (int, default: 5) — Minimum queries for fast-flux

**Response:**
```json
{
  "summary": {
    "total_queries_analyzed": 1500,
    "tunneling_detections": 3,
    "dga_detections": 7,
    "fast_flux_detections": 2,
    "other_patterns": 5,
    "top_tunneling": [...],
    "top_dga": [...],
    "top_fast_flux": [...],
    "top_patterns": [...]
  }
}
```

### Get DNS Tunneling Detections

```http
GET /api/v1/hunt/dns/tunneling
```

**Query Parameters:**
- `min_score` (float, default: 60.0) — Minimum tunneling score
- `min_queries` (int, default: 10) — Minimum query count
- `limit` (int, default: 100) — Max results
- `offset` (int, default: 0) — Pagination offset

**Response:**
```json
{
  "tunneling_detections": [
    {
      "domain": "evil-c2.com",
      "src_ip": "192.0.2.100",
      "query_count": 45,
      "unique_subdomains": 43,
      "avg_subdomain_entropy": 4.2,
      "max_subdomain_entropy": 4.5,
      "avg_subdomain_length": 32.5,
      "max_subdomain_length": 48,
      "txt_record_queries": 15,
      "nxdomain_responses": 0,
      "unusual_query_types": [],
      "estimated_bytes_exfiltrated": 1480,
      "tunneling_score": 87.5,
      "confidence": 0.92,
      "reasons": [
        "Very high subdomain entropy (4.20) indicates data encoding",
        "Long subdomains (avg 32 chars)",
        "High subdomain uniqueness (96%) indicates data encoding",
        "Significant TXT record queries (15)"
      ],
      "mitre_techniques": [
        "T1071.004",
        "T1048.003",
        "T1041"
      ],
      "first_seen": 1704110400.0,
      "last_seen": 1704111720.0,
      "time_span_seconds": 1320.0
    }
  ],
  "total": 3,
  "returned": 3
}
```

### Get DGA Domain Detections

```http
GET /api/v1/hunt/dns/dga
```

**Query Parameters:**
- `min_score` (float, default: 65.0) — Minimum DGA score
- `min_queries` (int, default: 3) — Minimum query count
- `limit` (int, default: 100) — Max results
- `offset` (int, default: 0) — Pagination offset

**Response:**
```json
{
  "dga_detections": [
    {
      "domain": "xqzwfkjhgpmnb.tk",
      "src_ip": "192.0.2.200",
      "domain_entropy": 3.85,
      "consonant_ratio": 4.2,
      "digit_ratio": 0.0,
      "bigram_score": 12.3,
      "meaningful_parts": 0,
      "query_count": 8,
      "nxdomain_count": 7,
      "success_count": 1,
      "tld": "tk",
      "tld_common": false,
      "dga_score": 89.0,
      "confidence": 0.85,
      "reasons": [
        "Very high entropy (3.85) indicates random generation",
        "Very low bigram score (12.3) - not English-like",
        "Very high consonant ratio (4.2) - unusual",
        "No recognizable word parts - likely generated",
        "Suspicious TLD commonly used by malware",
        "High NXDOMAIN rate (88%) typical of DGA probing"
      ],
      "mitre_techniques": [
        "T1071.004",
        "T1568.002"
      ],
      "first_seen": 1704110400.0,
      "last_seen": 1704110820.0
    }
  ],
  "total": 7,
  "returned": 7
}
```

### Get Fast-Flux Detections

```http
GET /api/v1/hunt/dns/fast-flux
```

**Query Parameters:**
- `min_score` (float, default: 70.0) — Minimum fast-flux score
- `min_queries` (int, default: 5) — Minimum query count
- `limit` (int, default: 100) — Max results
- `offset` (int, default: 0) — Pagination offset

**Response:**
```json
{
  "fast_flux_detections": [
    {
      "domain": "fastflux.example.com",
      "unique_ips": 15,
      "ip_list": [
        "203.0.113.0",
        "203.0.113.1",
        "..."
      ],
      "avg_ttl": 120.0,
      "min_ttl": 60.0,
      "query_count": 20,
      "ip_changes_per_hour": 3.2,
      "distinct_asns": 0,
      "distinct_countries": 0,
      "fast_flux_score": 82.0,
      "confidence": 0.88,
      "reasons": [
        "High number of unique IPs (15)",
        "High IP change rate (3.2/hour)",
        "Low TTL (120s) enables rapid IP rotation",
        "Observed over 4.7 hours"
      ],
      "mitre_techniques": [
        "T1071.004",
        "T1568.001"
      ],
      "first_seen": 1704110400.0,
      "last_seen": 1704127200.0,
      "time_span_seconds": 16800.0
    }
  ],
  "total": 2,
  "returned": 2
}
```

### Get Suspicious DNS Patterns

```http
GET /api/v1/hunt/dns/suspicious-patterns
```

**Query Parameters:**
- `min_score` (float, default: 60.0) — Minimum suspicion score
- `pattern_type` (string, optional) — Filter by pattern type
- `limit` (int, default: 100) — Max results
- `offset` (int, default: 0) — Pagination offset

**Pattern Types:**
- `excessive_nxdomain` — High rate of failed lookups
- `unusual_query_types` — Non-standard query types
- `high_query_rate` — Abnormally high query volume

**Response:**
```json
{
  "suspicious_patterns": [
    {
      "pattern_type": "excessive_nxdomain",
      "domain": null,
      "src_ip": "192.0.2.400",
      "query_count": 50,
      "unique_domains": 47,
      "anomaly_indicators": [
        "NXDOMAIN rate: 94%",
        "Total NXDOMAIN: 47"
      ],
      "suspicion_score": 85.0,
      "confidence": 0.94,
      "reasons": [
        "High NXDOMAIN response rate (94%)",
        "47 failed DNS lookups may indicate scanning or DGA probing"
      ],
      "mitre_techniques": [
        "T1046",
        "T1590.002"
      ],
      "first_seen": 1704110400.0,
      "last_seen": 1704111200.0
    }
  ],
  "total": 5,
  "returned": 5
}
```

### Get DNS Threat Statistics

```http
GET /api/v1/hunt/dns/stats
```

**Response:**
```json
{
  "summary": {
    "total_queries_analyzed": 1500,
    "total_threats_detected": 17,
    "tunneling_detections": 3,
    "dga_detections": 7,
    "fast_flux_detections": 2,
    "other_patterns": 5
  },
  "by_category": {
    "tunneling": {
      "critical": 1,
      "high": 1,
      "medium": 1,
      "low": 0
    },
    "dga": {
      "critical": 2,
      "high": 3,
      "medium": 2,
      "low": 0
    },
    "fast_flux": {
      "critical": 0,
      "high": 2,
      "medium": 0,
      "low": 0
    }
  },
  "top_threats": {
    "tunneling": [...],
    "dga": [...],
    "fast_flux": [...]
  }
}
```

---

## Usage Examples

### Detect All DNS Threats

```bash
curl "http://localhost:8000/api/v1/hunt/dns/threats"
```

### Find High-Confidence Tunneling

```bash
curl "http://localhost:8000/api/v1/hunt/dns/tunneling?min_score=80&min_queries=20"
```

### Search for DGA Domains

```bash
curl "http://localhost:8000/api/v1/hunt/dns/dga?min_score=70"
```

### Identify Fast-Flux Networks

```bash
curl "http://localhost:8000/api/v1/hunt/dns/fast-flux?min_score=75"
```

### Find Hosts with Excessive NXDOMAIN

```bash
curl "http://localhost:8000/api/v1/hunt/dns/suspicious-patterns?pattern_type=excessive_nxdomain"
```

---

## Implementation Details

### Entropy Calculation

Shannon entropy measures randomness in strings:

```
H(X) = -Σ p(x) * log₂(p(x))
```

- **Low entropy** (< 2.0): Repetitive patterns (e.g., "aaaaaaa")
- **Medium entropy** (2.0-3.5): Natural language (e.g., "example")
- **High entropy** (> 3.5): Random/encoded data (e.g., "a1b2c3d4e5")

### Bigram Analysis

Compares letter pair frequencies to English language statistics:

- **High score** (> 50): English-like patterns
- **Medium score** (30-50): Mixed patterns
- **Low score** (< 30): Non-linguistic, likely DGA

Common English bigrams: th, he, in, er, an, re, on, at, en, nd

### Consonant Ratio

Ratio of consonants to vowels:

- **Normal English** (1.0-2.5): Balanced (e.g., "example" = 1.33)
- **High ratio** (> 3.0): Unusual, DGA-like (e.g., "xyzqwrst")
- **No vowels** (> 5.0): Edge case, likely random

---

## Threat Severity Levels

### Critical (90-100)
- **Tunneling:** Very high entropy + TXT abuse + high volume
- **DGA:** Multiple indicators + suspicious TLD + high NXDOMAIN rate
- **Fast-Flux:** Rapid rotation (> 5 IPs/hour) + low TTL

### High (80-89)
- **Tunneling:** High entropy + long subdomains + consistent encoding
- **DGA:** High entropy + low bigram score + unusual consonants
- **Fast-Flux:** Multiple IPs (> 10) + rapid changes

### Medium (70-79)
- **Tunneling:** Elevated entropy + moderate volume
- **DGA:** Some DGA indicators present
- **Fast-Flux:** Moderate IP rotation

### Low (60-69)
- **Tunneling:** Suspicious patterns but lower confidence
- **DGA:** Possible DGA with limited indicators
- **Fast-Flux:** Some IP diversity

---

## False Positive Considerations

### Legitimate Use Cases

**CDNs and Load Balancers:**
- May trigger fast-flux detection due to multiple IPs
- Check for common CDN domains (cloudflare.com, akamai.net, etc.)

**Legitimate High-Volume Services:**
- May trigger high query rate detection
- Review context: is this expected for the application?

**Internationalized Domains:**
- May have unusual character patterns
- Higher entropy doesn't always mean malicious

**Development/Testing:**
- Frequent NXDOMAIN responses may be legitimate
- Check if source is development environment

### Reducing False Positives

1. **Allowlisting** — Whitelist known-good domains and services
2. **Context** — Consider network environment and expected behavior
3. **Thresholds** — Adjust score thresholds based on environment
4. **Correlation** — Cross-reference with other threat indicators
5. **Time Windows** — Look for sustained patterns, not one-time events

---

## Performance Considerations

- **In-memory analysis** — Fast processing, no database required
- **Efficient grouping** — Groups queries by source/domain for batch analysis
- **Configurable thresholds** — Tune for environment size
- **Pagination support** — Handle large result sets efficiently

### Recommended Settings

**Small environment (< 1000 queries/day):**
```
tunneling_threshold: 60.0
min_queries_tunneling: 5
```

**Medium environment (1000-10000 queries/day):**
```
tunneling_threshold: 70.0
min_queries_tunneling: 10
```

**Large environment (> 10000 queries/day):**
```
tunneling_threshold: 75.0
min_queries_tunneling: 20
```

---

## Integration with Other Detection

DNS threat detection complements other Vervet features:

- **Beaconing Detection** — DNS-based C2 may also show beaconing patterns
- **Suricata Alerts** — Cross-reference DNS threats with IDS alerts
- **Connection Analysis** — Correlate DNS with unusual connection patterns

---

## References

- **MITRE ATT&CK** — https://attack.mitre.org/
- **DNS Tunneling Research** — Detecting DNS Tunneling (SANS)
- **DGA Analysis** — Domain Generation Algorithms (IEEE)
- **Fast-Flux Networks** — Understanding Fast-Flux Service Networks

---

**Built for threat hunters, by threat hunters.** 🎯
