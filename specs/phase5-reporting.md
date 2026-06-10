# Phase 5: Reporting & Analyst Workflow

## Context
Vervet is positioning against AC-Hunter (Active Countermeasures) for SEU.
AC-Hunter's key features: automated hourly threat hunts, systems sorted by threat severity,
deep dive into all communications per system, syslog/Slack integration, beaconing + long
connection + DNS tunneling detection.

We already have most detection features. Phase 5 makes Vervet report-ready and
analyst-workflow-complete so it looks like a mature commercial tool in demos.

## 5A: PDF Report Generation + Report History (Backend + Frontend)
**Goal:** Generate downloadable PDF reports from the existing HTML report engine.
Uses the existing `report_generator.py` service.

### Backend (api/routers/reports.py)
- `GET /api/v1/reports/pdf` - Generate and return a PDF report (HTML → PDF via weasyprint or reportlab)
- `POST /api/v1/reports/generate` - Generate a report and save it to data/reports/ with metadata
- `GET /api/v1/reports/history` - List all saved reports with metadata (id, generated_at, threat_count, etc.)
- `GET /api/v1/reports/history/{report_id}` - Get a specific saved report
- `DELETE /api/v1/reports/history/{report_id}` - Delete a saved report

### Frontend (web/src/variants/v3/pages/Reports.tsx)
- Report history list with date, threat count, severity breakdown
- "Generate New Report" button
- Download PDF / View HTML buttons per report
- Report preview panel (show HTML in iframe or rendered)
- Quick stats: total reports, last generated date

### Dependencies
- `weasyprint` or `xhtml2pdf` for PDF generation (add to requirements.txt)
- If weasyprint has system deps issues, fall back to xhtml2pdf (pure Python)

## 5B: Hunt Hypothesis Templates + Annotations (Backend + Frontend)
**Goal:** Structured hunting workflows that an analyst can follow step-by-step.
Plus annotation system for adding notes to any threat/connection/finding.

### Hunt Hypotheses Backend (new service: api/services/hunt_hypotheses.py)
- File-backed JSON store in data/hypotheses/
- CRUD for hypothesis templates:
  - title, description, mitre_techniques, data_sources, steps[], status (draft/active/completed)
  - Each step: description, query_hint, expected_result, actual_result, completed
- Pre-seed 5 hypothesis templates:
  1. C2 Beaconing Detection (periodic outbound to single dest)
  2. DNS Tunneling Investigation (high subdomain count, TXT queries)
  3. Data Exfiltration Hunt (large outbound transfers, unusual protocols)
  4. Lateral Movement Detection (internal SMB/RDP/WMI patterns)
  5. Rogue Service Discovery (unexpected listening ports, new services)

### Hunt Hypotheses Router (api/routers/hunt_hypotheses.py)
- `GET /api/v1/hypotheses` - List all
- `POST /api/v1/hypotheses` - Create
- `GET /api/v1/hypotheses/{id}` - Get one
- `PUT /api/v1/hypotheses/{id}` - Update
- `DELETE /api/v1/hypotheses/{id}` - Delete
- `POST /api/v1/hypotheses/{id}/steps/{step_idx}/complete` - Mark step done

### Annotations Backend (new service: api/services/annotations.py)
- File-backed JSON store in data/annotations/
- Annotation = { id, target_type (threat|connection|dns|beacon|session), target_id, content, author, tags[], created_at, updated_at }
- CRUD endpoints under /api/v1/annotations

### Frontend
- New page: Hunt Hypotheses (or tab within Hunt Results)
  - Template library with cards
  - Step-by-step execution view with checkboxes
  - Link steps to actual data (connections, DNS, beacons)
- Annotation panel: slide-over on any threat/connection detail
  - Add note, tag, mark as investigated/false-positive/confirmed
  - Show annotation history

## 5C: Trend Analysis Dashboard (Backend + Frontend)
**Goal:** Week-over-week and day-over-day trend analysis. Shows whether your
network threat posture is improving or degrading.

### Backend
- New router: api/routers/trends.py
- Endpoints:
  - `GET /api/v1/trends/summary` - Overall trend data (threats over time, severity shifts)
  - `GET /api/v1/trends/hosts` - Per-host trend (score changes over time)
  - `GET /api/v1/trends/mitre` - MITRE technique frequency changes

### Data
- Store periodic snapshots in data/trends/ (JSON files per day)
- `POST /api/v1/trends/snapshot` - Take a point-in-time snapshot of current threat state
- Compare snapshots to generate trend data
- In demo mode: pre-seed 7 days of trend data

### Frontend (new page or tab within Analytics)
- Trend line charts: threat count over time, severity distribution over time
- Host risk score sparklines (up/down arrows, delta indicators)
- MITRE heatmap changes (new techniques appearing, old ones resolving)
- "Threat Posture" summary card: Improving / Stable / Degrading

## 5D: Long Connection Analyzer Enhancement + AC-Hunter Parity Features
**Goal:** Make the existing long connection detection match AC-Hunter's deep dive capability.
Add the "all communications for a host" view that AC-Hunter highlights.

### Backend Enhancements
- api/services/long_connection_analyzer.py - add scoring for connection duration outliers
- New endpoint: `GET /api/v1/hosts/{ip}/deep-dive` - Returns ALL communications for a host:
  - All connections (inbound + outbound)
  - All DNS queries involving this host
  - All alerts for this host
  - Beacon analysis results
  - Long connections
  - Session reconstructions
  - Risk timeline (when did each indicator appear)
- `GET /api/v1/hosts/ranking` - Hosts ranked by composite threat score (AC-Hunter's main view)

### Frontend
- New page: Host Deep Dive (/host/:ip)
  - Tabbed view: Overview, Connections, DNS, Alerts, Beacons, Timeline
  - Risk score prominently displayed
  - All evidence cards with expandable details
- Host Ranking page (or enhance existing Threats page)
  - Sorted list of all hosts by threat score (like AC-Hunter's main panel)
  - Click-through to deep dive
  - Severity badges, trend indicators

## Build Notes for Sub-Agents
- **CRITICAL:** `api/config/__init__.py` is the REAL config (it's a package). `api/config.py` is dead code.
- **CRITICAL:** FastAPI `on_event("startup")` doesn't fire reliably. Use `lifespan` context manager.
- **CRITICAL:** `detect_beacons` doesn't exist on BeaconAnalyzer. The method is `analyze_connections`.
- Demo data: Railway needs `VERVET_DEMO_MODE=true` env var.
- Existing services to import from: log_store, unified_threat_engine, beacon_analyzer, dns_analyzer, session_reconstructor, case_manager, report_generator
- V3 is the shipped variant. All frontend work goes in web/src/variants/v3/
- Use CSS classes from styles.css (v3-card, v3-table, v3-badge, v3-btn, etc.)
- Register all new routers in api/main.py
- All new pages need routes in web/src/variants/v3/App.tsx
