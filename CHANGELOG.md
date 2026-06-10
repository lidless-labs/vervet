# Changelog

All notable changes to Vervet are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-06-10

First public release under the **Vervet** name (formerly "Bro Hunter").

### Changed
- **Rebranded** the project to Vervet, a sentinel-animal name in the IDS tradition
  (Snort, Suricata) that covers both the Zeek and Suricata log sources rather than
  leaning on a single engine. Environment variables moved from `BROHUNTER_*` to
  `VERVET_*` (the old prefix is still honored for one release with a deprecation
  warning).
- **Relicensed** from MIT to **Apache-2.0**.
- Rewrote the README around the product: explainable per-host scoring, MITRE
  ATT&CK mapping, and an honest note that the OSS edition is in-memory.

### Added
- `docker compose up -d --build` one-command demo: a single container serves the
  API and web UI on `:8000` and seeds a sample environment on startup.
- CI (GitHub Actions): backend `pytest`, frontend build, and a Docker image build.
- Marketing site at `site/index.html`.

### Fixed
- **Dockerfile build:** added the `pkg-config` + `libcairo2-dev` toolchain that
  `pycairo` (via `xhtml2pdf`) needs to compile; the image never built before.
- **Unified threat engine** (the per-host scoring path) crashed on any ingested
  Suricata alert or detected beacon and was never exercised end to end. Fixed a
  cluster of latent defects that the test suite had been masking:
  - `datetime` timestamps passed into float-typed MITRE mapping fields
    (long-connection analyzer and the engine's timeline/temporal bounds).
  - The engine fed unified `Alert` objects to the Suricata analyzer, which expects
    raw `SuricataAlert`; added an adapter. Also `alert.dst_ip` -> `alert.dest_ip`.
  - `BeaconResult.threat_level` did not exist; severity is now derived from the
    beacon score.
  - `_build_aggregate_indicators` was written against a `ThreatIndicator` schema
    that did not match the model; rewritten so beacon, DNS, alert, and
    long-connection indicators all populate.
  - Beacon MITRE techniques are now expanded into the consolidated per-host MITRE
    view (the code read a nonexistent `mitre_mappings`).
  - Alerts now surface on both the source and destination host profiles.
- Repaired the test suite (was 69 failing on a fresh clone, now green): correct
  time-span fixtures, required model fields, and the stale `_log_store` reference.
