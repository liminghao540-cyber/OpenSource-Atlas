# Changelog

All notable changes to OpenSource Atlas are documented here.
A version is released only when its matching Git tag and GitHub Release exist.

## [8.0.2] - Unreleased

### Added
- Caller-supplied in-memory asset inventory normalization and duplicate detection.
- Deterministic finding correlation and deduplication with stable fingerprints.
- Evidence provenance, occurrence counts, time bounds, and asset enrichment.
- Expiring fingerprint-based suppressions that retain underlying evidence.
- V8.0.2 design documentation and focused tests.

### Security and limitations
- No endpoint discovery, telemetry collection, persistence, or external connector.
- Suppression affects triage state only; response execution remains disabled.

## [8.0.1] - Unreleased

### Added
- Deterministic analysis of caller-supplied normalized security events.
- Approval-gated dry-run response planning and bounded JSONL ingestion.

### Preserved
- Existing repository inspection, explainable scoring, Markdown/JSON reports, and local dashboard.
- Python 3.11, 3.12, and 3.13 automated test coverage.

### Security and limitations
- Event ingestion parses supplied text only; it is not a host agent, SIEM connector, network scanner, or telemetry collector.
- Response planning is proposal-only. Execution is disabled.
