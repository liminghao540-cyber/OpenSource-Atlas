# Changelog

All notable changes to OpenSource Atlas are documented here.
A version is released only when its matching Git tag and GitHub Release exist.

## [8.0.4] - Unreleased

### Added
- V6-style bounded Windows host snapshot: TCP connections/listeners, process metadata, Authenticode status, bounded SHA-256, firewall profile state, and Defender 1116/1117 events.
- Explainable heuristic host findings and bounded foreground monitoring with an in-memory deduplication set.
- V7-style explicit human-approved temporary outbound IP blocks, strict public-IP validation, bounded TTL/rule count, ownership state, response ledger, expiry cleanup, and preview-first exact rollback.
- Mocked tests and Windows 10 usage/safety documentation.

### Security and limitations
- Monitoring remains opt-in, foreground-only, bounded, and read-only.
- Firewall response is a separate explicit call; exact approval token BLOCK is required. No automatic response.
- Expiry cleanup is caller-triggered, not a background timer. Exact ownership metadata is verified before rule removal.
- PowerShell is mocked in CI; live Windows 10 validation remains required.

## [8.0.3] - Unreleased

### Added
- Opt-in, bounded Windows Event Log polling iterator with in-memory record-ID cursor.
- Explicit stop-event support, finite poll/runtime limits, and incremental event delivery.
- Mocked tests and Windows monitor usage/safety documentation.

### Security and limitations
- Foreground, caller-started, read-only polling only; no service, scheduled task, persistence, or auto-start.
- No telemetry upload, process termination, file deletion, quarantine, firewall changes, or automatic response.
- PowerShell integration is mocked in CI. A live Windows 10 validation remains required.

## [8.0.2] - Unreleased

### Added
- Caller-supplied in-memory asset inventory normalization and duplicate detection.
- Deterministic finding fingerprints, deduplication, provenance retention, asset enrichment, and expiring suppressions.
- Explicit, bounded, read-only Windows Event Log snapshot collection.

### Security and limitations
- Event collection is opt-in and read-only; it is not a background monitor or EDR agent.
- No endpoint discovery, telemetry upload, persistence, or automatic response.

## [8.0.1] - Unreleased

### Added
- Deterministic analysis of caller-supplied normalized security events.
- Approval-gated dry-run response planning and bounded JSONL ingestion.

### Preserved
- Existing repository inspection, explainable scoring, Markdown/JSON reports, and local dashboard.
- Python 3.11, 3.12, and 3.13 automated test coverage.
