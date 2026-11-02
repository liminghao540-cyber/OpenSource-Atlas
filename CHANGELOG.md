# Changelog

All notable changes to OpenSource Atlas are documented here.
A version is released only when its matching Git tag and GitHub Release exist.

## [8.0.3] - Unreleased

### Added
- Opt-in, bounded Windows Event Log polling iterator with in-memory record-ID cursor.
- Explicit stop-event support, finite poll/runtime limits, and incremental event delivery.
- Mocked tests and Windows monitor usage/safety documentation.

### Security and limitations
- Foreground, caller-started, read-only polling only; no service, scheduled task, persistence, or auto-start.
- No telemetry upload, process termination, file deletion, quarantine, firewall changes, or automatic response.
- PowerShell integration is mocked in CI; live Windows 10 validation remains required.

## [8.0.2] - Unreleased

### Added
- Caller-supplied in-memory asset inventory normalization and duplicate detection.
- Deterministic finding correlation and deduplication with stable fingerprints.
- Evidence provenance, occurrence counts, time bounds, and asset enrichment.
- Expiring fingerprint-based suppressions that retain underlying evidence.
- Explicit, bounded, read-only Windows Event Log snapshot collection for Application, System, and Security logs.
- Mocked tests for Windows collection validation, timeout handling, fixed PowerShell invocation, and output normalization.

### Security and limitations
- Windows event collection is opt-in and read-only; it is not a background monitor or EDR agent.
- No endpoint discovery, telemetry upload, persistence, or automatic response.
- Suppression affects triage state only; response execution remains disabled.

## [8.0.1] - Unreleased

### Added
- Deterministic analysis of caller-supplied normalized security events.
- Approval-gated dry-run response planning and bounded JSONL ingestion.

### Preserved
- Existing repository inspection, explainable scoring, Markdown/JSON reports, and local dashboard.
- Python 3.11, 3.12, and 3.13 automated test coverage.
