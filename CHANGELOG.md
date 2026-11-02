# Changelog

All notable changes to OpenSource Atlas are documented here.

This project follows a lightweight Keep a Changelog structure. A version is considered released only when its matching Git tag and GitHub Release have been published.

## [8.0.1] - Unreleased

### Added
- Deterministic analysis of caller-supplied normalized security events, with explicit evidence and limitations.
- Approval-gated, dry-run response plan generation; no response action is executed.
- Bounded JSONL event parsing with per-line validation errors and configurable input limits.
- V8 upgrade plan documenting architecture, milestones, acceptance criteria, and safety boundaries.

### Preserved
- Existing public GitHub repository inspection, explainable scoring, Markdown/JSON reports, and local-only dashboard.
- Python 3.11, 3.12, and 3.13 automated test coverage.

### Security and limitations
- Event ingestion parses supplied text only; it is not a host agent, SIEM connector, network scanner, or telemetry collector.
- Response planning is proposal-only. Execution is disabled.
- No credentials are collected or stored.
- Detection results are triage signals, not proof of compromise or proof of safety.

## [Unreleased]

### Planned
- Asset inventory, finding correlation, deduplication, and provenance-aware risk views.
- Connector health and operational audit visibility.
- Dashboard views for findings and response-plan review.
