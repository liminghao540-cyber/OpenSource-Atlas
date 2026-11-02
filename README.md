# OpenSource Atlas

[![Tests](https://github.com/liminghao540-cyber/OpenSource-Atlas/actions/workflows/tests.yml/badge.svg)](https://github.com/liminghao540-cyber/OpenSource-Atlas/actions/workflows/tests.yml) [![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/) [![Version](https://img.shields.io/badge/version-8.0.4--candidate-orange)](CHANGELOG.md)

**Understand public repositories and analyze supplied security events with transparent, actionable evidence.**

OpenSource Atlas is evolving from a GitHub repository intelligence tool into an explainable, approval-gated security operations foundation. V8.0.4 integrates bounded Windows host telemetry from the V6 line and the optional human-approved temporary firewall response from V7.

> **Release status:** V8.0.4 is under development on a separate branch; it is not a published GitHub Release. Windows monitoring is opt-in, foreground-only, bounded, and read-only. Firewall response is a separate explicit action and is disabled unless directly invoked with approval.

## V8.0.4 Windows Defense integration

- V6-style TCP established/listening sockets, process name/PID/path, Authenticode status, bounded SHA-256, firewall profile state, and Defender events 1116/1117.
- Explainable heuristic risk scoring and bounded foreground monitoring with in-memory deduplication.
- V7-style temporary outbound block for a validated public IP, only after explicit approval token BLOCK.
- 1–60 minute TTL, maximum five owned rules, local response ledger, expiry cleanup, and preview-first exact rollback.
- No automatic blocking, process termination, file deletion, quarantine, firewall-profile changes, Defender changes, or remote telemetry upload.

See the [V8.0.4 Windows Defense guide](docs/V8.0.4_WINDOWS_DEFENSE.md), [V8.0.3 Windows monitor guide](docs/V8.0.3_WINDOWS_MONITOR.md), and [changelog](CHANGELOG.md).

## Existing repository intelligence features

- Inspect public GitHub repositories by URL or owner/name.
- Review maintenance recency, community adoption, project metadata, and repository signals.
- See score components and the evidence behind each component.
- Export reports as Markdown or JSON.
- Use the optional local web dashboard.
- Run locally with Python 3.11+.

## Quick start

### Windows PowerShell

    py -3.11 -m venv .venv
    .\\.venv\\Scripts\\Activate.ps1
    python -m pip install -e ".[dev]"
    python -m pytest

### Run repository inspection

    atlas inspect pallets/flask
    atlas inspect pallets/flask --format json --output report.json

### Local dashboard

    atlas-web

Open http://127.0.0.1:8765. The dashboard binds to localhost only.

## V8.0.4 Windows host telemetry

    from opensource_atlas.windows_defense import collect_windows_host_snapshot, analyze_host_snapshot

    snapshot = collect_windows_host_snapshot(max_connections=500)
    findings = analyze_host_snapshot(snapshot)
    print(findings)

For bounded foreground monitoring, use iter_windows_defense_events. The first
snapshot establishes a baseline; later samples yield newly observed events.

## V7-style response — explicit approval only

    from opensource_atlas.firewall_response import create_temporary_outbound_block

    create_temporary_outbound_block("8.8.8.8", approval="BLOCK", ttl_minutes=10)

This requires Windows and an elevated PowerShell context. It blocks the specified
public IP for all outbound traffic and may interrupt legitimate services. It
does not kill a process or alter firewall profiles. Expiry cleanup is caller-
triggered; it is not a background timer. Rollback previews by default. Read the
full safety guide before using this function.

## Limitations and security

- Windows APIs are opt-in, bounded, local, and invoked only by the caller.
- Some process paths, signatures, hashes, firewall state, and event logs may be unavailable without sufficient permissions.
- Detection results are triage signals, not proof of compromise or proof of safety.
- CI mocks PowerShell calls; perform the documented live Windows 10 validation before relying on monitoring.
- No license has been selected. Do not assume the code is licensed for reuse until a license is added.
