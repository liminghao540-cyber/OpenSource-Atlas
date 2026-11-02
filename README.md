# OpenSource Atlas

[![Tests](https://github.com/liminghao540-cyber/OpenSource-Atlas/actions/workflows/tests.yml/badge.svg)](https://github.com/liminghao540-cyber/OpenSource-Atlas/actions/workflows/tests.yml) [![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/) [![Version](https://img.shields.io/badge/version-8.0.2--candidate-orange)](CHANGELOG.md)

**Understand public repositories and analyze supplied security events with transparent, actionable evidence.**

OpenSource Atlas is evolving from a GitHub repository intelligence tool into an explainable, approval-gated security operations foundation. The V8.0.2 candidate preserves the repository inspection CLI and local dashboard while adding bounded security-event analysis, asset correlation, and an explicitly invoked, read-only Windows Event Log snapshot collector.

> **Release status:** V8.0.2 is under development on a separate branch; it is not a published GitHub Release. Host event collection is opt-in and read-only. Response execution is disabled.

## V8.0.2 capabilities

- Normalize caller-supplied asset records and report duplicate identifiers.
- Correlate equivalent findings with stable fingerprints, provenance, and expiry-aware triage suppressions.
- Read a bounded snapshot from the Windows Application, System, or Security event log when explicitly invoked.
- Keep response planning in dry-run mode; no containment or destructive action is executed.

See the [V8.0.2 design](docs/V8.0.2_DESIGN.md), [Windows collection guide](docs/V8.0.2_WINDOWS_COLLECTION.md), and [changelog](CHANGELOG.md).

## Existing repository intelligence features

- Inspect public GitHub repositories by URL or `owner/name`.
- Review maintenance recency, community adoption, project metadata, and repository signals.
- See score components and the evidence behind each component.
- Export reports as Markdown or JSON.
- Use the optional local web dashboard.
- Run locally with Python 3.11+.

## Quick start

### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m pytest
```

### Windows Command Prompt

```bat
py -3.11 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -e ".[dev]"
python -m pytest
```

### Run repository inspection

```bash
atlas inspect pallets/flask
atlas inspect pallets/flask --format json --output report.json
```

### Launch the local dashboard

```bash
atlas-web
```

Open http://127.0.0.1:8765. The dashboard binds to localhost only.

## Explicit Windows Event Log snapshot

```python
from opensource_atlas.windows_events import collect_windows_events

snapshot = collect_windows_events(log_name="System", hours=24, max_events=100)
for event in snapshot["events"]:
    print(event)
```

This is a bounded, read-only snapshot, not continuous monitoring. Begin with the System or Application log. Security log access may require administrator privileges. The collector does not clear logs, install services or scheduled tasks, upload events, or execute response actions.

## Security-event analysis API

```python
from opensource_atlas.events import ingest_jsonl
from opensource_atlas.detection import analyze_event
from opensource_atlas.response import build_response_plan

parsed = ingest_jsonl('{"event_type":"malware_detected","source":"demo","asset":"host-01"}')
for event in parsed["events"]:
    finding = analyze_event(event)
    plan = build_response_plan(finding)
    print(finding)
    print(plan)
```

## Limitations and security

- No continuous endpoint agent, network scanner, or EDR capability is included.
- Windows collection is explicit, bounded, local, and read-only.
- No credentials or tokens are collected or stored.
- No blocking, isolation, deletion, account modification, or network change is performed.
- Detection results are triage signals, not proof of compromise or proof of safety.
- No license has been selected. Do not assume the code is licensed for reuse until a license is added.
