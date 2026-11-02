# OpenSource Atlas

[![Tests](https://github.com/liminghao540-cyber/OpenSource-Atlas/actions/workflows/tests.yml/badge.svg)](https://github.com/liminghao540-cyber/OpenSource-Atlas/actions/workflows/tests.yml) [![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/) [![Version](https://img.shields.io/badge/version-8.0.1--candidate-orange)](CHANGELOG.md)

**Understand public repositories and analyze supplied security events with transparent, actionable evidence.**

OpenSource Atlas is evolving from a GitHub repository intelligence tool into an explainable, approval-gated security operations foundation. The V8.0.1 release candidate preserves the existing repository inspection CLI and local dashboard while adding bounded security-event ingestion, deterministic event analysis, and dry-run response planning.

> **Release status:** V8.0.1 is being prepared; it is not a published GitHub Release yet. Security analysis is limited to caller-supplied events. Response execution is disabled.

## V8 capabilities

- Parse caller-supplied JSONL security events with per-line validation and configurable size/count limits.
- Analyze normalized events using deterministic rules and return explainable findings.
- Generate response proposals in dry-run mode; every plan requires approval and has execution disabled.
- Preserve the repository intelligence CLI, explainable scoring, Markdown/JSON reports, and local-only dashboard.

See the [V8.0.1 installation and verification guide](docs/V8.0.1_INSTALL.md), [V8 upgrade plan](docs/V8_UPGRADE_PLAN.md), and [changelog](CHANGELOG.md).

## Existing repository intelligence features

- Inspect public GitHub repositories by URL or `owner/name`.
- Review maintenance recency, community adoption, project metadata, and repository signals.
- See score components and the evidence behind each component.
- Export reports as Markdown or JSON.
- Use the optional local web dashboard.
- Run locally with Python 3.11+.

## Quick start

Create and activate a virtual environment, then install the project.

### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
python -m pip install -e .
```

### Windows Command Prompt

```bat
py -3.11 -m venv .venv
.venv\\Scripts\\activate.bat
python -m pip install -e .
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
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

Open http://127.0.0.1:8765. The dashboard binds to localhost only; it is not intended for internet-facing deployment.

## V8 security-event API (library)

The initial event APIs are Python library interfaces, not separate CLI commands or background services:

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

JSONL ingestion parses the string supplied by the caller. It does not read files, connect to SIEM products, collect telemetry, or authenticate event sources. Detection is a triage aid, not proof of compromise or proof of safety. Response plans are proposals only: `execution_enabled` remains false.

## Development and tests

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

See the [architecture overview](docs/architecture.md), [roadmap](docs/roadmap.md), [testing guide](docs/testing.md), [release process](docs/releasing.md), [contributing guide](CONTRIBUTING.md), and [security policy](SECURITY.md).

## Limitations and security

- No endpoint agent, host monitoring, network scanning, source-code execution, or vulnerability scanner is included.
- No credentials or tokens are collected or stored by the V8 foundation.
- No blocking, isolation, deletion, account modification, or network change is performed.
- Production deployment requires authentication, authorization, secure secret management, threat modeling, and independent security review.
- Repository health scores and event findings are heuristic triage signals.
- No license has been selected. Do not assume the code is licensed for reuse until a license is added.
