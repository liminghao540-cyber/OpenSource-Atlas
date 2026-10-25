# OpenSource Atlas

**Understand the health of a GitHub repository with transparent, actionable evidence.**

OpenSource Atlas is an open-source repository intelligence tool. Its first release inspects public GitHub repository metadata, calculates an explainable health score, and exports Markdown or JSON reports.

> **Status:** Early development. Scores are heuristic signals, not a guarantee of code quality or project safety.

## Features

- Inspect public GitHub repositories by URL or `owner/name`.
- Review maintenance recency, community adoption, project metadata, and repository signals.
- See score components and the evidence behind each component.
- Export reports as Markdown or JSON.
- Run locally with Python 3.11+ and no third-party runtime dependencies.

## Quick start

```bash
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1

python -m pip install -e .
atlas inspect pallets/flask
atlas inspect https://github.com/psf/requests --format json --output report.json
atlas inspect pallets/flask --format markdown --output report.md
```

Public GitHub API requests work without a token, but unauthenticated rate limits apply. OpenSource Atlas does not request or store GitHub credentials.

## Score model

The initial heuristic score is composed of four transparent dimensions:

| Dimension | Weight | Signals |
|---|---:|---|
| Maintenance | 35 | Time since latest push |
| Adoption | 25 | Stars and forks |
| Project metadata | 20 | Description, homepage, topics |
| Repository signals | 20 | License declaration and archived status |

The score is an indicator for triage, not an objective ranking. It does not inspect source-code correctness, vulnerability status, maintainer intent, or the quality of issue discussions. Missing evidence is called out in the report rather than silently treated as proof of poor quality.

## Development

```bash
python -m pip install -e ".[dev]"
pytest
```

See [the architecture overview](docs/architecture.md), [contributing guide](CONTRIBUTING.md), and [security policy](SECURITY.md).

## Roadmap

- [x] Public repository metadata inspection
- [x] Explainable health scoring
- [x] Markdown and JSON reports
- [x] Unit tests for scoring and report generation
- [ ] Optional authenticated GitHub API client
- [ ] Historical trend snapshots
- [ ] Web dashboard

## License

No license has been selected yet. Until one is added, do not assume this repository's code is licensed for reuse.
