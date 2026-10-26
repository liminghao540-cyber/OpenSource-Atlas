# OpenSource Atlas

[![Tests](https://github.com/liminghao540-cyber/OpenSource-Atlas/actions/workflows/tests.yml/badge.svg)](https://github.com/liminghao540-cyber/OpenSource-Atlas/actions/workflows/tests.yml) [![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/) [![Status](https://img.shields.io/badge/status-early%20development-orange)](docs/roadmap.md)

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

Create and activate a virtual environment, then install the project.

### Windows PowerShell

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e .
```

If PowerShell blocks activation because of its execution policy, you can skip activation and call the environment's Python directly:

```powershell
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\atlas.exe inspect pallets/flask
```

### Windows Command Prompt

```bat
py -3.11 -m venv .venv
.venv\Scripts\activate.bat
python -m pip install -e .
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
```

### Run an inspection

```bash
# Print a Markdown report to the terminal
atlas inspect pallets/flask

# Save a Markdown report
atlas inspect pallets/flask --format markdown --output report.md

# Save a JSON report for scripts or further analysis
atlas inspect https://github.com/psf/requests --format json --output report.json
```

The `atlas` command is installed by the package. If your shell cannot find it, confirm the virtual environment is active, or run it through Python:

```bash
python -m opensource_atlas.cli inspect pallets/flask
```

Public GitHub API requests work without a token, but unauthenticated rate limits apply. OpenSource Atlas does not request or store GitHub credentials.

## Troubleshooting

- **Python version error:** use Python 3.11 or newer; check with `python --version` (Windows users can also try `py --list`).
- **`atlas` command not found:** activate the environment where you installed the package, or use `python -m opensource_atlas.cli inspect owner/name`.
- **GitHub API rate limit or access error:** wait before retrying. The first release uses unauthenticated public API access and does not ask you to paste a personal access token.
- **Repository not found:** check the spelling and confirm the repository is public and its URL is a GitHub repository URL.
- **Cannot write a report file:** choose a directory where your account has write permission, and check that the target file is not locked by another program.

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

See the [architecture overview](docs/architecture.md), [product roadmap](docs/roadmap.md), [testing and acceptance guide](docs/testing.md), [changelog](CHANGELOG.md), [contributing guide](CONTRIBUTING.md), and [security policy](SECURITY.md).

## Project status

The current implementation is an early-stage Python CLI. The automated workflow is configured for Python 3.11, 3.12, and 3.13; check the live [Actions page](https://github.com/liminghao540-cyber/OpenSource-Atlas/actions/workflows/tests.yml) for the status of the latest run. A configured workflow is not, by itself, evidence that the latest commit passed.

The optional authenticated API client, historical snapshots, and web dashboard are planned work—not current features. See the [detailed roadmap](docs/roadmap.md) and [changelog](CHANGELOG.md).

## License

No license has been selected yet. Until one is added, do not assume this repository's code is licensed for reuse.
