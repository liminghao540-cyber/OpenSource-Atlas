"""Render inspection results as JSON or Markdown."""
from __future__ import annotations

import json
from datetime import datetime, timezone


def build_report(repository: dict, scorecard: dict) -> dict:
    return {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repository": {
            "name": repository.get("full_name"),
            "url": repository.get("html_url"),
            "description": repository.get("description"),
            "visibility": "private" if repository.get("private") else "public",
            "default_branch": repository.get("default_branch"),
            "created_at": repository.get("created_at"),
            "updated_at": repository.get("updated_at"),
            "pushed_at": repository.get("pushed_at"),
            "stars": repository.get("stargazers_count"),
            "forks": repository.get("forks_count"),
            "open_issues": repository.get("open_issues_count"),
            "license": (repository.get("license") or {}).get("spdx_id"),
            "archived": repository.get("archived"),
            "topics": repository.get("topics") or [],
            "homepage": repository.get("homepage"),
        },
        "health": scorecard,
        "limitations": [
            "The score is a heuristic based on public repository metadata.",
            "Source code, vulnerabilities, contributor intent, and issue discussion quality are not assessed.",
            "A low or missing metadata signal is not proof that a project is unsafe or low quality.",
        ],
    }


def to_json(report: dict) -> str:
    return json.dumps(report, indent=2, ensure_ascii=False, sort_keys=False)


def to_markdown(report: dict) -> str:
    repo = report["repository"]
    health = report["health"]
    score = health.get("score")
    score_text = f"{score}/100" if score is not None else "Unavailable"
    lines = [
        f"# Repository Intelligence Report: {repo.get('name') or 'Unknown repository'}",
        "",
        f"- **Repository:** {repo.get('url') or 'Unavailable'}",
        f"- **Generated:** {report.get('generated_at')}",
        f"- **Health indicator:** {score_text}",
        f"- **Score basis:** {health.get('score_basis', 'Unavailable')}",
        "",
        "## Repository overview",
        "",
        repo.get("description") or "_No description provided._",
        "",
        "| Signal | Value |",
        "|---|---|",
        f"| Visibility | {repo.get('visibility') or 'Unknown'} |",
        f"| Default branch | {repo.get('default_branch') or 'Unknown'} |",
        f"| Stars | {repo.get('stars') if repo.get('stars') is not None else 'Unknown'} |",
        f"| Forks | {repo.get('forks') if repo.get('forks') is not None else 'Unknown'} |",
        f"| Open issues (GitHub count) | {repo.get('open_issues') if repo.get('open_issues') is not None else 'Unknown'} |",
        f"| Latest push | {repo.get('pushed_at') or 'Unknown'} |",
        f"| License | {repo.get('license') or 'Not declared'} |",
        f"| Archived | {repo.get('archived') if repo.get('archived') is not None else 'Unknown'} |",
        "",
        "## Score breakdown",
        "",
        "| Dimension | Points | Weight | Evidence |",
        "|---|---:|---:|---|",
    ]
    for item in health.get("components", []):
        evidence = str(item.get("evidence", "")).replace("|", "\\|")
        lines.append(
            f"| {item['name']} | {item['points']} | {item['max_points']} | {evidence} |"
        )
    lines.extend(["", "## Notes", ""])
    lines.extend(f"- {note}" for note in health.get("notes", []))
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {item}" for item in report.get("limitations", []))
    lines.append("")
    return "\n".join(lines)
