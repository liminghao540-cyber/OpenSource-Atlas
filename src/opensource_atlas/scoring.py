"""Transparent heuristic scoring for repository metadata."""
from __future__ import annotations

from datetime import datetime, timezone
from math import log1p


def _parse_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError):
        return None


def _recency_points(pushed_at: str | None, now: datetime) -> tuple[int | None, str]:
    pushed = _parse_datetime(pushed_at)
    if pushed is None:
        return None, "Latest push timestamp is missing or invalid."
    days = max(0, (now - pushed).total_seconds() / 86400)
    if days <= 30:
        points = 35
    elif days <= 90:
        points = 30
    elif days <= 180:
        points = 24
    elif days <= 365:
        points = 16
    elif days <= 730:
        points = 8
    else:
        points = 3
    return points, f"Latest push was approximately {int(days)} day(s) ago."


def score_repository(repository: dict, now: datetime | None = None) -> dict:
    """Return weighted score components and human-readable evidence.

    This score intentionally uses metadata only. It is not a code audit.
    """
    current = now or datetime.now(timezone.utc)
    components: list[dict] = []
    evidence: list[str] = []
    missing: list[str] = []

    maintenance, maintenance_note = _recency_points(repository.get("pushed_at"), current)
    if maintenance is None:
        missing.append("pushed_at")
    else:
        components.append({
            "name": "Maintenance",
            "weight": 35,
            "points": maintenance,
            "max_points": 35,
            "evidence": maintenance_note,
        })

    stars = repository.get("stargazers_count")
    forks = repository.get("forks_count")
    if isinstance(stars, (int, float)) and isinstance(forks, (int, float)):
        # Log scaling limits the effect of very large repositories.
        adoption = round(15 * min(1.0, log1p(max(0, stars)) / log1p(1000))
                         + 10 * min(1.0, log1p(max(0, forks)) / log1p(200)))
        components.append({
            "name": "Adoption",
            "weight": 25,
            "points": adoption,
            "max_points": 25,
            "evidence": f"{int(stars)} stars and {int(forks)} forks; logarithmic scale.",
        })
    else:
        missing.append("stargazers_count/forks_count")

    metadata_fields = {
        "description": bool(repository.get("description")),
        "homepage": bool(repository.get("homepage")),
        "topics": bool(repository.get("topics")),
    }
    metadata_points = round(20 * sum(metadata_fields.values()) / len(metadata_fields))
    components.append({
        "name": "Project metadata",
        "weight": 20,
        "points": metadata_points,
        "max_points": 20,
        "evidence": "Present: " + (", ".join(k for k, v in metadata_fields.items() if v) or "none")
                    + ". Missing: " + (", ".join(k for k, v in metadata_fields.items() if not v) or "none") + ".",
    })

    license_declared = bool(repository.get("license"))
    archived = bool(repository.get("archived"))
    signal_points = (10 if license_declared else 0) + (0 if archived else 10)
    components.append({
        "name": "Repository signals",
        "weight": 20,
        "points": signal_points,
        "max_points": 20,
        "evidence": (
            f"License declared: {'yes' if license_declared else 'no'}; "
            f"archived: {'yes' if archived else 'no'}."
        ),
    })

    available_max = sum(item["max_points"] for item in components)
    earned = sum(item["points"] for item in components)
    score = round(earned / available_max * 100) if available_max else None
    if archived:
        evidence.append("Repository is archived; recent activity should not be interpreted as expected.")
    if missing:
        evidence.append("Some signals were unavailable: " + ", ".join(missing) + ".")
    evidence.append("Metadata-only heuristic; this is not a security or source-code quality audit.")

    return {
        "score": score,
        "score_basis": f"{earned}/{available_max} weighted points available",
        "components": components,
        "missing_signals": missing,
        "notes": evidence,
    }
