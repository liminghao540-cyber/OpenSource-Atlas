from datetime import datetime, timezone

from opensource_atlas.scoring import score_repository


NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)


def base_repository(**overrides):
    repository = {
        "pushed_at": "2025-12-20T00:00:00Z",
        "stargazers_count": 100,
        "forks_count": 20,
        "description": "A useful project",
        "homepage": "https://example.com",
        "topics": ["python"],
        "license": {"spdx_id": "MIT"},
        "archived": False,
    }
    repository.update(overrides)
    return repository


def test_score_is_bounded_and_explained():
    result = score_repository(base_repository(), now=NOW)
    assert 0 <= result["score"] <= 100
    assert len(result["components"]) == 4
    assert sum(item["max_points"] for item in result["components"]) == 100
    assert all(item["evidence"] for item in result["components"])


def test_archived_repository_is_flagged():
    result = score_repository(base_repository(archived=True), now=NOW)
    assert any("archived" in note.lower() for note in result["notes"])
    assert result["components"][-1]["points"] == 10


def test_missing_push_timestamp_is_not_scored_as_zero():
    result = score_repository(base_repository(pushed_at=None), now=NOW)
    assert "pushed_at" in result["missing_signals"]
    maintenance = next(c for c in result["components"] if c["name"] == "Maintenance")
    assert maintenance["points"] <= maintenance["max_points"]
    assert result["score_basis"] == "65/65 weighted points available"


def test_old_push_receives_fewer_maintenance_points():
    recent = score_repository(base_repository(), now=NOW)
    old = score_repository(base_repository(pushed_at="2020-01-01T00:00:00Z"), now=NOW)
    recent_points = next(c["points"] for c in recent["components"] if c["name"] == "Maintenance")
    old_points = next(c["points"] for c in old["components"] if c["name"] == "Maintenance")
    assert recent_points > old_points
