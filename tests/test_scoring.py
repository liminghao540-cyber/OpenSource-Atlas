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
    assert all(c["name"] != "Maintenance" for c in result["components"])
    assert result["score_basis"] == "56/65 weighted points available"
    assert any("unavailable" in note.lower() for note in result["notes"])


def test_old_push_receives_fewer_maintenance_points():
    recent = score_repository(base_repository(), now=NOW)
    old = score_repository(base_repository(pushed_at="2020-01-01T00:00:00Z"), now=NOW)
    recent_points = next(c["points"] for c in recent["components"] if c["name"] == "Maintenance")
    old_points = next(c["points"] for c in old["components"] if c["name"] == "Maintenance")
    assert recent_points > old_points



def test_naive_reference_datetime_is_treated_as_utc():
    naive_now = datetime(2026, 1, 1)
    aware_now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    naive_result = score_repository(base_repository(), now=naive_now)
    aware_result = score_repository(base_repository(), now=aware_now)

    assert naive_result == aware_result


def test_timezone_aware_reference_datetime_is_normalized_to_utc():
    from datetime import timedelta

    utc_now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    offset_now = datetime(2026, 1, 1, 8, tzinfo=timezone(timedelta(hours=8)))

    utc_result = score_repository(base_repository(), now=utc_now)
    offset_result = score_repository(base_repository(), now=offset_now)

    assert utc_result == offset_result
