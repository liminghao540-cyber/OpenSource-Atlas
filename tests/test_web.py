from opensource_atlas import web
from opensource_atlas.github import GitHubAPIError


def sample_repository():
    return {
        "full_name": "octo/example",
        "html_url": "https://github.com/octo/example",
        "description": "Example project",
        "pushed_at": "2025-12-20T00:00:00Z",
        "stargazers_count": 10,
        "forks_count": 2,
        "license": {"spdx_id": "MIT"},
        "archived": False,
        "topics": ["python"],
        "homepage": "https://example.com",
        "private": False,
        "default_branch": "main",
        "created_at": "2020-01-01T00:00:00Z",
        "updated_at": "2025-12-20T00:00:00Z",
        "open_issues_count": 3,
    }


def test_analyze_repository_uses_existing_report_pipeline(monkeypatch):
    monkeypatch.setattr(web, "fetch_repository", lambda value: sample_repository())
    report = web.analyze_repository("octo/example")
    assert report["repository"]["name"] == "octo/example"
    assert report["health"]["components"]
    assert report["schema_version"] == "1.0"


def test_analyze_repository_propagates_api_errors(monkeypatch):
    def fail(_value):
        raise GitHubAPIError("rate limit")

    monkeypatch.setattr(web, "fetch_repository", fail)
    try:
        web.analyze_repository("octo/example")
    except GitHubAPIError as exc:
        assert "rate limit" in str(exc)
    else:
        raise AssertionError("Expected GitHubAPIError")


def test_dashboard_is_local_only():
    try:
        web.serve(host="0.0.0.0", port=0)
    except ValueError as exc:
        assert "localhost" in str(exc)
    else:
        raise AssertionError("Dashboard must reject non-loopback binding")


def test_dashboard_page_contains_expected_controls():
    assert "OpenSource Atlas" in web.PAGE
    assert "/api/inspect" in web.PAGE
    assert "Export JSON" in web.PAGE
    assert "Export Markdown" in web.PAGE
