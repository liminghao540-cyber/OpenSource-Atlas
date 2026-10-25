import json
from unittest.mock import MagicMock
from urllib.error import HTTPError, URLError

import pytest

from opensource_atlas import github
from opensource_atlas.github import GitHubAPIError, fetch_repository, normalize_repository


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("pallets/flask", "pallets/flask"),
        ("https://github.com/psf/requests", "psf/requests"),
        ("https://github.com/psf/requests.git", "psf/requests"),
        ("git@github.com:psf/requests.git", "psf/requests"),
        ("https://github.com/psf/requests/tree/main", "psf/requests"),
        ("  psf/requests  ", "psf/requests"),
    ],
)
def test_normalize_repository(value, expected):
    assert normalize_repository(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "",
        "not-a-repository",
        "owner/",
        "/repo",
        "https://example.com/a/b",
        "example.com/foo/bar",
        "owner/repo/extra",
        "https://github.com.evil.test/owner/repo",
    ],
)
def test_invalid_repository_is_rejected(value):
    with pytest.raises(ValueError):
        normalize_repository(value)


def mock_response(payload):
    response = MagicMock()
    response.read.return_value = json.dumps(payload).encode("utf-8")
    manager = MagicMock()
    manager.__enter__.return_value = response
    return manager


def test_fetch_repository_returns_metadata_and_sends_expected_headers(monkeypatch):
    payload = {"full_name": "octo/example", "stargazers_count": 3}
    captured = {}

    def fake_urlopen(request, timeout):
        captured["request"] = request
        captured["timeout"] = timeout
        return mock_response(payload)

    monkeypatch.setattr(github, "urlopen", fake_urlopen)

    result = fetch_repository("octo/example")

    assert result == payload
    assert captured["timeout"] == 10.0
    assert captured["request"].full_url.endswith("/repos/octo/example")
    assert captured["request"].get_header("User-agent") == "OpenSource-Atlas/0.1.0"
    assert captured["request"].get_header("Accept") == "application/vnd.github+json"


@pytest.mark.parametrize("status", [403, 429])
def test_fetch_repository_reports_rate_limit_errors(monkeypatch, status):
    def fail_request(request, timeout):
        raise HTTPError(request.full_url, status, "restricted", {}, None)

    monkeypatch.setattr(github, "urlopen", fail_request)

    with pytest.raises(GitHubAPIError, match="rate limit or access restriction"):
        fetch_repository("octo/example")


def test_fetch_repository_reports_missing_repository(monkeypatch):
    def fail_request(request, timeout):
        raise HTTPError(request.full_url, 404, "not found", {}, None)

    monkeypatch.setattr(github, "urlopen", fail_request)

    with pytest.raises(GitHubAPIError, match="Repository not found"):
        fetch_repository("octo/missing")


def test_fetch_repository_reports_other_http_errors(monkeypatch):
    def fail_request(request, timeout):
        raise HTTPError(request.full_url, 500, "server error", {}, None)

    monkeypatch.setattr(github, "urlopen", fail_request)

    with pytest.raises(GitHubAPIError, match="HTTP 500"):
        fetch_repository("octo/example")


@pytest.mark.parametrize("error", [URLError("offline"), TimeoutError("timed out")])
def test_fetch_repository_reports_connection_errors(monkeypatch, error):
    def fail_request(request, timeout):
        raise error

    monkeypatch.setattr(github, "urlopen", fail_request)

    with pytest.raises(GitHubAPIError, match="Could not reach GitHub"):
        fetch_repository("octo/example")


@pytest.mark.parametrize("body", [b"{not json", b"\xff\xfe\xff"])
def test_fetch_repository_rejects_invalid_json_or_encoding(monkeypatch, body):
    response = MagicMock()
    response.read.return_value = body
    manager = MagicMock()
    manager.__enter__.return_value = response
    monkeypatch.setattr(github, "urlopen", lambda request, timeout: manager)

    with pytest.raises(GitHubAPIError, match="invalid JSON"):
        fetch_repository("octo/example")


@pytest.mark.parametrize("payload", [["not", "an", "object"], {}, {"message": "API error"}])
def test_fetch_repository_rejects_unexpected_payload(monkeypatch, payload):
    monkeypatch.setattr(
        github, "urlopen", lambda request, timeout: mock_response(payload)
    )

    with pytest.raises(GitHubAPIError, match="did not contain repository metadata"):
        fetch_repository("octo/example")
