import pytest

from opensource_atlas.github import normalize_repository


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("pallets/flask", "pallets/flask"),
        ("https://github.com/psf/requests", "psf/requests"),
        ("https://github.com/psf/requests.git", "psf/requests"),
        ("git@github.com:psf/requests.git", "psf/requests"),
        ("https://github.com/psf/requests/tree/main", "psf/requests"),
    ],
)
def test_normalize_repository(value, expected):
    assert normalize_repository(value) == expected


@pytest.mark.parametrize("value", ["", "not-a-repository", "owner/", "/repo", "https://example.com/a/b", "example.com/foo/bar", "owner/repo/extra", "https://github.com.evil.test/owner/repo"])
def test_invalid_repository_is_rejected(value):
    with pytest.raises(ValueError):
        normalize_repository(value)


import json
from urllib.error import HTTPError
from unittest.mock import MagicMock

from opensource_atlas import github
from opensource_atlas.github import GitHubAPIError, fetch_repository


def mock_response(payload):
    response = MagicMock()
    response.read.return_value = json.dumps(payload).encode("utf-8")
    manager = MagicMock()
    manager.__enter__.return_value = response
    return manager


def test_fetch_repository_returns_metadata(monkeypatch):
    payload = {"full_name": "octo/example", "stargazers_count": 3}
    monkeypatch.setattr(github, "urlopen", lambda request, timeout: mock_response(payload))

    result = fetch_repository("octo/example")

    assert result == payload


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


def test_fetch_repository_rejects_invalid_json(monkeypatch):
    response = MagicMock()
    response.read.return_value = b"{not json"
    manager = MagicMock()
    manager.__enter__.return_value = response
    monkeypatch.setattr(github, "urlopen", lambda request, timeout: manager)

    with pytest.raises(GitHubAPIError, match="invalid JSON"):
        fetch_repository("octo/example")


def test_fetch_repository_rejects_unexpected_payload(monkeypatch):
    monkeypatch.setattr(github, "urlopen", lambda request, timeout: mock_response(["not", "an", "object"]))

    with pytest.raises(GitHubAPIError, match="did not contain repository metadata"):
        fetch_repository("octo/example")
