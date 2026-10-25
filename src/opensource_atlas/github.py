"""Small, dependency-free client for public GitHub repository metadata."""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

_API_ROOT = "https://api.github.com"
_REPO_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


class GitHubAPIError(RuntimeError):
    """Raised when GitHub cannot provide repository metadata."""


def normalize_repository(value: str) -> str:
    """Accept owner/name or a standard github.com repository URL."""
    raw = value.strip()
    if raw.lower().startswith(("http://", "https://")):
        parsed = urlsplit(raw)
        if parsed.hostname is None or parsed.hostname.lower() != "github.com":
            raise ValueError("Repository URL must use the github.com host.")
        candidate = parsed.path.strip("/")
        # Repository pages may include /tree/<branch> or other subpaths.
        parts = candidate.split("/")
        if len(parts) > 2:
            candidate = "/".join(parts[:2])
    elif raw.startswith("git@github.com:"):
        candidate = raw[len("git@github.com:"):].rstrip("/")
    else:
        candidate = raw.rstrip("/")
        if len(candidate.split("/")) != 2:
            raise ValueError(
                "Repository must be owner/name or a GitHub repository URL, "
                "for example: https://github.com/pallets/flask"
            )
    candidate = re.sub(r"\.git$", "", candidate, flags=re.I)
    if not _REPO_PATTERN.fullmatch(candidate):
        raise ValueError(
            "Repository must be owner/name or a GitHub repository URL, "
            "for example: https://github.com/pallets/flask"
        )
    return candidate


def fetch_repository(value: str, timeout: float = 10.0) -> dict:
    """Fetch public repository metadata using GitHub's REST API."""
    full_name = normalize_repository(value)
    request = Request(
        f"{_API_ROOT}/repos/{full_name}",
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "OpenSource-Atlas/0.1.0",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        if exc.code == 404:
            raise GitHubAPIError(
                "Repository not found or not publicly accessible. "
                "Check the owner/name and repository visibility."
            ) from exc
        if exc.code == 403 or exc.code == 429:
            raise GitHubAPIError(
                "GitHub API rate limit or access restriction reached. "
                "Wait and retry; authenticated access may be added in a future release."
            ) from exc
        raise GitHubAPIError(f"GitHub API returned HTTP {exc.code}.") from exc
    except (URLError, TimeoutError) as exc:
        raise GitHubAPIError(f"Could not reach GitHub: {exc}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GitHubAPIError("GitHub returned an invalid JSON response.") from exc

    if not isinstance(payload, dict) or "full_name" not in payload:
        raise GitHubAPIError("GitHub response did not contain repository metadata.")
    return payload
