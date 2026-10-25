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


@pytest.mark.parametrize("value", ["", "not-a-repository", "owner/", "/repo", "https://example.com/a/b"])
def test_invalid_repository_is_rejected(value):
    with pytest.raises(ValueError):
        normalize_repository(value)
