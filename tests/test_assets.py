import pytest
from opensource_atlas.assets import build_asset_inventory, normalize_asset


def test_normalizes_sorts_and_deduplicates_tags():
    result = build_asset_inventory([
        {"asset_id": " HOST-B ", "platform": " Windows ", "tags": ["prod", "prod"]},
        {"id": "host-a"},
    ])
    assert result["accepted"] == 2
    assert [x["asset_id"] for x in result["assets"]] == ["host-a", "host-b"]
    assert result["assets"][1]["tags"] == ["prod"]


def test_duplicate_asset_id_is_rejected():
    result = build_asset_inventory([{"id": "host-1"}, {"asset_id": "HOST-1"}])
    assert result["accepted"] == 1 and result["rejected"] == 1


@pytest.mark.parametrize("asset", [{}, {"id": 3}, {"id": "x", "tags": "prod"}])
def test_invalid_asset_is_rejected(asset):
    with pytest.raises((TypeError, ValueError)):
        normalize_asset(asset)
