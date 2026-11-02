"""Caller-supplied, in-memory asset inventory normalization."""
from __future__ import annotations
from typing import Any


def normalize_asset(asset: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(asset, dict):
        raise TypeError("asset must be a dictionary")
    raw_id = asset.get("asset_id", asset.get("id"))
    if not isinstance(raw_id, str) or not raw_id.strip():
        raise ValueError("asset_id must be a non-empty string")
    asset_id = raw_id.strip().casefold()
    if len(asset_id) > 200:
        raise ValueError("asset_id must be at most 200 characters")

    def text_field(key: str, limit: int = 120) -> str | None:
        value = asset.get(key)
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError(f"{key} must be a string")
        value = value.strip()
        if len(value) > limit:
            raise ValueError(f"{key} must be at most {limit} characters")
        return value or None

    tags = asset.get("tags", [])
    if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
        raise ValueError("tags must be a list of strings")
    clean_tags = sorted({tag.strip()[:80] for tag in tags if tag.strip()})
    if len(clean_tags) > 50:
        raise ValueError("tags must contain at most 50 unique values")
    return {
        "asset_id": asset_id,
        "hostname": text_field("hostname"),
        "platform": text_field("platform", 80),
        "environment": text_field("environment", 80),
        "owner": text_field("owner"),
        "tags": clean_tags,
    }


def build_asset_inventory(records: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(records, list):
        raise TypeError("records must be a list")
    assets, errors, seen = [], [], set()
    for index, record in enumerate(records):
        try:
            normalized = normalize_asset(record)
            if normalized["asset_id"] in seen:
                raise ValueError("duplicate asset_id")
            seen.add(normalized["asset_id"])
            assets.append(normalized)
        except (TypeError, ValueError) as exc:
            errors.append({"index": index, "error": str(exc)})
    assets.sort(key=lambda item: item["asset_id"])
    return {"schema_version": "1.0", "assets": assets, "errors": errors,
            "accepted": len(assets), "rejected": len(errors)}
