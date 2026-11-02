"""Deterministic correlation for caller-supplied findings; no side effects."""
from __future__ import annotations
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

_SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except ValueError:
        return None


def _stamp(value: datetime | None) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value else None


def _fingerprint(item: dict[str, Any]) -> str:
    identity = {
        "rule_id": str(item.get("rule_id") or "unclassified").strip().casefold(),
        "asset_id": str(item.get("asset_id") or item.get("asset") or "unknown").strip().casefold(),
        "title": str(item.get("title") or "").strip().casefold(),
        "evidence": str(item.get("evidence") or "").strip().casefold(),
    }
    raw = json.dumps(identity, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def correlate_findings(findings: list[dict[str, Any]], *,
                       assets: list[dict[str, Any]] | None = None,
                       suppressions: list[dict[str, Any]] | None = None,
                       now: str | None = None) -> dict[str, Any]:
    """Group identical findings, retain provenance, and honor expiring suppressions."""
    if not isinstance(findings, list):
        raise TypeError("findings must be a list")
    assets = [] if assets is None else assets
    suppressions = [] if suppressions is None else suppressions
    if not isinstance(assets, list) or not isinstance(suppressions, list):
        raise TypeError("assets and suppressions must be lists")
    reference = _time(now) if now is not None else datetime.now(timezone.utc)
    if reference is None:
        raise ValueError("now must be a valid ISO-8601 timestamp")
    asset_index = {a["asset_id"].casefold(): a for a in assets
                   if isinstance(a, dict) and isinstance(a.get("asset_id"), str)}
    active = {}
    for rule in suppressions:
        if isinstance(rule, dict) and isinstance(rule.get("fingerprint"), str):
            expiry = _time(rule.get("expires_at"))
            if expiry and expiry > reference:
                active[rule["fingerprint"]] = rule
    groups, errors = {}, []
    for index, item in enumerate(findings):
        if not isinstance(item, dict):
            errors.append({"index": index, "error": "finding must be a dictionary"})
            continue
        severity = item.get("severity", "info")
        if not isinstance(severity, str) or severity not in _SEVERITY:
            errors.append({"index": index, "error": "invalid severity"})
            continue
        confidence = item.get("confidence")
        if confidence is not None and (isinstance(confidence, bool)
            or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1):
            errors.append({"index": index, "error": "confidence must be between 0 and 1"})
            continue
        fingerprint = _fingerprint(item)
        asset_id = str(item.get("asset_id") or item.get("asset") or "").strip().casefold()
        observed = _time(item.get("observed_at"))
        source = item.get("source")
        provenance = {"source": source[:120] if isinstance(source, str) else None,
                      "observed_at": _stamp(observed)}
        if fingerprint not in groups:
            groups[fingerprint] = {
                "fingerprint": fingerprint,
                "rule_id": item.get("rule_id") if isinstance(item.get("rule_id"), str) else "unclassified",
                "title": item.get("title") if isinstance(item.get("title"), str) else "Unclassified finding",
                "asset_id": asset_id or None, "severity": severity,
                "confidence": float(confidence) if confidence is not None else None,
                "evidence": item.get("evidence") if isinstance(item.get("evidence"), str) else "",
                "occurrences": 0, "first_seen": _stamp(observed),
                "last_seen": _stamp(observed), "provenance": [],
            }
        current = groups[fingerprint]
        current["occurrences"] += 1
        if _SEVERITY[severity] > _SEVERITY[current["severity"]]:
            current["severity"] = severity
        if confidence is not None:
            current["confidence"] = max(current["confidence"] or 0.0, float(confidence))
        times = [_time(current["first_seen"]), _time(current["last_seen"]), observed]
        times = [value for value in times if value is not None]
        if times:
            current["first_seen"], current["last_seen"] = _stamp(min(times)), _stamp(max(times))
        if provenance not in current["provenance"]:
            current["provenance"].append(provenance)
    results = []
    for fingerprint, item in groups.items():
        item["provenance"].sort(key=lambda p: (p["observed_at"] or "", p["source"] or ""))
        item["asset"] = asset_index.get(item["asset_id"] or "")
        suppression = active.get(fingerprint)
        item["suppressed"] = suppression is not None
        item["suppression_expires_at"] = suppression.get("expires_at") if suppression else None
        results.append(item)
    results.sort(key=lambda item: (-_SEVERITY[item["severity"]], item["fingerprint"]))
    return {"schema_version": "1.0", "generated_at": _stamp(reference),
            "findings": results, "errors": errors, "input_count": len(findings),
            "correlated_count": len(results),
            "duplicate_count": sum(max(0, item["occurrences"] - 1) for item in results)}
