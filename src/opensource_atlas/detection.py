"""Explainable, metadata-only security event detection primitives.

This module evaluates caller-supplied normalized events. It does not monitor
hosts, inspect processes, scan networks, or execute response actions.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

_SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
_HIGH_RISK_TYPES = {
    "malware_detected": ("critical", "A malware indicator was reported by the event source."),
    "ransomware_indicator": ("critical", "A ransomware-related indicator was reported."),
    "privilege_escalation": ("high", "A privilege-escalation event was reported."),
    "suspicious_persistence": ("high", "A persistence-related event was reported."),
}


def _timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    except ValueError:
        return None


def analyze_event(event: dict[str, Any]) -> dict[str, Any]:
    """Return a deterministic finding for one normalized security event."""
    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")
    event_type = event.get("event_type")
    if not isinstance(event_type, str):
        event_type = "unknown"
    event_type = event_type.strip().lower()[:80] or "unknown"
    findings: list[dict[str, str]] = []
    if event_type in _HIGH_RISK_TYPES:
        severity, explanation = _HIGH_RISK_TYPES[event_type]
        findings.append({"rule_id": "ATLAS-SEC-001", "severity": severity,
                         "title": event_type.replace("_", " ").title(), "evidence": explanation})
    attempts = event.get("failed_attempts")
    if isinstance(attempts, int) and not isinstance(attempts, bool) and attempts >= 3:
        severity = "high" if attempts >= 10 else "medium"
        findings.append({"rule_id": "ATLAS-AUTH-001", "severity": severity,
                         "title": "Repeated authentication failures",
                         "evidence": f"{attempts} failed authentication attempts were reported in one event window."})
    findings.sort(key=lambda item: _SEVERITY_ORDER[item["severity"]], reverse=True)
    overall = findings[0]["severity"] if findings else "info"
    def safe_text(key: str, limit: int = 200) -> str | None:
        value = event.get(key)
        return value[:limit] if isinstance(value, str) and value.strip() else None
    return {
        "engine_version": "1.0", "event_type": event_type, "severity": overall,
        "source": safe_text("source", 120), "asset": safe_text("asset", 120),
        "observed_at": _timestamp(event.get("observed_at")), "findings": findings,
        "disposition": "review_required" if findings else "no_rule_matched",
        "limitations": [
            "Rules evaluate only the supplied normalized event; source authenticity is not verified.",
            "No host, network, process, or repository source-code inspection is performed.",
            "A no-rule-matched result does not establish that an asset is safe.",
        ],
    }
