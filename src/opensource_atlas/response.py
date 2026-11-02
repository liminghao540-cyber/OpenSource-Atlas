"""Approval-gated response planning; no action is executed by this module."""
from __future__ import annotations
from typing import Any

_RESPONSE_TEMPLATES = {
    "critical": [("preserve_evidence", "Preserve relevant logs and event context."), ("notify_operator", "Notify the designated security operator immediately."), ("containment_review", "Request an authorized operator to assess containment options.")],
    "high": [("preserve_evidence", "Preserve relevant logs and event context."), ("notify_operator", "Notify the designated security operator."), ("investigation", "Open an investigation task for the affected asset.")],
    "medium": [("record_event", "Record the event for triage."), ("investigation", "Request analyst review.")],
    "low": [("record_event", "Record the event for routine review.")],
    "info": [("record_event", "Record the event as informational context.")],
}


def build_response_plan(assessment: dict[str, Any]) -> dict[str, Any]:
    """Build a dry-run plan from a detection assessment; never execute actions."""
    if not isinstance(assessment, dict):
        raise TypeError("assessment must be a dictionary")
    severity = assessment.get("severity", "info")
    if severity not in _RESPONSE_TEMPLATES:
        raise ValueError("assessment severity must be info, low, medium, high, or critical")
    steps = [{"action": action, "description": description, "status": "proposed"}
             for action, description in _RESPONSE_TEMPLATES[severity]]
    return {
        "plan_version": "1.0", "mode": "dry_run", "severity": severity,
        "approval_required": True, "execution_enabled": False, "steps": steps,
        "safety_note": "Recommendations only. No response action has been executed. Any future integration that changes systems must require explicit authorization, least-privilege credentials, and an auditable approval.",
    }
