"""Bounded JSONL ingestion for caller-supplied security events.

This module parses local text only. It performs no network access, file access,
credential handling, telemetry collection, or response actions.
"""
from __future__ import annotations

import json
from typing import Any


def ingest_jsonl(
    content: str,
    *,
    max_line_bytes: int = 65_536,
    max_events: int = 10_000,
) -> dict[str, Any]:
    """Parse JSONL into validated event dictionaries and line-specific errors."""
    if not isinstance(content, str):
        raise TypeError("content must be a string")
    if (not isinstance(max_line_bytes, int) or isinstance(max_line_bytes, bool)
            or max_line_bytes < 1):
        raise ValueError("max_line_bytes must be a positive integer")
    if (not isinstance(max_events, int) or isinstance(max_events, bool)
            or max_events < 1):
        raise ValueError("max_events must be a positive integer")

    events: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    def reject(line_number: int, reason: str) -> None:
        errors.append({"line": line_number, "error": reason})

    for line_number, line in enumerate(content.splitlines(), start=1):
        if not line.strip():
            continue
        if len(line.encode("utf-8")) > max_line_bytes:
            reject(line_number, "line exceeds max_line_bytes")
            continue
        if len(events) >= max_events:
            reject(line_number, "event limit exceeded")
            continue
        try:
            event = json.loads(
                line,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    ValueError(f"non-standard JSON constant: {value}")
                ),
            )
        except (json.JSONDecodeError, ValueError):
            reject(line_number, "invalid JSON")
            continue
        if not isinstance(event, dict):
            reject(line_number, "event must be a JSON object")
            continue
        event_type = event.get("event_type")
        if not isinstance(event_type, str) or not event_type.strip():
            reject(line_number, "event_type must be a non-empty string")
            continue
        event["event_type"] = event_type.strip().lower()[:80]
        events.append(event)

    return {
        "schema_version": "1.0",
        "events": events,
        "errors": errors,
        "accepted": len(events),
        "rejected": len(errors),
    }
