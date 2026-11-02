"""Explicit, read-only Windows Event Log collection.

Collection is opt-in: callers invoke collect_windows_events() directly.
Only the Application, System, and Security logs are accepted. The PowerShell
script is constant; request values are sent as JSON on stdin, never interpolated
into executable command text. No event is modified or cleared.
"""
from __future__ import annotations

import json
import platform
import subprocess
from typing import Any

_ALLOWED_LOGS = {"Application", "System", "Security"}
_MAX_EVENTS = 500
_MAX_HOURS = 168
_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$allowed = @('Application', 'System', 'Security')
if ($request.log_name -notin $allowed) { throw 'Unsupported event log.' }
$start = [DateTimeOffset]::Parse($request.start_time)
$items = @(Get-WinEvent -FilterHashtable @{
    LogName = $request.log_name
    StartTime = $start.UtcDateTime
} -MaxEvents ([int]$request.max_events) -ErrorAction SilentlyContinue | ForEach-Object {
    @{
        event_id = $_.Id
        log_name = $_.LogName
        provider = $_.ProviderName
        level = $_.LevelDisplayName
        time_created = if ($_.TimeCreated) { $_.TimeCreated.ToUniversalTime().ToString('o') } else { $null }
        record_id = $_.RecordId
        machine_name = $_.MachineName
        message = if ($_.Message) { $_.Message.Substring(0, [Math]::Min(2000, $_.Message.Length)) } else { '' }
    }
})
ConvertTo-Json -InputObject $items -Depth 4 -Compress
"""


def collect_windows_events(
    *,
    log_name: str = "System",
    hours: int = 24,
    max_events: int = 100,
    timeout_seconds: int = 20,
) -> dict[str, Any]:
    """Read a bounded number of recent events from one allow-listed Windows log.

    This function never clears logs, changes settings, starts persistence, or
    performs response actions. Security log access may require administrator
    privileges; prefer Application or System for an initial test.
    """
    if not isinstance(log_name, str) or log_name not in _ALLOWED_LOGS:
        raise ValueError("log_name must be Application, System, or Security")
    for name, value, maximum in (
        ("hours", hours, _MAX_HOURS),
        ("max_events", max_events, _MAX_EVENTS),
        ("timeout_seconds", timeout_seconds, 120),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= maximum:
            raise ValueError(f"{name} must be an integer between 1 and {maximum}")
    if platform.system() != "Windows":
        raise OSError("Windows Event Log collection is available only on Windows")

    from datetime import datetime, timedelta, timezone
    start_time = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    request = json.dumps({
        "log_name": log_name,
        "start_time": start_time,
        "max_events": max_events,
    })
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "RemoteSigned", "-Command", _SCRIPT],
            input=request,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_seconds,
            check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("powershell.exe was not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("Windows Event Log collection timed out") from exc

    if completed.returncode != 0:
        detail = (completed.stderr or "PowerShell returned an error").strip()[:500]
        raise RuntimeError(f"Windows Event Log collection failed: {detail}")
    output = completed.stdout.strip()
    if not output:
        records: list[Any] = []
    else:
        try:
            parsed = json.loads(output)
        except json.JSONDecodeError as exc:
            raise RuntimeError("PowerShell returned invalid JSON") from exc
        records = parsed if isinstance(parsed, list) else [parsed]
    events = []
    for record in records[:max_events]:
        if not isinstance(record, dict):
            continue
        events.append({
            "event_type": "windows_event",
            "source": "windows_event_log",
            "asset": record.get("machine_name"),
            "observed_at": record.get("time_created"),
            "event_id": record.get("event_id"),
            "log_name": record.get("log_name"),
            "provider": record.get("provider"),
            "level": record.get("level"),
            "record_id": record.get("record_id"),
            "message": record.get("message"),
        })
    return {
        "schema_version": "1.0",
        "source": "windows_event_log",
        "log_name": log_name,
        "requested_hours": hours,
        "requested_max_events": max_events,
        "accepted": len(events),
        "events": events,
        "read_only": True,
        "limitations": [
            "Only the selected Windows event log is read.",
            "Access to the Security log may require administrator privileges.",
            "Event messages and source authenticity are not independently verified.",
            "No logs are cleared, changed, or uploaded; no response action is executed.",
        ],
    }
