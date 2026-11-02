"""Bounded, opt-in polling of Windows Event Logs.

The monitor runs only while the caller iterates it. It keeps its record-ID
cursor in memory, has explicit poll/runtime limits, and performs read-only
queries. It does not install a service, schedule a task, auto-start, persist
state, upload events, or execute response actions.
"""
from __future__ import annotations

import json
import platform
import subprocess
import time
from typing import Any, Iterator

_ALLOWED_LOGS = {"Application", "System", "Security"}
_MAX_EVENTS_PER_POLL = 100
_MAX_POLLS = 10_000
_MAX_RUNTIME_SECONDS = 3_600
_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$allowed = @('Application', 'System', 'Security')
if ($request.log_name -notin $allowed) { throw 'Unsupported event log.' }
$items = @()
if ($request.mode -eq 'baseline') {
    $latest = Get-WinEvent -LogName $request.log_name -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($null -ne $latest) { $items = @(@{ record_id = [long]$latest.RecordId }) }
} elseif ($request.mode -eq 'poll') {
    $cursor = [long]$request.after_record_id
    $xpath = '*[System[EventRecordID > ' + $cursor.ToString() + ']]'
    $items = @(Get-WinEvent -LogName $request.log_name -FilterXPath $xpath -MaxEvents ([int]$request.max_events) -ErrorAction SilentlyContinue | Sort-Object RecordId | ForEach-Object {
        @{
            event_id = $_.Id
            log_name = $_.LogName
            provider = $_.ProviderName
            level = $_.LevelDisplayName
            time_created = if ($_.TimeCreated) { $_.TimeCreated.ToUniversalTime().ToString('o') } else { $null }
            record_id = [long]$_.RecordId
            machine_name = $_.MachineName
            message = if ($_.Message) { $_.Message.Substring(0, [Math]::Min(2000, $_.Message.Length)) } else { '' }
        }
    })
} else { throw 'Unsupported collection mode.' }
ConvertTo-Json -InputObject @($items) -Depth 4 -Compress
"""


def _invoke(log_name: str, mode: str, *, after_record_id: int = 0,
            max_events: int = 1, timeout_seconds: int = 20) -> list[dict[str, Any]]:
    request = json.dumps({
        "log_name": log_name,
        "mode": mode,
        "after_record_id": after_record_id,
        "max_events": max_events,
    })
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "RemoteSigned", "-Command", _SCRIPT],
            input=request, capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout_seconds, check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("powershell.exe was not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("Windows Event Log polling timed out") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or "PowerShell returned an error").strip()[:500]
        raise RuntimeError(f"Windows Event Log polling failed: {detail}")
    output = completed.stdout.strip()
    if not output:
        return []
    try:
        parsed = json.loads(output)
    except json.JSONDecodeError as exc:
        raise RuntimeError("PowerShell returned invalid JSON") from exc
    rows = parsed if isinstance(parsed, list) else [parsed]
    return [row for row in rows if isinstance(row, dict)]


def _normalize(record: dict[str, Any]) -> dict[str, Any]:
    return {
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
    }


def iter_windows_events(
    *,
    log_name: str = "System",
    poll_interval_seconds: int = 5,
    max_events_per_poll: int = 50,
    max_polls: int = 60,
    max_runtime_seconds: int = 300,
    timeout_seconds: int = 20,
    start_from_latest: bool = True,
    stop_event: Any = None,
) -> Iterator[dict[str, Any]]:
    """Yield newly recorded Windows events while the caller consumes the iterator.

    Defaults stop after 60 polls or five minutes, whichever comes first.
    Pass a threading.Event-like object to request early stop via is_set().
    With start_from_latest=True, existing records are treated as baseline and
    only subsequently written records are yielded.
    """
    if not isinstance(log_name, str) or log_name not in _ALLOWED_LOGS:
        raise ValueError("log_name must be Application, System, or Security")
    limits = (
        ("poll_interval_seconds", poll_interval_seconds, 5, 300),
        ("max_events_per_poll", max_events_per_poll, 1, _MAX_EVENTS_PER_POLL),
        ("max_polls", max_polls, 1, _MAX_POLLS),
        ("max_runtime_seconds", max_runtime_seconds, 1, _MAX_RUNTIME_SECONDS),
        ("timeout_seconds", timeout_seconds, 1, 120),
    )
    for name, value, minimum, maximum in limits:
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")
    if not isinstance(start_from_latest, bool):
        raise ValueError("start_from_latest must be a boolean")
    if stop_event is not None and not callable(getattr(stop_event, "is_set", None)):
        raise ValueError("stop_event must provide an is_set() method")
    if platform.system() != "Windows":
        raise OSError("Windows Event Log monitoring is available only on Windows")
    # Honor an already-set stop request before invoking PowerShell for baseline.
    if stop_event is not None and stop_event.is_set():
        return

    cursor = 0
    if start_from_latest:
        baseline = _invoke(log_name, "baseline", timeout_seconds=timeout_seconds)
        if baseline:
            try:
                cursor = max(0, int(baseline[-1].get("record_id") or 0))
            except (TypeError, ValueError):
                cursor = 0

    started = time.monotonic()
    for poll_number in range(max_polls):
        if stop_event is not None and stop_event.is_set():
            break
        elapsed = time.monotonic() - started
        if elapsed >= max_runtime_seconds:
            break
        if poll_number:
            remaining = max_runtime_seconds - elapsed
            if remaining <= 0:
                break
            time.sleep(min(poll_interval_seconds, remaining))
            if stop_event is not None and stop_event.is_set():
                break
        rows = _invoke(
            log_name, "poll", after_record_id=cursor,
            max_events=max_events_per_poll, timeout_seconds=timeout_seconds,
        )
        for row in rows:
            try:
                record_id = int(row.get("record_id"))
            except (TypeError, ValueError):
                continue
            if record_id <= cursor:
                continue
            cursor = max(cursor, record_id)
            yield _normalize(row)
