import json
import platform
import subprocess
from unittest.mock import Mock

import pytest

from opensource_atlas import windows_events


def test_rejects_unsupported_logs_and_unbounded_limits():
    with pytest.raises(ValueError):
        windows_events.collect_windows_events(log_name="Microsoft-Windows-PowerShell/Operational")
    with pytest.raises(ValueError):
        windows_events.collect_windows_events(hours=999)
    with pytest.raises(ValueError):
        windows_events.collect_windows_events(max_events=501)
    with pytest.raises(ValueError):
        windows_events.collect_windows_events(timeout_seconds=True)


def test_refuses_to_run_outside_windows(monkeypatch):
    monkeypatch.setattr(windows_events.platform, "system", lambda: "Linux")
    with pytest.raises(OSError, match="only on Windows"):
        windows_events.collect_windows_events()


def test_reads_and_normalizes_mocked_windows_event_log(monkeypatch):
    monkeypatch.setattr(windows_events.platform, "system", lambda: "Windows")
    payload = [{
        "event_id": 7036, "log_name": "System", "provider": "Service Control Manager",
        "level": "Information", "time_created": "2026-11-02T00:00:00Z",
        "record_id": 44, "machine_name": "TEST-PC", "message": "Service changed state",
    }]
    monkeypatch.setattr(windows_events.subprocess, "run", lambda *a, **kw:
        subprocess.CompletedProcess(a[0], 0, json.dumps(payload), ""))
    result = windows_events.collect_windows_events(log_name="System", max_events=10)
    assert result["accepted"] == 1
    assert result["read_only"] is True
    assert result["events"][0]["event_type"] == "windows_event"
    assert result["events"][0]["asset"] == "TEST-PC"


def test_passes_request_via_stdin_and_uses_fixed_script(monkeypatch):
    monkeypatch.setattr(windows_events.platform, "system", lambda: "Windows")
    captured = {}
    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(args, 0, "[]", "")
    monkeypatch.setattr(windows_events.subprocess, "run", fake_run)
    windows_events.collect_windows_events(log_name="Application", hours=2, max_events=7)
    request = json.loads(captured["kwargs"]["input"])
    assert request["log_name"] == "Application"
    assert request["max_events"] == 7
    assert captured["kwargs"]["timeout"] == 20
    assert "-NoProfile" in captured["args"]
    assert "Application" not in captured["args"]


def test_handles_timeout_and_missing_powershell(monkeypatch):
    monkeypatch.setattr(windows_events.platform, "system", lambda: "Windows")
    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 1)
    monkeypatch.setattr(windows_events.subprocess, "run", timeout)
    with pytest.raises(TimeoutError):
        windows_events.collect_windows_events()
    def missing(*args, **kwargs):
        raise FileNotFoundError()
    monkeypatch.setattr(windows_events.subprocess, "run", missing)
    with pytest.raises(RuntimeError, match="not found"):
        windows_events.collect_windows_events()


def test_rejects_invalid_json_from_powershell(monkeypatch):
    monkeypatch.setattr(windows_events.platform, "system", lambda: "Windows")
    monkeypatch.setattr(windows_events.subprocess, "run", lambda *a, **kw:
        subprocess.CompletedProcess(a[0], 0, "not-json", ""))
    with pytest.raises(RuntimeError, match="invalid JSON"):
        windows_events.collect_windows_events()
