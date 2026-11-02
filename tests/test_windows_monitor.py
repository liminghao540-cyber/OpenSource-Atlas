import json
import subprocess

import pytest

from opensource_atlas import windows_monitor


def test_rejects_invalid_limits_and_non_windows(monkeypatch):
    with pytest.raises(ValueError):
        list(windows_monitor.iter_windows_events(poll_interval_seconds=1))
    with pytest.raises(ValueError):
        list(windows_monitor.iter_windows_events(max_events_per_poll=101))
    with pytest.raises(ValueError):
        list(windows_monitor.iter_windows_events(max_polls=0))
    monkeypatch.setattr(windows_monitor.platform, "system", lambda: "Linux")
    with pytest.raises(OSError, match="only on Windows"):
        list(windows_monitor.iter_windows_events())


def test_incremental_poll_yields_only_records_after_baseline(monkeypatch):
    monkeypatch.setattr(windows_monitor.platform, "system", lambda: "Windows")
    calls = []

    def fake_run(args, **kwargs):
        request = json.loads(kwargs["input"])
        calls.append(request)
        if request["mode"] == "baseline":
            payload = [{"record_id": 40}]
        else:
            payload = [
                {"record_id": 41, "event_id": 7036, "log_name": "System",
                 "provider": "Service Control Manager", "level": "Information",
                 "time_created": "2026-11-02T00:00:00Z", "machine_name": "TEST-PC",
                 "message": "Service state changed"},
                {"record_id": 42, "event_id": 7040, "log_name": "System",
                 "provider": "Service Control Manager", "level": "Information",
                 "time_created": "2026-11-02T00:00:01Z", "machine_name": "TEST-PC",
                 "message": "Start type changed"},
            ]
        return subprocess.CompletedProcess(args, 0, json.dumps(payload), "")

    monkeypatch.setattr(windows_monitor.subprocess, "run", fake_run)
    monkeypatch.setattr(windows_monitor.time, "sleep", lambda _: None)
    events = list(windows_monitor.iter_windows_events(
        log_name="System", max_polls=1, start_from_latest=True))
    assert [event["record_id"] for event in events] == [41, 42]
    assert events[0]["event_type"] == "windows_event"
    assert calls[0]["mode"] == "baseline"
    assert calls[1]["mode"] == "poll"
    assert calls[1]["after_record_id"] == 40


def test_start_without_baseline_reads_from_record_zero(monkeypatch):
    monkeypatch.setattr(windows_monitor.platform, "system", lambda: "Windows")
    captured = {}

    def fake_run(args, **kwargs):
        captured.update(json.loads(kwargs["input"]))
        return subprocess.CompletedProcess(args, 0, '[{"record_id":1}]', "")

    monkeypatch.setattr(windows_monitor.subprocess, "run", fake_run)
    events = list(windows_monitor.iter_windows_events(
        max_polls=1, start_from_latest=False))
    assert len(events) == 1
    assert captured["mode"] == "poll"
    assert captured["after_record_id"] == 0


def test_stop_event_prevents_polling(monkeypatch):
    monkeypatch.setattr(windows_monitor.platform, "system", lambda: "Windows")

    class Stop:
        def is_set(self):
            return True

    def unexpected(*args, **kwargs):
        raise AssertionError("no PowerShell invocation expected")

    monkeypatch.setattr(windows_monitor.subprocess, "run", unexpected)
    assert list(windows_monitor.iter_windows_events(stop_event=Stop())) == []


def test_uses_constant_script_and_passes_query_as_json_stdin(monkeypatch):
    monkeypatch.setattr(windows_monitor.platform, "system", lambda: "Windows")
    captured = {}

    def fake_run(args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return subprocess.CompletedProcess(args, 0, "[]", "")

    monkeypatch.setattr(windows_monitor.subprocess, "run", fake_run)
    list(windows_monitor.iter_windows_events(
        log_name="Application", max_polls=1, start_from_latest=False))
    request = json.loads(captured["kwargs"]["input"])
    assert request["log_name"] == "Application"
    assert request["mode"] == "poll"
    assert "Application" not in captured["args"]
    assert "-NoProfile" in captured["args"]


def test_handles_timeout_and_invalid_json(monkeypatch):
    monkeypatch.setattr(windows_monitor.platform, "system", lambda: "Windows")

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(args[0], 1)

    monkeypatch.setattr(windows_monitor.subprocess, "run", timeout)
    with pytest.raises(TimeoutError):
        list(windows_monitor.iter_windows_events(
            max_polls=1, start_from_latest=False))

    monkeypatch.setattr(windows_monitor.subprocess, "run", lambda *a, **kw:
        subprocess.CompletedProcess(a[0], 0, "not-json", ""))
    with pytest.raises(RuntimeError, match="invalid JSON"):
        list(windows_monitor.iter_windows_events(
            max_polls=1, start_from_latest=False))
