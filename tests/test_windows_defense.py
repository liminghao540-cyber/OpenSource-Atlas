import json
import subprocess

import pytest

from opensource_atlas import windows_defense


def test_snapshot_validation_and_platform_guard(monkeypatch):
    with pytest.raises(ValueError):
        windows_defense.collect_windows_host_snapshot(max_connections=0)
    monkeypatch.setattr(windows_defense.platform, "system", lambda: "Linux")
    with pytest.raises(OSError, match="only on Windows"):
        windows_defense.collect_windows_host_snapshot()


def test_snapshot_uses_fixed_script_and_json_stdin(monkeypatch):
    monkeypatch.setattr(windows_defense.platform, "system", lambda: "Windows")
    captured = {}
    payload = {"established": [], "listeners": [], "firewall_profiles": [],
               "defender_events": [], "errors": []}
    def fake_run(args, **kwargs):
        captured["args"], captured["kwargs"] = args, kwargs
        return subprocess.CompletedProcess(args, 0, json.dumps(payload), "")
    monkeypatch.setattr(windows_defense.subprocess, "run", fake_run)
    result = windows_defense.collect_windows_host_snapshot(max_connections=12)
    assert result["read_only"] is True
    assert json.loads(captured["kwargs"]["input"])["max_connections"] == 12
    assert "-NoProfile" in captured["args"]
    assert "12" not in captured["args"]


def test_risk_scoring_and_defender_mapping():
    snapshot = {
        "established": [{"pid": 42, "remote_port": 23, "remote_address": "203.0.113.8",
                         "local_address": "10.0.0.2", "local_port": 5000,
                         "process": {"name": "powershell", "path": "C:\\Users\\x\\AppData\\a.exe",
                                     "signature": "NotSigned", "sha256": "abc"}}],
        "listeners": [],
        "firewall_profiles": [{"name": "Public", "enabled": False}],
        "defender_events": [{"event_id": 1116, "message": "detection"}],
    }
    findings = windows_defense.analyze_host_snapshot(snapshot)
    assert any(x["severity"] == "critical" for x in findings)
    assert any(x["rule_id"] == "ATLAS-FW-001" for x in findings)
    assert any(x["rule_id"] == "ATLAS-DEF-001" for x in findings)


def test_unavailable_firewall_is_not_mislabeled_disabled():
    result = windows_defense.analyze_host_snapshot({
        "collection_errors": ["Firewall profile state unavailable"],
        "firewall_profiles": [], "established": [], "listeners": [], "defender_events": [],
    })
    assert result[0]["severity"] == "info"
    assert "not evidence" in result[0]["evidence"]


def test_monitor_honors_stop_before_collection(monkeypatch):
    monkeypatch.setattr(windows_defense.platform, "system", lambda: "Windows")
    class Stop:
        def is_set(self): return True
    def unexpected(**kwargs): raise AssertionError("must not collect")
    monkeypatch.setattr(windows_defense, "collect_windows_host_snapshot", unexpected)
    assert list(windows_defense.iter_windows_defense_events(stop_event=Stop())) == []


def test_monitor_validates_limits():
    with pytest.raises(ValueError):
        list(windows_defense.iter_windows_defense_events(poll_interval_seconds=1))
