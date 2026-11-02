import json
import subprocess

import pytest

from opensource_atlas import firewall_response as response


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "192.168.1.1",
                                     "169.254.1.1", "224.0.0.1", "not-an-ip"])
def test_rejects_non_public_addresses(address):
    with pytest.raises(ValueError):
        response._public_address(address)


def test_requires_exact_human_approval_before_side_effects(tmp_path, monkeypatch):
    monkeypatch.setattr(response.platform, "system", lambda: "Windows")
    def unexpected(*args, **kwargs): raise AssertionError("must not invoke PowerShell")
    monkeypatch.setattr(response.subprocess, "run", unexpected)
    with pytest.raises(PermissionError):
        response.create_temporary_outbound_block(
            "8.8.8.8", approval="yes",
            state_path=tmp_path / "state.json", ledger_path=tmp_path / "ledger.jsonl")


def test_validates_ttl_and_rule_cap_before_side_effects(tmp_path, monkeypatch):
    monkeypatch.setattr(response.platform, "system", lambda: "Windows")
    with pytest.raises(ValueError):
        response.create_temporary_outbound_block(
            "8.8.8.8", approval="BLOCK", ttl_minutes=61,
            state_path=tmp_path / "state.json", ledger_path=tmp_path / "ledger.jsonl")


def test_creates_rule_using_fixed_script_and_json_stdin(tmp_path, monkeypatch):
    monkeypatch.setattr(response.platform, "system", lambda: "Windows")
    captured = {}
    def fake_run(args, **kwargs):
        captured["args"], captured["kwargs"] = args, kwargs
        request = json.loads(kwargs["input"])
        assert request["remote_address"] == "8.8.8.8"
        return subprocess.CompletedProcess(args, 0, json.dumps({"status": "created"}), "")
    monkeypatch.setattr(response.subprocess, "run", fake_run)
    result = response.create_temporary_outbound_block(
        "8.8.8.8", approval="BLOCK", ttl_minutes=5,
        state_path=tmp_path / "state.json", ledger_path=tmp_path / "ledger.jsonl")
    assert result["status"] == "created"
    assert "-NoProfile" in captured["args"]
    assert "8.8.8.8" not in captured["args"]
    state = json.loads((tmp_path / "state.json").read_text(encoding="utf-8"))
    assert state["rules"][0]["status"] == "active"


def test_rollback_defaults_to_preview(tmp_path):
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"schema_version": "1.0", "rules": [
        {"name": "OSA8-TempOut-0123456789abcdef", "remote_address": "8.8.8.8"}
    ]}), encoding="utf-8")
    result = response.rollback_temporary_outbound_blocks(state_path=state)
    assert result["no_changes_made"] is True
    assert state.exists()
