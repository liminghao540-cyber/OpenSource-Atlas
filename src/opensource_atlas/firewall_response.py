"""Explicitly approved, temporary Windows Firewall outbound blocks.

Nothing in this module runs automatically. Callers must explicitly invoke a
response function and pass the exact approval token 'BLOCK'. Rules are
restricted to validated public unicast IPs and exact ownership metadata.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import platform
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

_MARKER = "ManagedBy=OpenSourceAtlas-V8.0.4;Scope=TemporaryOutboundBlock"
_GROUP = "OpenSourceAtlas-V8.0.4"
_PREFIX = "OpenSourceAtlas-v8-TemporaryOutboundBlock-"
_RULE_PREFIX = "OSA8-TempOut-"
_CREATE_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$r = [Console]::In.ReadToEnd() | ConvertFrom-Json
$name = [string]$r.name
$display = [string]$r.display_name
$address = [string]$r.remote_address
if ($name -notmatch '^OSA8-TempOut-[0-9a-f]{16}$') { throw 'Invalid owned rule name.' }
if ($display -notlike 'OpenSourceAtlas-v8-TemporaryOutboundBlock-*') { throw 'Invalid display name.' }
if (@(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue).Count -gt 0) { throw 'Rule name already exists; refusing to overwrite.' }
New-NetFirewallRule -Name $name -DisplayName $display -Group 'OpenSourceAtlas-V8.0.4' -Description 'ManagedBy=OpenSourceAtlas-V8.0.4;Scope=TemporaryOutboundBlock' -Direction Outbound -Action Block -RemoteAddress $address -Profile Any -Enabled True -ErrorAction Stop | Out-Null
ConvertTo-Json -Compress @{ status = 'created'; name = $name }
"""
_REMOVE_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$r = [Console]::In.ReadToEnd() | ConvertFrom-Json
$name = [string]$r.name
$expectedAddress = [string]$r.remote_address
if ($name -notmatch '^OSA8-TempOut-[0-9a-f]{16}$') { throw 'Invalid owned rule name.' }
$rules = @(Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue)
if ($rules.Count -eq 0) { ConvertTo-Json -Compress @{ status = 'absent'; name = $name }; exit 0 }
$valid = @($rules | Where-Object {
    $_.Name -eq $name -and
    $_.Description -eq 'ManagedBy=OpenSourceAtlas-V8.0.4;Scope=TemporaryOutboundBlock' -and
    $_.DisplayName -like 'OpenSourceAtlas-v8-TemporaryOutboundBlock-*' -and
    $_.Group -eq 'OpenSourceAtlas-V8.0.4' -and
    $_.Direction -eq 'Outbound' -and $_.Action -eq 'Block'
})
if ($valid.Count -ne 1) { throw 'Ownership verification failed; refusing removal.' }
$addresses = @($valid | Get-NetFirewallAddressFilter)
if ($addresses.Count -ne 1 -or (@($addresses[0].RemoteAddress) -join ',') -ne $expectedAddress) { throw 'Remote address verification failed; refusing removal.' }
Remove-NetFirewallRule -Name $name -ErrorAction Stop
ConvertTo-Json -Compress @{ status = 'removed'; name = $name }
"""


def _public_address(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("remote_address must be a public IP address")
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValueError("remote_address must be a valid IP address") from exc
    if (not address.is_global or address.is_multicast or address.is_unspecified
            or address.is_reserved or address.is_loopback or address.is_link_local
            or getattr(address, "ipv4_mapped", None) is not None):
        raise ValueError("only public global unicast IP addresses are eligible")
    return str(address)


def _paths(state_path: str | Path, ledger_path: str | Path) -> tuple[Path, Path]:
    return Path(state_path), Path(ledger_path)


def _load_state(path: Path) -> list[dict[str, Any]]:
    if not path.exists(): return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("firewall ownership state is unreadable; refusing changes") from exc
    if not isinstance(payload, dict) or payload.get("schema_version") != "1.0" or not isinstance(payload.get("rules"), list):
        raise RuntimeError("firewall ownership state has an unsupported shape; refusing changes")
    return [row for row in payload["rules"] if isinstance(row, dict)]


def _save_state(path: Path, rules: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps({"schema_version": "1.0", "rules": rules},
                                    ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def _ledger(path: Path, record: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def _invoke(script: str, request: dict[str, Any], timeout_seconds: int) -> dict[str, Any]:
    if platform.system() != "Windows":
        raise OSError("Windows Firewall response is available only on Windows")
    try:
        completed = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "RemoteSigned", "-Command", script],
            input=json.dumps(request), capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=timeout_seconds, check=False,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("powershell.exe was not found") from exc
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("Windows Firewall operation timed out") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or "PowerShell returned an error").strip()[:500]
        raise RuntimeError(f"Windows Firewall operation failed: {detail}")
    try:
        result = json.loads(completed.stdout.strip() or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError("PowerShell returned invalid JSON") from exc
    if not isinstance(result, dict): raise RuntimeError("PowerShell returned an invalid response")
    return result


def create_temporary_outbound_block(remote_address: str, *, approval: str,
                                    ttl_minutes: int = 10, max_owned_rules: int = 5,
                                    state_path: str | Path = "data/firewall-response-state.json",
                                    ledger_path: str | Path = "data/firewall-response-ledger.jsonl",
                                    timeout_seconds: int = 30) -> dict[str, Any]:
    """Create one temporary outbound block after the caller explicitly approves.

    Requires an elevated Windows console. No process is terminated and no
    firewall profile/default policy is changed. This changes Windows Firewall.
    """
    address = _public_address(remote_address)
    if approval != "BLOCK": raise PermissionError("explicit approval token must be exactly 'BLOCK'")
    for name, value, low, high in (("ttl_minutes", ttl_minutes, 1, 60),
                                   ("max_owned_rules", max_owned_rules, 1, 5),
                                   ("timeout_seconds", timeout_seconds, 1, 120)):
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise ValueError(f"{name} must be an integer between {low} and {high}")
    state, ledger = _paths(state_path, ledger_path)
    rules = _load_state(state)
    active = [r for r in rules if r.get("status") in ("pending", "active")]
    if len(active) >= max_owned_rules: raise RuntimeError("maximum owned firewall rule count reached")
    digest = hashlib.sha256(address.encode("ascii")).hexdigest()[:16]
    name = _RULE_PREFIX + digest
    if any(r.get("name") == name for r in rules): raise RuntimeError("an owned rule for this address already exists")
    expires = (datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)).isoformat()
    record = {"name": name, "display_name": _PREFIX + digest, "remote_address": address,
              "created_at": datetime.now(timezone.utc).isoformat(), "expires_at": expires,
              "status": "pending"}
    rules.append(record)
    _save_state(state, rules)
    try:
        result = _invoke(_CREATE_SCRIPT, {"name": name, "display_name": record["display_name"],
                                         "remote_address": address}, timeout_seconds)
        if result.get("status") != "created": raise RuntimeError("PowerShell did not confirm rule creation")
        record["status"] = "active"
        _save_state(state, rules)
        _ledger(ledger, {"at": datetime.now(timezone.utc).isoformat(), "action": "create",
                         "status": "success", "name": name, "remote_address": address,
                         "expires_at": expires})
        return {"status": "created", "name": name, "remote_address": address,
                "expires_at": expires, "ttl_minutes": ttl_minutes,
                "warning": "This rule blocks this public IP for all outbound traffic and may interrupt legitimate services."}
    except Exception as exc:
        record["status"] = "pending_cleanup"
        _save_state(state, rules)
        _ledger(ledger, {"at": datetime.now(timezone.utc).isoformat(), "action": "create",
                         "status": "failed_or_uncertain", "name": name, "error": str(exc)[:300]})
        raise


def cleanup_expired_temporary_blocks(*, state_path: str | Path = "data/firewall-response-state.json",
                                     ledger_path: str | Path = "data/firewall-response-ledger.jsonl",
                                     timeout_seconds: int = 30) -> dict[str, Any]:
    """Remove only expired rules whose full ownership metadata still matches."""
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 120:
        raise ValueError("timeout_seconds must be an integer between 1 and 120")
    state, ledger = _paths(state_path, ledger_path)
    rules = _load_state(state)
    now = datetime.now(timezone.utc)
    removed, retained, errors = [], [], []
    for record in rules:
        try:
            expiry = datetime.fromisoformat(str(record.get("expires_at", "")).replace("Z", "+00:00"))
            if expiry.tzinfo is None: expiry = expiry.replace(tzinfo=timezone.utc)
        except ValueError:
            retained.append(record); errors.append("invalid expiry retained"); continue
        if expiry > now or record.get("status") not in ("active", "pending", "pending_cleanup"):
            retained.append(record); continue
        try:
            address = _public_address(str(record.get("remote_address", "")))
            result = _invoke(_REMOVE_SCRIPT, {"name": record.get("name"), "remote_address": address}, timeout_seconds)
            if result.get("status") not in ("removed", "absent"): raise RuntimeError("removal was not confirmed")
            removed.append(record.get("name"))
            _ledger(ledger, {"at": now.isoformat(), "action": "expire", "status": result["status"],
                             "name": record.get("name"), "remote_address": address})
        except Exception as exc:
            retained.append(record); errors.append(str(exc)[:300])
            _ledger(ledger, {"at": now.isoformat(), "action": "expire", "status": "refused_or_failed",
                             "name": record.get("name"), "error": str(exc)[:300]})
    _save_state(state, retained)
    return {"removed": removed, "retained": len(retained), "errors": errors}


def rollback_temporary_outbound_blocks(*, preview: bool = True,
                                       state_path: str | Path = "data/firewall-response-state.json",
                                       ledger_path: str | Path = "data/firewall-response-ledger.jsonl",
                                       timeout_seconds: int = 30) -> dict[str, Any]:
    """Preview by default; set preview=False to remove only exactly owned rules."""
    if not isinstance(preview, bool): raise ValueError("preview must be a boolean")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 120:
        raise ValueError("timeout_seconds must be an integer between 1 and 120")
    state, ledger = _paths(state_path, ledger_path)
    rules = _load_state(state)
    if preview:
        return {"preview": True, "would_remove": [r.get("name") for r in rules],
                "state_file": str(state), "no_changes_made": True}
    removed, retained, errors = [], [], []
    for record in rules:
        try:
            address = _public_address(str(record.get("remote_address", "")))
            result = _invoke(_REMOVE_SCRIPT, {"name": record.get("name"), "remote_address": address}, timeout_seconds)
            if result.get("status") not in ("removed", "absent"): raise RuntimeError("removal was not confirmed")
            removed.append(record.get("name"))
            _ledger(ledger, {"at": datetime.now(timezone.utc).isoformat(), "action": "rollback",
                             "status": result["status"], "name": record.get("name")})
        except Exception as exc:
            retained.append(record); errors.append(str(exc)[:300])
    _save_state(state, retained)
    return {"preview": False, "removed": removed, "retained": len(retained), "errors": errors}
