"""Bounded Windows host telemetry and explainable V6/V7-style monitoring.

Collection is opt-in and foreground-only. No persistence, upload, or response
action is performed by this module. Firewall responses live in firewall_response.
"""
from __future__ import annotations

import json
import platform
import subprocess
import time
from typing import Any, Iterator

_ALLOWED_LOGS = ("Microsoft-Windows-Windows Defender/Operational",)
_MAX_CONNECTIONS = 1000
_MAX_DEFENDER_EVENTS = 100
_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$maxConnections = [int]$request.max_connections
$maxDefenderEvents = [int]$request.max_defender_events
$processCache = @{}
$errors = New-Object 'System.Collections.Generic.List[string]'
function Get-ProcessEvidence([int]$Id) {
    $cacheKey = [string]$Id
    if ($processCache.ContainsKey($cacheKey)) { return $processCache[$cacheKey] }
    $name = 'unknown'; $path = $null; $signature = 'Unavailable'; $hash = $null
    try {
        $p = Get-Process -Id $Id -ErrorAction Stop
        $name = [string]$p.ProcessName
        try { $path = [string]$p.Path } catch {}
    } catch {}
    if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) {
        try { $signature = [string](Get-AuthenticodeSignature -FilePath $path -ErrorAction Stop).Status } catch { $signature = 'CheckFailed' }
        try {
            $file = Get-Item -LiteralPath $path -ErrorAction Stop
            if ($file.Length -le 104857600) { $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash }
        } catch {}
    }
    $item = @{ pid = $Id; name = $name; path = $path; signature = $signature; sha256 = $hash }
    if ($processCache.Count -lt 300) { $processCache[$cacheKey] = $item }
    return $item
}
function Get-TcpRows([string]$State) {
    $rows = @()
    try {
        $items = @(Get-NetTCPConnection -State $State -ErrorAction Stop | Select-Object -First $maxConnections)
        foreach ($c in $items) {
            $pidValue = [int]$c.OwningProcess
            $proc = Get-ProcessEvidence $pidValue
            $rows += @{
                state = $State; pid = $pidValue; local_address = [string]$c.LocalAddress
                local_port = [int]$c.LocalPort; remote_address = [string]$c.RemoteAddress
                remote_port = [int]$c.RemotePort; process = $proc
            }
        }
    } catch { $errors.Add(('TCP ' + $State + ': ' + $_.Exception.Message)) }
    return @($rows)
}
$established = @(Get-TcpRows 'Established')
$listeners = @(Get-TcpRows 'Listen')
$profiles = @()
try {
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
        @{ name = [string]$_.Name; enabled = [bool]$_.Enabled
           inbound_action = [string]$_.DefaultInboundAction; outbound_action = [string]$_.DefaultOutboundAction }
    })
} catch { $errors.Add('Firewall profile state unavailable') }
$defender = @()
try {
    $defender = @(Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Windows Defender/Operational'; Id = @(1116,1117)
    } -MaxEvents $maxDefenderEvents -ErrorAction Stop | Sort-Object RecordId | ForEach-Object {
        $message = if ($_.Message) { $_.Message.Substring(0, [Math]::Min(350, $_.Message.Length)) } else { '' }
        @{ event_id = [int]$_.Id; record_id = [long]$_.RecordId
           time_created = if ($_.TimeCreated) { $_.TimeCreated.ToUniversalTime().ToString('o') } else { $null }
           message = $message }
    })
} catch { $errors.Add('Defender Operational log unavailable or unreadable') }
ConvertTo-Json -InputObject @{
    established = @($established); listeners = @($listeners)
    firewall_profiles = @($profiles); defender_events = @($defender)
    errors = @($errors.ToArray())
} -Depth 7 -Compress
"""


def collect_windows_host_snapshot(*, max_connections: int = 500,
                                  max_defender_events: int = 50,
                                  timeout_seconds: int = 30) -> dict[str, Any]:
    """Collect bounded local TCP/process/firewall/Defender metadata on Windows."""
    limits = (("max_connections", max_connections, 1, _MAX_CONNECTIONS),
              ("max_defender_events", max_defender_events, 1, _MAX_DEFENDER_EVENTS),
              ("timeout_seconds", timeout_seconds, 1, 120))
    for name, value, low, high in limits:
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise ValueError(f"{name} must be an integer between {low} and {high}")
    if platform.system() != "Windows":
        raise OSError("Windows host telemetry is available only on Windows")
    request = json.dumps({"max_connections": max_connections,
                          "max_defender_events": max_defender_events})
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
        raise TimeoutError("Windows host telemetry collection timed out") from exc
    if completed.returncode != 0:
        detail = (completed.stderr or "PowerShell returned an error").strip()[:500]
        raise RuntimeError(f"Windows host telemetry failed: {detail}")
    try:
        payload = json.loads(completed.stdout.strip() or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError("PowerShell returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise RuntimeError("PowerShell returned an invalid snapshot shape")
    return {
        "schema_version": "1.0", "source": "windows_host_snapshot",
        "established": payload.get("established", []) if isinstance(payload.get("established"), list) else [],
        "listeners": payload.get("listeners", []) if isinstance(payload.get("listeners"), list) else [],
        "firewall_profiles": payload.get("firewall_profiles", []) if isinstance(payload.get("firewall_profiles"), list) else [],
        "defender_events": payload.get("defender_events", []) if isinstance(payload.get("defender_events"), list) else [],
        "collection_errors": payload.get("errors", []) if isinstance(payload.get("errors"), list) else [],
        "read_only": True,
        "limits": {"max_connections_per_state": max_connections,
                   "max_defender_events": max_defender_events},
        "limitations": [
            "Process paths, signatures, hashes, firewall state, and event logs may be unavailable without sufficient permissions.",
            "SHA-256 is skipped for files larger than 100 MiB; signatures and hashes are metadata, not malware verdicts.",
            "Only current TCP state, firewall profiles, and Defender events 1116/1117 are sampled.",
            "No network scan, upload, persistence, or response action is performed.",
        ],
    }


def _risk(process: dict[str, Any], remote_port: int, fanout: int) -> tuple[int, list[str]]:
    score, evidence = 10, []
    name = str(process.get("name") or "").casefold()
    path = str(process.get("path") or "").replace("/", "\\").casefold()
    if name in {"powershell", "pwsh", "wscript", "cscript", "mshta", "rundll32", "regsvr32"}:
        score += 25; evidence.append("script-or-system-tool")
    if any(part in path for part in ("\\appdata\\", "\\temp\\", "\\downloads\\")):
        score += 20; evidence.append("user-writable-location")
    if process.get("signature") == "NotSigned":
        score += 15; evidence.append("unsigned-binary")
    if process.get("signature") == "HashMismatch":
        score += 40; evidence.append("signature-hash-mismatch")
    if fanout >= 20:
        score += 20; evidence.append("high-connection-fanout")
    if remote_port in (23, 2323):
        score += 10; evidence.append("unusual-remote-port")
    return min(100, score), evidence


def analyze_host_snapshot(snapshot: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert a collected snapshot into V6/V7-style explainable findings."""
    if not isinstance(snapshot, dict):
        raise TypeError("snapshot must be a dictionary")
    findings: list[dict[str, Any]] = []
    connections = snapshot.get("established", [])
    if not isinstance(connections, list):
        connections = []
    counts: dict[int, int] = {}
    for item in connections:
        if isinstance(item, dict) and isinstance(item.get("pid"), int):
            counts[item["pid"]] = counts.get(item["pid"], 0) + 1
    def add(rule: str, title: str, severity: str, evidence: str,
            asset: str | None = None, observed_at: str | None = None,
            confidence: float = 0.5) -> None:
        findings.append({"rule_id": rule, "title": title, "severity": severity,
                         "confidence": confidence, "evidence": evidence[:1000],
                         "asset_id": asset, "source": "windows_host_snapshot",
                         "observed_at": observed_at})
    for item in connections:
        if not isinstance(item, dict):
            continue
        process = item.get("process") if isinstance(item.get("process"), dict) else {}
        try: port = int(item.get("remote_port") or 0)
        except (TypeError, ValueError): port = 0
        try: pid_value = int(item.get("pid") or 0)
        except (TypeError, ValueError): pid_value = 0
        score, reasons = _risk(process, port, counts.get(pid_value, 0))
        severity = "high" if score >= 60 else "medium" if score >= 35 else "low" if score >= 20 else "info"
        add("ATLAS-NET-001", "New or observed TCP connection", severity,
            json.dumps({"pid": pid_value, "process": process, "local": item.get("local_address"),
                        "local_port": item.get("local_port"), "remote": item.get("remote_address"),
                        "remote_port": port, "risk_score": score, "risk_evidence": reasons},
                       ensure_ascii=False, sort_keys=True),
            confidence=0.65 if reasons else 0.35)
    listeners = snapshot.get("listeners", [])
    if isinstance(listeners, list):
        for item in listeners:
            if not isinstance(item, dict): continue
            process = item.get("process") if isinstance(item.get("process"), dict) else {}
            score, reasons = _risk(process, 0, 0)
            score = max(25, score)
            severity = "high" if score >= 60 else "medium" if score >= 35 else "low"
            add("ATLAS-NET-002", "TCP listening socket", severity,
                json.dumps({"pid": item.get("pid"), "address": item.get("local_address"),
                            "port": item.get("local_port"), "process": process,
                            "risk_score": score, "risk_evidence": reasons},
                           ensure_ascii=False, sort_keys=True), confidence=0.55)
    profiles = snapshot.get("firewall_profiles", [])
    if isinstance(profiles, list):
        for profile in profiles:
            if not isinstance(profile, dict): continue
            if profile.get("enabled") is False:
                add("ATLAS-FW-001", "Windows Firewall profile disabled", "high",
                    json.dumps(profile, sort_keys=True), confidence=0.8)
    errors = snapshot.get("collection_errors", [])
    if isinstance(errors, list) and any("Firewall" in str(x) for x in errors):
        add("ATLAS-FW-002", "Firewall profile state unavailable", "info",
            "Firewall state could not be read; this is not evidence that the firewall is disabled.",
            confidence=0.2)
    defender = snapshot.get("defender_events", [])
    if isinstance(defender, list):
        for item in defender:
            if not isinstance(item, dict): continue
            event_id = item.get("event_id")
            if event_id == 1116:
                add("ATLAS-DEF-001", "Microsoft Defender detection event", "critical",
                    str(item.get("message") or "Defender event 1116"), observed_at=item.get("time_created"),
                    confidence=0.85)
            elif event_id == 1117:
                add("ATLAS-DEF-002", "Microsoft Defender remediation event", "info",
                    str(item.get("message") or "Defender event 1117"), observed_at=item.get("time_created"),
                    confidence=0.6)
    return findings


def iter_windows_defense_events(*, poll_interval_seconds: int = 8,
                                max_polls: int = 60, max_runtime_seconds: int = 300,
                                max_connections: int = 500, stop_event: Any = None
                                ) -> Iterator[dict[str, Any]]:
    """Yield newly fingerprinted host findings in a bounded foreground loop."""
    from hashlib import sha256
    limits = (("poll_interval_seconds", poll_interval_seconds, 5, 300),
              ("max_polls", max_polls, 1, 10000),
              ("max_runtime_seconds", max_runtime_seconds, 1, 3600))
    for name, value, low, high in limits:
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise ValueError(f"{name} must be an integer between {low} and {high}")
    if stop_event is not None and not callable(getattr(stop_event, "is_set", None)):
        raise ValueError("stop_event must provide an is_set() method")
    if platform.system() != "Windows":
        raise OSError("Windows host monitoring is available only on Windows")
    if stop_event is not None and stop_event.is_set():
        return
    seen: set[str] = set()
    started = time.monotonic()
    previous_connections: set[str] | None = None
    previous_listeners: set[str] | None = None
    previous_firewall: str | None = None
    for poll in range(max_polls):
        if stop_event is not None and stop_event.is_set(): break
        if time.monotonic() - started >= max_runtime_seconds: break
        if poll:
            remaining = max_runtime_seconds - (time.monotonic() - started)
            if remaining <= 0: break
            time.sleep(min(poll_interval_seconds, remaining))
            if stop_event is not None and stop_event.is_set(): break
        snapshot = collect_windows_host_snapshot(max_connections=max_connections)
        def keys(rows: Any) -> set[str]:
            if not isinstance(rows, list): return set()
            return {json.dumps(row, sort_keys=True, ensure_ascii=False) for row in rows if isinstance(row, dict)}
        current_connections = keys(snapshot["established"])
        current_listeners = keys(snapshot["listeners"])
        if previous_connections is None:
            previous_connections, previous_listeners = current_connections, current_listeners
            previous_firewall = json.dumps(snapshot["firewall_profiles"], sort_keys=True)
            continue
        snapshot["established"] = [json.loads(x) for x in sorted(current_connections - previous_connections)]
        snapshot["listeners"] = [json.loads(x) for x in sorted(current_listeners - (previous_listeners or set()))]
        previous_connections, previous_listeners = current_connections, current_listeners
        current_firewall = json.dumps(snapshot["firewall_profiles"], sort_keys=True)
        firewall_available = bool(snapshot["firewall_profiles"]) and not any(
            "Firewall" in str(error) for error in snapshot["collection_errors"]
        )
        firewall_changed = firewall_available and previous_firewall is not None and current_firewall != previous_firewall
        if firewall_available:
            previous_firewall = current_firewall
        if firewall_changed:
            snapshot.setdefault("collection_errors", [])
            snapshot["collection_errors"] = list(snapshot["collection_errors"]) + [
                "Firewall profile state changed since the previous sample: " + current_firewall
            ]
        for finding in analyze_host_snapshot(snapshot):
            if finding.get("rule_id") == "ATLAS-FW-002" and firewall_changed:
                finding["rule_id"] = "ATLAS-FW-003"
                finding["title"] = "Windows Firewall profile state changed"
                finding["severity"] = "medium"
                finding["evidence"] = "Firewall profile state changed since the previous sample: " + current_firewall
            fingerprint = sha256(json.dumps(finding, sort_keys=True, ensure_ascii=False).encode("utf-8")).hexdigest()
            if fingerprint in seen: continue
            seen.add(fingerprint)
            if len(seen) > 5000: seen = set(list(seen)[-2500:])
            yield finding
