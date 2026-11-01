# Windows Defense v0.6

Correlated, deduplicated, **monitor-only** Windows network and process telemetry for Windows 10 / Windows PowerShell 5.1.

## What's new
- Correlates TCP connection/listener records with process name, executable path, Authenticode status, and SHA-256.
- Adds heuristic risk evidence for script-capable tools, user-writable executable locations, unsigned binaries, high per-process connection fan-out, and selected unusual remote ports.
- Deduplicates event records with SHA-256 fingerprints and persists a bounded set of seen keys.
- Writes structured JSON Lines to `data/events.jsonl`, state to `data/state-v0.6.json`, and readable logs to `logs/`.
- Monitors Windows Firewall profile state and Microsoft Defender Operational events 1116/1117 where available.

## Safety
- Default and only response mode in this release: **MONITOR ONLY**.
- Does not create/remove firewall rules, stop processes, delete files, change registry, disable firewall, or alter Defender settings.
- Run without elevation first. Some process paths and event logs may be unavailable without permissions; this is recorded as limited visibility, not treated as proof of compromise.
- Risk scores are heuristic triage signals, not malware verdicts. A valid signature is not a guarantee of safety; unsigned software is not automatically malicious.
- This is a learning/monitoring tool, not an EDR replacement or a guarantee of prevention.

## Run
1. Extract the repository branch ZIP.
2. Open this folder.
3. Double-click `Start-WindowsDefense-v0.6.bat`.
4. Stop with Ctrl+C.
5. Review `logs/` and `data/events.jsonl`.

Run static tests in Windows PowerShell 5.1:
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Test-WindowsDefense-v0.6.ps1
```

Optional one-cycle diagnostic (does not keep polling):
```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\WindowsDefense-v0.6.ps1 -Once
```

## Configuration
Only bounded polling, alert thresholds, and monitor toggles are configurable. Do not interpret thresholds as calibrated probabilities.
