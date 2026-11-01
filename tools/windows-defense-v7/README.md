# Windows Defense v0.7

Windows 10 / PowerShell 5.1 monitoring with optional human-approved temporary outbound IP blocks.

## Changes
- Retains v0.6 TCP connection/listener monitoring, process metadata, signature/SHA256 checks, heuristic risk scoring, event deduplication, JSONL records, firewall-profile monitoring and Defender 1116/1117 classification.
- Optional approval workflow for high-risk newly observed outbound TCP connections.
- A response blocks only the observed remote IP in the Outbound direction; it does not terminate the process.
- Every response requires typing BLOCK. Default is MonitorOnly and approval blocks are disabled.
- Temporary rules have a bounded 1-60 minute TTL (default 10), a rule-count cap, persistent state and a response ledger.
- Expiry cleanup and explicit rollback verify exact rule name, marker, group, direction and action.

## Safety
- First run in default MonitorOnly mode and review logs.
- No unattended automatic blocking, process termination, file deletion, registry edits, Defender exclusions or firewall-profile changes.
- Only validated public unicast IPs are eligible; private, loopback, link-local, multicast and special local ranges are rejected.
- Response uses Windows Firewall; it is not independent of Windows Firewall. Blocking a shared public IP may interrupt legitimate services.
- Risk scores are heuristic triage signals, not malware verdicts. This is a learning tool, not an EDR replacement.

## Run
1. Download and extract the windows-defense-v7 branch ZIP.
2. Double-click Start-WindowsDefense-v0.7.bat.
3. Keep MonitorOnly for initial testing. Stop with Ctrl+C.
4. Review logs, data/events.jsonl and data/response-ledger-v0.7.jsonl.

Static test:
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Test-WindowsDefense-v0.7.ps1

One-cycle diagnostic:
    powershell -NoProfile -ExecutionPolicy Bypass -File .\WindowsDefense-v0.7.ps1 -Once

## Optional approval mode
Only after monitor-only testing, set ResponseMode to Approval and EnableApprovalBlocks to true in config.json. Each eligible high-risk event displays the remote IP and impact warning; type BLOCK to approve. Any other input declines. This mode requires an interactive console and may require elevation to create firewall rules.

## Rollback
Preview:
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Undo-WindowsDefense-v0.7.ps1 -WhatIfOnly

Execute:
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Undo-WindowsDefense-v0.7.ps1

Rollback reads the local state file and verifies exact ownership before removal; it does not perform broad firewall cleanup.
