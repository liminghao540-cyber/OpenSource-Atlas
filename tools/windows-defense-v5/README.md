# Windows Defense v0.5 — Monitored, Audited, Reversible

Windows PowerShell 5.1 prototype for Windows 10. It monitors TCP listeners, established TCP connections, firewall profile state, and (when readable) Microsoft Defender Operational events. It records process paths, Authenticode signature status, and SHA-256 hashes for newly observed listener processes.

This is a defensive monitoring utility, **not** an antivirus, EDR, or guarantee of attack prevention. Heuristic risk scores are triage hints, not malware verdicts.

## Safety defaults

- `ResponseMode` defaults to `MonitorOnly`; the monitor makes no firewall changes.
- Automatic temporary firewall rules are separately disabled by default.
- The tool never kills processes, deletes files, changes registry policy, disables Windows Firewall, or edits Defender exclusions.
- No IP is blocked merely because it is unknown or appears in a connection.
- Temporary rules are limited to an explicit, manually reviewed `ApprovedBlockList`, have a 1–60 minute TTL, and use a unique v0.5 rule-name prefix.
- A temporary rule must match both the dedicated display-name prefix and an exact ownership description marker before cleanup or rollback. The tool removes by exact internal firewall rule name, not by a broad display-name wildcard.

## Start

1. Extract the repository ZIP.
2. Open `tools/windows-defense-v5`.
3. Double-click `Start-WindowsDefense-v0.5.bat`.
4. Keep the console open; press Ctrl+C to stop.
5. Review `logs/` and `data/response-ledger.json`.

Run PowerShell as Administrator only if you need access to protected event data or approved firewall actions. Monitoring may still work without elevation.

## Response modes

- `MonitorOnly` (default): log and score observations only.
- `Approval`: when approved temporary blocks are enabled, ask for interactive confirmation before each configured IP block.
- `Auto`: apply only the exact IPs manually entered in `ApprovedBlockList`, and only when `EnableApprovedTemporaryBlocks` is true. This is not automatic threat-intelligence blocking.

To use a block list, verify every address independently, set the response mode deliberately, enable the feature, and keep the TTL short. Blocking affects inbound traffic through **Windows Firewall**; monitoring itself does not depend on Windows Firewall.

## Recovery

- Set `EnableApprovedTemporaryBlocks` to `false` to prevent new rules.
- The monitor removes its own expired rules while running and on the next start.
- To immediately remove all remaining v0.5-owned rules, open an elevated PowerShell in this folder and run:
  `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Remove-WindowsDefense-Rules.ps1`
- Review the displayed exact rule names before confirming. To skip confirmation, use `-Force` only when you have verified the listed rules.

The rollback script does not remove rules from Windows Firewall generally; it targets only the v0.5 prefix.

## Data and privacy

Logs may contain local/remote IP addresses, ports, process paths, file hashes, signature status, and Defender event text. Treat them as sensitive and redact before sharing. Data is stored locally in this folder. No cloud service, telemetry upload, or credentials are used.

## Limitations

- Polling can miss very short-lived connections.
- Process path and signature information may be unavailable due to permissions or process exit.
- Authenticode status and hashes are evidence, not proof of safety or maliciousness.
- Defender event access depends on Windows configuration and permissions.
- Temporary block rules require Windows Firewall cmdlets and suitable permissions.
- The project has not been validated on every Windows 10 build or on the user's PC. Review the code and run the self-test before enabling any response.

## Self-test

Run:
`powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-WindowsDefense-v0.5.ps1`

The self-test checks PowerShell syntax, JSON validity, and critical safe-default settings. It does not simulate real attacks or prove runtime protection.
