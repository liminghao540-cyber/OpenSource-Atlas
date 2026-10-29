 # Windows Defense — Safe Audit v0.2

A small, read-only Windows 10 audit helper. It is not antivirus software and cannot guarantee system safety.

## Run
1. Download and extract the ZIP.
2. Open `tools/windows-defense-v2`.
3. Double-click `Start-WindowsDefense-v0.2.bat`.
4. Reports are written to the `reports` folder as TXT and JSON.

## Checks
- Windows version/build.
- Firewall profiles, default inbound/outbound actions, firewall service and policy registry values.
- Defender status when available; otherwise marks it unconfirmed.
- TCP listeners and established TCP connections, with best-effort process names/paths.
- Common Run registry keys, Startup folders and ten recent hotfixes.

## Safety and limits
- Read-only: no registry writes, firewall changes, process termination, file deletion, blocking, remote scanning or cloud/AI calls.
- A listener or unknown IP is not proof of malicious activity.
- Reports may contain usernames, paths, local/remote IPs, ports and process names. Review and redact before sharing.
- Not validated on every Windows build; confirm important findings independently.
- The launcher uses `-ExecutionPolicy Bypass` only for the launched PowerShell process. Inspect the script first and do not use it if prohibited by an administrator.
- If firewall policy values say `EnableFirewall=0` while Local Group Policy Editor says Not Configured, inspect `gpresult` and management/security software. Do not blindly delete policy keys.

Version 0.2 does not include automatic remediation, continuous monitoring or actual AI analysis.
