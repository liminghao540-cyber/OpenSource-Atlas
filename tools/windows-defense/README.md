# Windows Defense — Safe Audit

A zero-cost, read-only Windows 10 security-audit prototype. It uses built-in Windows PowerShell and Windows management commands; no Python, third-party package, GPU, or network access is required.

## Start
1. Download the repository ZIP from GitHub and extract it.
2. Open tools\windows-defense.
3. Double-click Start-WindowsDefense.bat.
4. Read the console summary and open the generated text report in reports\.

The launcher uses ExecutionPolicy Bypass only for the child PowerShell process; it does not change the machine's execution-policy setting. Review the script before running it. If your organization manages PowerShell execution policy, do not bypass that policy—ask the administrator.

## What it checks
- Windows edition/build and last boot time.
- Microsoft Defender status, where Defender cmdlets are available.
- Windows Firewall profile status.
- A local snapshot of listening TCP endpoints and established TCP connections.
- Startup-command inventory.
- A short list of recent hotfixes, as an informational signal only.
- Text and JSON reports for later review.

## Safety model
- Read-only in v0.1: it does not disable protections, block traffic, kill processes, delete files, edit the registry, or change system settings.
- It does not scan other devices or send data to a server.
- It does not upload logs or call an AI service.
- A port, process, startup item, or remote connection is not automatically malicious.
- UNKNOWN means a check could not be completed, not that the device is infected.

## Current limitations
This is a local audit helper, not an antivirus, EDR, firewall replacement, or guarantee of safety. The rule-based guidance is intentionally conservative. The first version does not include live background monitoring, automatic blocking, or AI-based analysis.

## Requirements
- Windows 10
- Windows PowerShell 5.1 (included with Windows 10)
- No external dependencies

## Test plan
- Run on a test or personal Windows 10 machine first.
- Confirm timestamped TXT and JSON reports appear under reports\.
- Compare Defender and firewall items with the Windows Security app.
- Run without elevation first. Do not elevate unless needed.
- Review reports before sharing; they may contain usernames, process names, IP addresses, ports, startup commands, and device details.

## Roadmap
1. Add automated parser/unit tests using mocked command output.
2. Add a reviewable GUI and clear severity explanations.
3. Add optional local AI analysis of a user-selected report, disabled by default and with sensitive-field redaction.
4. Add carefully scoped remediation actions only after confirmation and with rollback support.
