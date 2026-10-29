# Windows Defense v0.4 — Independent Monitor + Bounded Response

Windows PowerShell 5.1 prototype. Monitoring runs independently of Windows Firewall, but optional temporary inbound IP blocking uses Windows Firewall. Not an EDR product; it cannot guarantee prevention or detection of all attacks.

## Start
1. Extract the ZIP.
2. Open tools/windows-defense-v4.
3. Double-click Start-WindowsDefense-v0.4.bat.
4. Keep the console open; press Ctrl+C to stop.
5. Review logs/ and data/response-ledger.json.

## Included
- Polling monitor for new TCP listeners, including best-effort process name/path.
- Firewall state change alerts, deduplicated until state changes/recovery.
- Reads Defender Operational events 1116/1117 where permitted.
- Simple heuristic risk scores, not an AI verdict.
- Timestamped response ledger.
- Rate-limited Defender quick scan request after Defender threat event 1116.
- Optional temporary inbound blocks for explicitly configured IPs. Disabled by default; requires suitable permissions.
- Only rules with the WindowsDefense-TemporaryBlock- prefix recorded by this tool are considered for expiry cleanup.

## Optional explicit block list
Do not enable unless you understand the effect and have a recovery plan. In config.json:
- Set EnableTemporaryFirewallBlock to true.
- Add only exact, verified IP addresses to ExplicitBlockList.
- TemporaryBlockMinutes must be 1–60.
This creates temporary inbound block rules in Windows Firewall; it does not block outbound connections and is not independent of Windows Firewall. Do not populate the list automatically from unknown IPs.

## Recovery and rollback
- Default configuration makes no firewall changes.
- The tool tracks only its own temporary rules and removes expired owned rules during monitoring and on the next run. Ctrl+C cleans up already-expired rules, not unexpired ones; unexpired rules remain until expiry or can be manually removed by their exact display name.
- To disable future blocking, set EnableTemporaryFirewallBlock to false. This does not remove unexpired rules automatically; check the response ledger and remove only exact rules created by this tool.
- The program does not kill processes, delete files, or edit registry policy.

## Privacy and limitations
Logs may include IPs, ports, process names/paths and Defender event text. Redact before sharing. New listeners and unknown IPs are not proof of malware. Defender event access and process paths may require Administrator. No service/task is installed; this runs in a foreground console and is not yet configured for automatic startup. Not tested on every Windows build or on the user's PC. Inspect code before running and obey device-management policy.

Version 0.4 is a prototype. Risk scores are heuristic. Temporary firewall response is opt-in and uses Windows Firewall.
