 # Windows Defense — Continuous Monitor v0.3

This version runs a continuous foreground monitor. It is not a replacement for Microsoft Defender or Windows Firewall.

## Start
1. Extract the ZIP.
2. Open `tools/windows-defense-v3`.
3. Double-click `Start-WindowsDefense-v0.3.bat`.
4. Keep the console open. Press Ctrl+C to stop.
5. Review `logs/WindowsDefense-Monitor-*.log`.

## Monitoring and response
- Polls TCP listeners every 10 seconds by default and logs newly observed listeners.
- Watches Windows Firewall profile state and warns if a profile is disabled or cannot be confirmed.
- Checks Windows Defender Operational events 1116/1117 and logs threat/action events when accessible.
- When a Defender threat-detection event (1116) is observed, it attempts a Defender quick scan by default. This can be disabled in `config.json` by setting `AutoQuickScanOnThreat` to `false`.
- It does not automatically block IPs, kill processes, delete/quarantine files, change firewall settings, or alter registry/policy. Those actions can disrupt legitimate software and are deliberately not automatic in this version.

## Configuration
- `PollSeconds`: 5 to 60 seconds.
- `AutoQuickScanOnThreat`: true/false.
- `ShowConsoleAlerts`: true/false.

## Limitations and safety
- Keep Microsoft Defender real-time protection and Windows Firewall enabled. This monitor does not prevent attacks by itself.
- Some event logs and process details may require running PowerShell as Administrator.
- New TCP listener does not mean malicious; review the process path and expected application.
- Logs may contain machine details and Defender event text. Review/redact before sharing.
- This script has not been tested on the user's machine. Test in a normal console first. The launcher uses ExecutionPolicy Bypass for that PowerShell process only; inspect the script and obey device-management policy.
- This version is a monitoring prototype, not a validated EDR product. It does not guarantee real-time detection; polling interval and Windows event logging limit coverage.
