# Native BAT + PowerShell Windows Defense

Extract the archive and double-click Start-WindowsDefense-V8.0.5.bat.
Choose 1 for one read-only snapshot, or 2 for foreground monitoring for up
to five minutes. The monitor can be stopped with Ctrl+C.

This native Windows PowerShell 5.1 script reads TCP connections/listeners,
process metadata, firewall profile state, and available Defender Operational
events 1116/1117. It writes logs and JSONL findings beside the script.

It does not change firewall rules, Defender settings, services, or system
configuration; it does not kill processes, delete files, quarantine files,
upload telemetry, or persist in the background. No administrator elevation
is requested. Some process paths or event logs may be unavailable to a
standard user and are reported as warnings. Risk scores are triage hints,
not malware verdicts.

This BAT package provides native read-only monitoring. It does not yet expose
the separate Python firewall-response API.
