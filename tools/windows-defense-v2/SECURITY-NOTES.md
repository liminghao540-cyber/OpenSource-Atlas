 # Security notes for v0.2

- Local read-only inventory and rule-based triage only.
- Does not bypass endpoint management, group policy, antivirus or access controls.
- Review reports for private information before sharing.
- Launcher bypasses execution policy only for its child PowerShell process; inspect the script first.
- No dynamic blocking or remediation is implemented.
