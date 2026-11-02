# Windows Defense desktop executable

The dedicated GUI is built by the **Windows Defense EXE** workflow and is
separate from the repository-intelligence dashboard executable.

## Build

On GitHub, open Actions → Windows Defense EXE → Run workflow, or create a PR
touching the launcher/workflow/package source. Download the artifact named
\`OpenSourceAtlas-Defense-Windows-10-x64\`.

## Use

Run \`OpenSourceAtlasDefense.exe\` on Windows 10. The app starts in read-only
mode and does not collect telemetry until the user presses a monitoring button.
The one-shot snapshot is bounded. Foreground monitoring is limited to 60 polls
or five minutes and can be stopped from the UI.

Firewall response is a separate high-impact operation. It requires a valid
public global-unicast IP, an explicit confirmation dialog, the exact approval
word \`BLOCK\`, and an elevated Windows context. It blocks that IP for all
outbound traffic and may interrupt legitimate services. Do not block gateways,
DNS resolvers, school/work network infrastructure, or services you rely on.
Rollback previews first and removes only rules whose ownership metadata matches.

The application stores its response state and ledger under a \`data\` directory
beside the executable. Keep these files; deleting them prevents safe ownership
verification and rollback.

CI validates packaging and Python compilation. It does **not** validate live
Windows Event Log or Windows Firewall behavior. Perform read-only validation
first. This is a learning/triage tool, not a certified EDR.
