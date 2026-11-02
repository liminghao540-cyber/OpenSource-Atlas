# Windows 10 standalone EXE

This build packages OpenSource Atlas V8.0.1 into a single Windows x64 executable using PyInstaller.

## Build output

`OpenSourceAtlas.exe` is built on GitHub Actions using Windows runners. The executable includes the Python runtime and project package; users do not need to install Python separately. See the [PyInstaller documentation](https://pyinstaller.org/en/latest/operating-mode.html).

## Run

1. Download the `OpenSourceAtlas-Windows-10-x64` artifact ZIP from the successful **Windows EXE** workflow run.
2. Extract the ZIP.
3. Double-click `OpenSourceAtlas.exe`.
4. Keep the console window open. The launcher opens the local dashboard at http://127.0.0.1:8765.

The dashboard binds to localhost only. Closing the console window stops the local server.

## Notes

- This is a personal Windows x64 build, not a signed installer.
- Windows SmartScreen or antivirus may show a warning for an unsigned, newly built executable.
- Do not expose the local dashboard to a public network.
- Security event ingestion remains a caller-supplied JSONL parsing API; response plans remain dry-run and approval-gated. This EXE does not add endpoint monitoring or automatic remediation.
