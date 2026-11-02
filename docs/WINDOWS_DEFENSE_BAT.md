# Windows Defense BAT launcher

Use \`Start-WindowsDefense-V8.0.5.bat\` from the extracted project root.

Requirements:
- Windows 10
- Python 3.11 or newer installed from python.org, with the Python Launcher (\`py\`) or \`python\` on PATH
- Standard Python Tkinter component

The BAT launcher sets \`PYTHONPATH\` to the bundled \`src\` directory and starts
the desktop UI in the foreground. It does not install packages, elevate, alter
firewall settings, or enable monitoring automatically. The console remains open
so Python/PowerShell diagnostic output can be read. If startup fails, retain the
full console text for troubleshooting.

Use the one-shot snapshot first. Do not run as Administrator for initial
read-only validation. Firewall response is separate, requires explicit approval
inside the application, and may disrupt all outbound connections to the target IP.

This source bundle is not a standalone EXE; Python must be installed.
