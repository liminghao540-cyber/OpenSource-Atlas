# Testing and Runtime Acceptance

## Automated tests

Every push to `main` and every pull request targeting `main` triggers the test workflow.

The workflow tests Python 3.11, 3.12, and 3.13 on GitHub-hosted Ubuntu runners. It installs the package with its development extra and runs `pytest`.

Check the latest result at:

https://github.com/liminghao540-cyber/OpenSource-Atlas/actions/workflows/tests.yml

## Local automated test command

From the repository root:

```bash
python -m pip install -e ".[dev]"
python -m pytest
```

A workflow file in the repository is not itself proof that a run passed. Confirm a completed green run before treating the tests as verified.

## Local web dashboard acceptance

After installing the package in the virtual environment, run:

Windows PowerShell:
```powershell
.\.venv\Scripts\atlas-web.exe
```

macOS/Linux:
```bash
atlas-web
```

Open `http://127.0.0.1:8765`, inspect a public repository such as `pallets/flask`, and verify that the overview, score components, evidence, JSON export, and Markdown export are available. Stop the server with Ctrl+C. The server intentionally binds only to localhost.

## Manual runtime acceptance

Automated tests use mocked GitHub responses in many cases. Before calling a local installation verified, run these checks on a computer with Python 3.11 or newer and internet access.

### 1. Install in an isolated environment

Windows PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e .
```

macOS/Linux:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

If Python 3.11 is not installed on Windows, replace `-3.11` with an installed supported Python version.

### 2. Inspect a known public repository

Windows PowerShell:

```powershell
.\.venv\Scripts\atlas.exe inspect pallets/flask
```

macOS/Linux (with the environment activated):

```bash
atlas inspect pallets/flask
```

Expected: the command exits successfully and prints a Markdown report with the repository name, health indicator, score breakdown, notes, and limitations.

### 3. Verify JSON output

Windows PowerShell:

```powershell
.\.venv\Scripts\atlas.exe inspect pallets/flask --format json --output acceptance-report.json
.\.venv\Scripts\python.exe -m json.tool acceptance-report.json
```

macOS/Linux:

```bash
atlas inspect pallets/flask --format json --output acceptance-report.json
python -m json.tool acceptance-report.json
```

Expected: the tool reports that the file was written, and `json.tool` parses it without an error. The generated file is a local test artifact; do not commit it unless intentionally needed.

### 4. Verify invalid input handling

```text
atlas inspect not-a-repository
```

Expected: a concise error message and exit code `2`, without a Python traceback. In PowerShell, use `$LASTEXITCODE` to inspect the exit code; in macOS/Linux, use `echo $?` immediately after the command.

### Acceptance checklist

- [ ] Package installs in a clean virtual environment.
- [ ] Live public-repository request succeeds.
- [ ] Markdown report renders to standard output.
- [ ] JSON report is written and parses successfully.
- [ ] Invalid repository input exits cleanly.
- [ ] Local dashboard starts on loopback and exports JSON/Markdown.
- [ ] Latest GitHub Actions run for the exact commit is completed and successful.

Until these manual checks have been run on the target computer, report the state as **automated tests passing; local runtime acceptance pending**.
