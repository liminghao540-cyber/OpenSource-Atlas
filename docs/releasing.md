# Release Process

OpenSource Atlas is still in early development. Do not publish a version tag until the changelog, tests, and package metadata have been reviewed.

## Pre-release checklist

1. Review the changes and update `CHANGELOG.md`.
2. Confirm `pyproject.toml` version and Python requirement are correct.
3. Run tests locally:

   ```bash
   python -m pip install -e ".[dev]"
   python -m pytest
   ```

4. Confirm the latest test workflow is green for the commit being released.
5. Build and inspect a local distribution if possible:

   ```bash
   python -m pip install --upgrade build twine
   python -m build
   python -m twine check dist/*
   ```

## Automated package workflow

The `Package` workflow runs on a `v*` tag or manual dispatch. It builds a wheel and source distribution, validates metadata with `twine check`, and uploads the files as a short-lived workflow artifact.

The workflow does **not** publish to PyPI and does **not** create a GitHub Release automatically. Review the artifacts and publish only after an explicit release decision.

## Versioning

Use tags such as `v0.1.0` only when the version in `pyproject.toml` matches. Do not describe a tag as a stable release unless the project has intentionally declared that stability level.
