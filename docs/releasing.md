# Release Process

A version is not considered released until its matching Git tag and GitHub Release exist. The package workflow builds artifacts but does not publish to PyPI or create a GitHub Release.

## V8.0.1 release checklist

1. Merge the release-preparation changes into `main`.
2. Confirm `pyproject.toml` and `opensource_atlas.__version__` both report `8.0.1`.
3. Confirm the test workflow passes on Python 3.11, 3.12, and 3.13 for the exact main commit.
4. Run the package workflow for tag `v8.0.1`.
5. Download and inspect the wheel and source distribution; verify metadata with `twine check`.
6. Run the manual installation and runtime checks in [V8.0.1 installation guide](V8.0.1_INSTALL.md).
7. Review the changelog and safety limitations.
8. Only after explicit release approval, create Git tag `v8.0.1` and publish the GitHub Release with the verified artifacts.

## Local build

```bash
python -m pip install --upgrade build twine
python -m build
python -m twine check dist/*
```

## Automated package workflow

The `Package` workflow runs on a `v*` tag or manual dispatch. It builds a wheel and source distribution, validates metadata with `twine check`, and uploads the files as a 14-day workflow artifact. It does not publish to PyPI or create a GitHub Release automatically.

## Versioning

Use a `vX.Y.Z` Git tag only when the package metadata version is exactly `X.Y.Z`. Never label an unverified candidate as a stable release.
