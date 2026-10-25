# Testing

## GitHub Actions

Every push to `main` and every pull request targeting `main` triggers the test workflow.

The workflow tests Python 3.11, 3.12, and 3.13 on GitHub-hosted Ubuntu runners. It installs the package with its development extra and runs `pytest`.

Check the latest result at:

https://github.com/liminghao540-cyber/OpenSource-Atlas/actions/workflows/tests.yml

## Local test command

```bash
python -m pip install -e ".[dev]"
pytest
```

A workflow file in the repository is not itself proof that a run passed. Confirm a completed green run before treating the tests as verified.
