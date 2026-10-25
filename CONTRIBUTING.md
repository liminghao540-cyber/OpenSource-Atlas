# Contributing

Thanks for your interest in OpenSource Atlas.

## Development setup

- Python 3.11 or newer
- Git
- Optional: pytest for the test suite

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
pytest
```

## Contribution principles

1. Keep scoring rules explicit and explainable.
2. Distinguish unavailable data from negative evidence.
3. Never claim that metadata scores prove code quality or security.
4. Add tests for bug fixes and new scoring behavior.
5. Keep runtime dependencies small and document any new dependency.
6. Do not commit tokens, credentials, private repository data, or generated reports containing sensitive information.

## Pull requests

Describe the user-visible behavior, include relevant tests, and note limitations or API assumptions. Small, focused pull requests are easier to review.
