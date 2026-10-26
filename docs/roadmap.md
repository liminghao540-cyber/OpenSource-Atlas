# Product Roadmap

OpenSource Atlas prioritizes trustworthy evidence and a reproducible local workflow over flashy but unverified claims. Roadmap items are plans, not implemented features.

## Stage 1 — Reliable CLI foundation

- [x] Inspect public GitHub repository metadata.
- [x] Explain score components and show evidence.
- [x] Export Markdown and JSON reports.
- [x] Automated tests for CLI, GitHub API handling, scoring, and reports.
- [x] CI matrix for Python 3.11, 3.12, and 3.13.
- [ ] Add report schema validation and explicit schema compatibility tests.
- [ ] Improve retry/backoff and actionable messaging for rate limits and transient network failures.

**Acceptance:** deterministic tests cover success, malformed input, API errors, missing metadata, and output-write failures.

## Stage 2 — Better analysis, without overclaiming

- [ ] Add optional authenticated GitHub API access without storing tokens in config files or logs.
- [ ] Add repository activity signals such as release recency and contributor activity where API data is available.
- [ ] Document every signal's source, weight, missing-data behavior, and known bias.
- [ ] Add a score-model version to reports so scores can be compared responsibly across releases.

**Acceptance:** each new signal has tests, source documentation, and a clear unavailable-data state. No feature should infer security or code quality from stars alone.

## Stage 3 — Historical snapshots

- [ ] Save opt-in timestamped snapshots locally.
- [ ] Compare two snapshots and report changes in metadata and score components.
- [ ] Define retention and privacy behavior before adding any hosted storage.

**Acceptance:** snapshot format is versioned, malformed snapshots fail safely, and historical comparisons never silently mix score-model versions.

## Stage 4 — Web dashboard

- [ ] Build a thin dashboard on top of the existing analysis/report layer.
- [ ] Show repository overview, score breakdown, evidence, and limitations.
- [ ] Support accessible keyboard navigation and responsive layouts.
- [ ] Keep API failures and rate limits visible to the user.

**Acceptance:** dashboard results agree with CLI reports for the same fixture; no fabricated repository data or success states.

## Non-goals for the early release

- Claiming that a metadata score proves a repository is secure.
- Publishing fabricated stars, users, downloads, test results, or benchmark numbers.
- Downloading or executing analyzed repository source code.
- Requiring users to paste credentials into command-line arguments or reports.

## How to contribute

Pick a small item, open an issue describing the intended behavior and acceptance criteria, and submit tests with the implementation. See [CONTRIBUTING.md](../CONTRIBUTING.md).
