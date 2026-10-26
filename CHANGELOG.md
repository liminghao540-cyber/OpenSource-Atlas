# Changelog

All notable changes to OpenSource Atlas are documented here.

This project follows a lightweight Keep a Changelog structure. Versions are not considered released until a corresponding Git tag or GitHub Release exists.

## [Unreleased]

### Added
- Initial local web dashboard using the existing report/scoring pipeline, with JSON and Markdown export.
- Local-only dashboard server entry point (`atlas-web`) and dashboard integration tests.

### Previously added
- Initial project changelog and release-note conventions.
- Engineering roadmap covering reliability, richer repository signals, and the future dashboard.

### Current baseline
- Public GitHub repository metadata inspection.
- Explainable heuristic scoring with component-level evidence.
- Markdown and JSON report output.
- Automated test workflow targeting Python 3.11, 3.12, and 3.13.

### Known limitations
- No source-code or dependency vulnerability analysis.
- No historical trend store or web dashboard yet.
- Public unauthenticated GitHub API rate limits apply.
- Repository health scores are triage heuristics, not objective quality or security guarantees.
