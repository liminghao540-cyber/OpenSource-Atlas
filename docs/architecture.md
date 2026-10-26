# Architecture

## Data flow

```text
CLI input
  -> repository identifier normalization
  -> GitHub REST API (public repository metadata)
  -> transparent scoring components
  -> report model
  -> Markdown or JSON renderer
  -> stdout or output file
```

## Modules

- `github.py`: validates identifiers and fetches metadata from GitHub. Network failures, rate limits, and inaccessible repositories produce explicit errors.
- `scoring.py`: applies documented metadata heuristics and returns component-level evidence. Missing maintenance data is excluded from the available denominator rather than treated as a zero.
- `report.py`: assembles a versioned report structure and renders Markdown or JSON.
- `cli.py`: parses user input and connects the modules.

## Design constraints

- Python 3.11+, standard-library runtime only.
- No repository source code is downloaded or executed.
- No credentials are requested or stored.
- Scores are heuristic triage signals, not proof of quality or security.
- The public unauthenticated GitHub API has rate limits.

## Future extension points

An authenticated client can later be introduced behind the same metadata interface. Historical snapshots should store timestamped observations separately from current repository metadata. A web dashboard should call the same scoring/report layer rather than reimplementing scoring rules.


## Local web dashboard

The optional `atlas-web` command starts a dependency-free local dashboard on `127.0.0.1:8765`. It reuses the same `github.py`, `scoring.py`, and `report.py` modules as the CLI rather than maintaining a separate scoring implementation.

- `web.py`: local HTTP server, single-page dashboard, JSON inspection endpoint, and Markdown export endpoint.
- `POST /api/inspect`: accepts a repository identifier and returns the versioned report JSON.
- `POST /api/markdown`: renders a supplied report object as Markdown.
- The server refuses non-loopback host bindings. It does not accept or store credentials.
- The dashboard calls GitHub's public API through the existing client; public API rate limits still apply.

This is an initial local dashboard, not a hosted service. It should be reviewed and tested before any public deployment. For internet-facing deployment, add a production server, request throttling, stricter input and report schema validation, and deployment-specific security review first.
