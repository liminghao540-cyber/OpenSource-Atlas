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
