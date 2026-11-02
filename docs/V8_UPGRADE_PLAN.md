# OpenSource Atlas V8.0 — Upgrade Plan

## Direction

Transform OpenSource Atlas from a public-repository metadata intelligence tool into a modular, explainable, approval-gated security operations and defense platform. The existing CLI, GitHub metadata client, scoring model, report renderers, and local dashboard remain available as the project-intelligence foundation.

## V8 architecture

1. **Data connectors** — explicitly configured sources for repository metadata, normalized security events, and later approved telemetry integrations.
2. **Normalization** — validate event shape, timestamps, source labels, and asset identifiers before analysis.
3. **Detection engine** — deterministic, versioned rules with evidence and explicit unavailable-data states.
4. **Risk engine** — correlate findings and asset context without presenting heuristic scores as proof of compromise or safety.
5. **Response planner** — create proposed actions in dry-run mode. No blocking, isolation, deletion, account modification, or network change is performed.
6. **Approval and audit** — future execution integrations must require explicit authorization, least privilege, immutable/auditable records, and rollback procedures where applicable.
7. **Reporting and dashboard** — present findings, evidence, confidence, limitations, response proposals, and historical changes.

## Implemented in the V8 foundation

- Added detection.py, a deterministic event-rule engine for normalized events.
- Added response.py, an approval-gated dry-run response planner.
- Added unit tests for rule matching, invalid timestamps, malformed counters, and the invariant that response plans never execute actions.
- Preserved the existing metadata-only GitHub analysis pipeline.

## Important boundaries

- The initial detector evaluates caller-supplied normalized events only; it is not an endpoint agent, network scanner, SIEM connector, or malware analyzer.
- Detection output is triage evidence, not a definitive incident verdict.
- The response planner does not perform external side effects.
- No credentials or tokens are collected or stored by this foundation.
- Production deployment requires authentication, authorization, rate limiting, secure secret management, threat modeling, and an independent security review.

## Full-upgrade milestones

### V8.0.1 — Foundation and contracts
- Versioned finding and response-plan schemas.
- Expand tests for event validation, deterministic behavior, and compatibility.
- Add bounded retries and actionable API rate-limit handling to GitHub client.

### V8.0.2 — Risk correlation
- Asset inventory model and finding deduplication.
- Severity, confidence, evidence provenance, and suppression expiry.
- Snapshot and change tracking with retention controls.

### V8.0.3 — Connectors and observability
- Opt-in import of structured JSONL events.
- Connector health, ingestion errors, and audit events.
- No privileged host agent by default.

### V8.0.4 — Dashboard and operations
- Findings queue, filters, evidence details, and response-plan review.
- Accessibility and end-to-end browser tests.
- Local-only deployment remains the default.

### V8.1 — Carefully controlled response integrations
- Integrations only for explicitly authorized systems and actions.
- Human approval, least privilege, idempotency, rate limits, audit trail, rollback plan, and dry-run preview are mandatory.
- No autonomous destructive response.

## Acceptance criteria

- Existing CLI and dashboard behavior remains compatible.
- Every detection rule has positive, negative, and boundary tests.
- Unknown or missing data is never silently converted into a clean bill of health.
- Response plans always have execution_enabled=false in the foundation release.
- Reports identify engine/schema versions and preserve evidence provenance.
- CI must pass before merge; live runtime acceptance must be reported separately.
