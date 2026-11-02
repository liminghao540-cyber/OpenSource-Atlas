# V8.0.3 JSONL ingestion contract

The first connector boundary is an explicit, local-text JSONL parser. Callers
supply the content; the parser does not open files, make network requests,
collect host telemetry, or execute response actions.

Example:

    from opensource_atlas.events import ingest_jsonl

    batch = ingest_jsonl(jsonl_text)
    # batch["events"] can be passed to detection.analyze_event
    # batch["errors"] reports rejected rows with their 1-based line numbers.

Contract:
- Each non-empty line must be a JSON object with a non-empty string event_type.
  Event types are trimmed, lowercased, and capped at 80 characters.
- Default limits are 64 KiB per line and 10,000 accepted events per batch.
- Invalid JSON, non-object rows, missing event types, and over-limit rows are
  skipped and reported. A malformed row does not discard valid neighboring rows.
- Non-standard JSON constants such as NaN and Infinity are rejected.
- The result includes schema version, accepted events, line-specific errors,
  and accepted/rejected counts. It does not claim that input sources are trusted.

This is a parser contract, not a production connector: durable storage, source
authentication, replay protection, retention, and operational health reporting
remain future work.
