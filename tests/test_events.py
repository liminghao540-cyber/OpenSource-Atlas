import json

import pytest

from opensource_atlas.events import ingest_jsonl


def test_ingests_valid_events_and_normalizes_event_type():
    result = ingest_jsonl(
        '{"event_type":" RANSOMWARE_INDICATOR ","asset":"host-1"}\n'
        '{"event_type":"authentication","failed_attempts":4}\n'
    )
    assert result["accepted"] == 2
    assert result["rejected"] == 0
    assert result["events"][0]["event_type"] == "ransomware_indicator"
    assert result["events"][1]["failed_attempts"] == 4
    assert result["schema_version"] == "1.0"


def test_skips_bad_rows_and_reports_original_line_numbers():
    result = ingest_jsonl(
        '{"event_type":"valid"}\n'
        'not-json\n'
        '[]\n'
        '{"asset":"missing-type"}\n'
    )
    assert result["accepted"] == 1
    assert [item["line"] for item in result["errors"]] == [2, 3, 4]


def test_rejects_non_standard_json_constants():
    result = ingest_jsonl('{"event_type":"x","value":NaN}')
    assert result["accepted"] == 0
    assert result["errors"][0]["error"] == "invalid JSON"


def test_enforces_line_and_event_limits():
    result = ingest_jsonl(
        '{"event_type":"first"}\n{"event_type":"second"}\n',
        max_line_bytes=20,
        max_events=1,
    )
    assert result["accepted"] == 1
    assert result["errors"] == [{"line": 2, "error": "event limit exceeded"}]


@pytest.mark.parametrize("kwargs", [
    {"max_line_bytes": 0},
    {"max_events": 0},
    {"max_events": True},
])
def test_rejects_invalid_limits(kwargs):
    with pytest.raises(ValueError):
        ingest_jsonl('{"event_type":"x"}', **kwargs)


def test_rejects_non_string_content():
    with pytest.raises(TypeError):
        ingest_jsonl(None)


def test_preserves_unicode_and_extra_event_fields():
    event = {"event_type": "custom", "asset": "服务器-一", "labels": ["生产"]}
    result = ingest_jsonl(json.dumps(event, ensure_ascii=False))
    assert result["events"] == [event]
