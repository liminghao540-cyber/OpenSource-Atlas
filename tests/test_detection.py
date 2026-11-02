from opensource_atlas.detection import analyze_event


def test_repeated_authentication_failures_are_detected():
    result = analyze_event({"event_type": "authentication", "failed_attempts": 10})
    assert result["severity"] == "high"
    assert result["findings"][0]["rule_id"] == "ATLAS-AUTH-001"


def test_known_high_risk_event_type_is_detected():
    result = analyze_event({"event_type": "ransomware_indicator"})
    assert result["severity"] == "critical"
    assert result["disposition"] == "review_required"


def test_unmatched_event_is_not_claimed_safe():
    result = analyze_event({"event_type": "routine"})
    assert result["severity"] == "info"
    assert result["disposition"] == "no_rule_matched"
    assert any("does not establish" in item for item in result["limitations"])


def test_invalid_timestamp_is_reported_as_unavailable():
    result = analyze_event({"event_type": "routine", "observed_at": "not-a-date"})
    assert result["observed_at"] is None


def test_boolean_is_not_counted_as_failed_attempts():
    result = analyze_event({"event_type": "authentication", "failed_attempts": True})
    assert result["severity"] == "info"
