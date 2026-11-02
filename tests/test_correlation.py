from opensource_atlas.correlation import correlate_findings


def sample(**extra):
    item = {"rule_id": "ATLAS-001", "title": "Suspicious activity",
            "asset_id": "host-1", "severity": "medium", "confidence": 0.6,
            "evidence": "Three failed logins", "source": "auth-log",
            "observed_at": "2026-11-01T10:00:00Z"}
    item.update(extra)
    return item


def test_deduplicates_and_preserves_provenance_and_asset_context():
    result = correlate_findings(
        [sample(), sample(source="edr", severity="high", confidence=0.9,
                          observed_at="2026-11-01T11:00:00Z")],
        assets=[{"asset_id": "host-1", "hostname": "workstation-1"}],
        now="2026-11-02T00:00:00Z")
    item = result["findings"][0]
    assert result["correlated_count"] == 1
    assert item["occurrences"] == 2 and item["severity"] == "high"
    assert item["confidence"] == 0.9 and len(item["provenance"]) == 2
    assert item["asset"]["hostname"] == "workstation-1"


def test_suppression_must_have_future_expiry():
    finding = sample()
    fp = correlate_findings([finding], now="2026-11-02T00:00:00Z")["findings"][0]["fingerprint"]
    result = correlate_findings([finding],
        suppressions=[{"fingerprint": fp, "expires_at": "2026-11-03T00:00:00Z"}],
        now="2026-11-02T00:00:00Z")
    assert result["findings"][0]["suppressed"] is True


def test_expired_suppression_is_ignored():
    finding = sample()
    fp = correlate_findings([finding], now="2026-11-02T00:00:00Z")["findings"][0]["fingerprint"]
    result = correlate_findings([finding],
        suppressions=[{"fingerprint": fp, "expires_at": "2026-11-01T00:00:00Z"}],
        now="2026-11-02T00:00:00Z")
    assert result["findings"][0]["suppressed"] is False


def test_invalid_rows_are_reported_and_distinct_evidence_is_not_merged():
    result = correlate_findings([sample(severity="urgent"), sample(evidence="Other"),
                                 "bad row"], now="2026-11-02T00:00:00Z")
    assert result["correlated_count"] == 1
    assert result["errors"] == [{"index": 0, "error": "invalid severity"},
                                {"index": 2, "error": "finding must be a dictionary"}]
