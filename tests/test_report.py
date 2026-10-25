import json

from opensource_atlas.report import build_report, to_json, to_markdown


def test_json_report_is_valid_and_contains_limitations():
    report = build_report(
        {"full_name": "octo/example", "html_url": "https://github.com/octo/example"},
        {"score": 70, "score_basis": "70/100 weighted points available", "components": [], "notes": []},
    )
    decoded = json.loads(to_json(report))
    assert decoded["repository"]["name"] == "octo/example"
    assert decoded["limitations"]


def test_markdown_report_has_breakdown():
    report = build_report(
        {"full_name": "octo/example", "html_url": "https://github.com/octo/example", "stargazers_count": 1},
        {
            "score": 70,
            "score_basis": "70/100 weighted points available",
            "components": [{"name": "Maintenance", "points": 20, "max_points": 35, "evidence": "Recent push"}],
            "notes": ["Heuristic only."],
        },
    )
    markdown = to_markdown(report)
    assert "Score breakdown" in markdown
    assert "Maintenance" in markdown
    assert "Limitations" in markdown
