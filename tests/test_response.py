import pytest
from opensource_atlas.response import build_response_plan


@pytest.mark.parametrize("severity", ["info", "low", "medium", "high", "critical"])
def test_all_plans_are_dry_run_and_require_approval(severity):
    plan = build_response_plan({"severity": severity})
    assert plan["mode"] == "dry_run"
    assert plan["approval_required"] is True
    assert plan["execution_enabled"] is False
    assert all(step["status"] == "proposed" for step in plan["steps"])


@pytest.mark.parametrize("severity", ["unknown", [], None, 3])
def test_invalid_severity_is_rejected(severity):
    with pytest.raises(ValueError):
        build_response_plan({"severity": severity})
