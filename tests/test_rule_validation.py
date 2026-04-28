from pathlib import Path

from amihacked.detection.rule_loader import RuleLoader, validate_rule
from amihacked.detection.rule_models import DetectionRule


def test_builtin_rules_are_valid():
    _rules, results = RuleLoader([Path("rules/builtin")]).load_rules()

    invalid = [result for result in results if not result.valid]

    assert invalid == []


def test_broad_process_name_contains_rule_is_rejected():
    rule = DetectionRule(
        id="AH-TEST-BROAD",
        name="Broad PowerShell",
        enabled=True,
        source="process",
        severity="medium",
        confidence=0.5,
        description="This rule is intentionally too broad for validation testing.",
        conditions={"all": [{"field": "name", "contains": "powershell"}]},
        recommendation="Use command line or parent process context.",
    )

    result = validate_rule(rule)

    assert not result.valid
    assert any("broad contains" in error for error in result.errors)
    assert any("only one condition" in error for error in result.errors)

