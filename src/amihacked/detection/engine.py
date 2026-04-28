from typing import Any

from amihacked.core.models import Finding, RuleMatch
from amihacked.detection.operators import evaluate_operator
from amihacked.detection.rule_models import DetectionRule
from amihacked.utils.ids import stable_id


class DetectionEngine:
    def __init__(self, rules: list[DetectionRule]) -> None:
        self.rules = rules

    def run(self, evidence: dict[str, list[dict[str, Any]]]) -> tuple[list[RuleMatch], list[Finding]]:
        matches: list[RuleMatch] = []
        findings: list[Finding] = []

        for rule in self.rules:
            for artifact in evidence.get(rule.source, []):
                matched, fields = self._matches(rule.conditions, artifact)
                if not matched:
                    continue

                evidence_id = artifact.get("artifact_id")
                mitre = [item.technique_id for item in rule.mitre]
                match = RuleMatch(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    source=rule.source,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    evidence_id=evidence_id,
                    evidence_refs=[evidence_id] if evidence_id else [],
                    reason=rule.description,
                    matched_fields=fields,
                    mitre_techniques=mitre,
                    recommendation=rule.recommendation,
                )
                matches.append(match)
                findings.append(
                    Finding(
                        id=stable_id("finding", rule.id, evidence_id),
                        title=rule.name,
                        severity=rule.severity,
                        confidence=rule.confidence,
                        description=rule.description,
                        evidence_type=rule.source,
                        evidence_id=evidence_id,
                        evidence_refs=[evidence_id] if evidence_id else [],
                        matched_rule=rule.id,
                        reason=self._plain_reason(rule, fields),
                        recommendation=rule.recommendation,
                        mitre_techniques=mitre,
                    )
                )

        return matches, findings

    def _matches(self, conditions: dict[str, Any], artifact: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        matched_fields: dict[str, Any] = {}

        if "all" in conditions:
            for condition in conditions["all"]:
                result, fields = self._evaluate_condition(condition, artifact)
                if not result:
                    return False, {}
                matched_fields.update(fields)
            return True, matched_fields

        if "any" in conditions:
            any_matched = False
            for condition in conditions["any"]:
                result, fields = self._evaluate_condition(condition, artifact)
                if result:
                    any_matched = True
                    matched_fields.update(fields)
            return any_matched, matched_fields

        return False, {}

    def _evaluate_condition(self, condition: dict[str, Any], artifact: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        if "all" in condition or "any" in condition:
            return self._matches(condition, artifact)

        field = condition["field"]
        operator = next(key for key in condition if key != "field")
        expected = condition.get(operator)
        actual = artifact.get(field)
        result = evaluate_operator(operator, actual, expected)
        return result, {field: actual} if result else {}

    @staticmethod
    def _plain_reason(rule: DetectionRule, fields: dict[str, Any]) -> str:
        evidence_bits = ", ".join(f"{key}={value!r}" for key, value in fields.items() if value is not None)
        if not evidence_bits:
            return rule.description
        return f"{rule.description} Matched evidence: {evidence_bits}."
