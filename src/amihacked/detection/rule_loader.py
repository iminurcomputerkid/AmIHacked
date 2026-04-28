from pathlib import Path
from typing import Any

import yaml

from amihacked.detection.operators import SUPPORTED_OPERATORS
from amihacked.detection.rule_models import DetectionRule, RuleValidationResult


SUPPORTED_FIELDS = {
    "process": {
        "artifact_id",
        "type",
        "pid",
        "ppid",
        "name",
        "exe_path",
        "command_line",
        "username",
        "create_time",
        "cwd",
        "cpu_percent",
        "memory_percent",
        "sha256",
        "signed",
        "signer",
        "parent_name",
    },
    "network": {
        "artifact_id",
        "type",
        "pid",
        "process_name",
        "local_address",
        "local_port",
        "remote_address",
        "remote_port",
        "status",
        "protocol",
        "is_public_remote",
    },
    "persistence": {
        "artifact_id",
        "type",
        "source",
        "name",
        "command",
        "path",
        "user",
        "enabled",
        "last_modified",
        "registry_hive",
        "registry_path",
        "registry_value_type",
        "startup_folder",
        "task_status",
        "schedule_type",
        "last_run_time",
        "next_run_time",
        "display_name",
        "status",
        "start_type",
        "pid",
    },
    "log": {
        "artifact_id",
        "type",
        "source",
        "channel",
        "provider",
        "event_id",
        "record_id",
        "timestamp",
        "computer",
        "username",
        "level",
        "message",
        "raw",
    },
}


class RuleLoader:
    def __init__(self, rule_dirs: list[Path], include_disabled: bool = False) -> None:
        self.rule_dirs = rule_dirs
        self.include_disabled = include_disabled

    def load_rules(self) -> tuple[list[DetectionRule], list[RuleValidationResult]]:
        rules: list[DetectionRule] = []
        validation_results: list[RuleValidationResult] = []
        for rule_file in self._iter_rule_files():
            try:
                raw = yaml.safe_load(rule_file.read_text(encoding="utf-8")) or {}
                rule = DetectionRule.model_validate(raw)
                result = validate_rule(rule)
                validation_results.append(result)
                if result.valid and (rule.enabled or self.include_disabled):
                    rules.append(rule)
            except Exception as exc:
                validation_results.append(
                    RuleValidationResult(rule_id=rule_file.name, valid=False, errors=[str(exc)])
                )
        return rules, validation_results

    def _iter_rule_files(self) -> list[Path]:
        files: list[Path] = []
        for rule_dir in self.rule_dirs:
            if not rule_dir.exists():
                continue
            files.extend(sorted(rule_dir.rglob("*.yml")))
            files.extend(sorted(rule_dir.rglob("*.yaml")))
            files.extend(sorted(rule_dir.rglob("*.json")))
        return sorted(set(files))


def validate_rule(rule: DetectionRule) -> RuleValidationResult:
    errors: list[str] = []
    warnings: list[str] = []

    if rule.source not in SUPPORTED_FIELDS:
        errors.append(f"Unsupported source: {rule.source}")

    if not rule.description or len(rule.description.strip()) < 20:
        warnings.append("Description is short; analyst context may be weak.")

    if not rule.recommendation:
        warnings.append("Recommendation is missing.")

    dangerous_tokens = ("subprocess", "os.system", "eval(", "exec(")
    serialized = str(rule.model_dump()).lower()
    for token in dangerous_tokens:
        if token in serialized:
            errors.append(f"Rule contains disallowed executable-code token: {token.strip()}")

    _validate_condition_group(rule.conditions, rule.source, errors, warnings)
    leaf_conditions = _flatten_leaf_conditions(rule.conditions)
    _validate_breadth(leaf_conditions, errors, warnings)

    return RuleValidationResult(
        rule_id=rule.id,
        valid=not errors,
        errors=errors,
        warnings=warnings,
    )


def _validate_condition_group(group: dict[str, Any], source: str, errors: list[str], warnings: list[str]) -> None:
    if not isinstance(group, dict):
        errors.append("Conditions must be a mapping.")
        return

    if "all" not in group and "any" not in group:
        errors.append("Conditions must contain all or any.")
        return

    for key in ("all", "any"):
        conditions = group.get(key)
        if conditions is None:
            continue
        if not isinstance(conditions, list) or not conditions:
            errors.append(f"conditions.{key} must be a non-empty list.")
            continue
        for condition in conditions:
            if "all" in condition or "any" in condition:
                _validate_condition_group(condition, source, errors, warnings)
                continue
            _validate_leaf(condition, source, errors, warnings)


def _validate_leaf(condition: dict[str, Any], source: str, errors: list[str], warnings: list[str]) -> None:
    if not isinstance(condition, dict):
        errors.append("Each condition must be a mapping.")
        return

    field = condition.get("field")
    if not field:
        errors.append("Condition is missing field.")
        return

    if source in SUPPORTED_FIELDS and field not in SUPPORTED_FIELDS[source]:
        errors.append(f"Unsupported field for {source}: {field}")

    operators = [key for key in condition if key != "field"]
    if len(operators) != 1:
        errors.append(f"Condition for {field} must use exactly one operator.")
        return

    operator = operators[0]
    if operator not in SUPPORTED_OPERATORS:
        errors.append(f"Unsupported operator: {operator}")

    if field in {"name", "process_name"} and operator == "contains":
        errors.append(f"Rule on {field} uses broad contains; use equals or equals_any.")


def _flatten_leaf_conditions(group: dict[str, Any]) -> list[dict[str, Any]]:
    leaves: list[dict[str, Any]] = []
    if not isinstance(group, dict):
        return leaves
    for key in ("all", "any"):
        for condition in group.get(key) or []:
            if isinstance(condition, dict) and ("all" in condition or "any" in condition):
                leaves.extend(_flatten_leaf_conditions(condition))
            elif isinstance(condition, dict):
                leaves.append(condition)
    return leaves


def _validate_breadth(conditions: list[dict[str, Any]], errors: list[str], warnings: list[str]) -> None:
    if not conditions:
        return
    fields = {condition.get("field") for condition in conditions}
    identity_fields = {"name", "process_name", "provider", "channel", "source"}
    contextual_fields = {
        "command_line",
        "exe_path",
        "parent_name",
        "remote_address",
        "remote_port",
        "local_port",
        "is_public_remote",
        "message",
        "event_id",
        "path",
        "command",
    }

    if len(conditions) == 1:
        errors.append("Rule has only one condition and is likely too broad.")
    if fields and fields.issubset(identity_fields):
        errors.append("Rule only matches identity fields; add contextual behavior conditions.")
    if not fields.intersection(contextual_fields):
        warnings.append("Rule has no behavioral context fields such as command_line, path, network, event_id, or message.")

    for condition in conditions:
        operator = next((key for key in condition if key != "field"), None)
        expected = condition.get(operator)
        if operator in {"contains", "contains_any"}:
            values = expected if isinstance(expected, list) else [expected]
            for value in values:
                if value is not None and len(str(value).strip()) < 4:
                    warnings.append(f"Contains value {value!r} is short and may be noisy.")
