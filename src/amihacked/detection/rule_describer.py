from typing import Any


def describe_rule_conditions(conditions: dict[str, Any]) -> str:
    return _describe_group(conditions)


def _describe_group(group: dict[str, Any]) -> str:
    if "all" in group:
        return " AND ".join(_describe_condition(condition) for condition in group["all"])
    if "any" in group:
        return " OR ".join(_describe_condition(condition) for condition in group["any"])
    return "invalid condition group"


def _describe_condition(condition: dict[str, Any]) -> str:
    if "all" in condition or "any" in condition:
        return f"({_describe_group(condition)})"
    field = condition.get("field", "<missing field>")
    operator = next((key for key in condition if key != "field"), "<missing operator>")
    value = condition.get(operator)
    return f"{field} {operator.replace('_', ' ')} {_format_value(value)}"


def _format_value(value: Any) -> str:
    if isinstance(value, list):
        return "[" + ", ".join(repr(item) for item in value) + "]"
    return repr(value)

