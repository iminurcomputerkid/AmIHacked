import re
from typing import Any

from amihacked.utils.ip_utils import is_private_ip, is_public_ip


def evaluate_operator(operator: str, actual: Any, expected: Any = None) -> bool:
    if operator == "equals":
        return _lower(actual) == _lower(expected)
    if operator == "equals_any":
        return _lower(actual) in {_lower(item) for item in expected or []}
    if operator == "contains":
        return _contains(actual, expected)
    if operator == "contains_any":
        return any(_contains(actual, item) for item in expected or [])
    if operator == "regex":
        if actual is None:
            return False
        return re.search(str(expected), str(actual), flags=re.IGNORECASE) is not None
    if operator == "starts_with":
        return str(actual or "").lower().startswith(str(expected or "").lower())
    if operator == "ends_with":
        return str(actual or "").lower().endswith(str(expected or "").lower())
    if operator == "path_contains":
        return _contains(str(actual or "").replace("/", "\\"), str(expected or "").replace("/", "\\"))
    if operator == "path_under":
        actual_path = str(actual or "").lower().replace("/", "\\").rstrip("\\")
        expected_path = str(expected or "").lower().replace("/", "\\").rstrip("\\")
        return actual_path == expected_path or actual_path.startswith(expected_path + "\\")
    if operator == "greater_than":
        return _to_float(actual) is not None and _to_float(actual) > float(expected)
    if operator == "less_than":
        return _to_float(actual) is not None and _to_float(actual) < float(expected)
    if operator == "exists":
        return actual is not None
    if operator == "not_exists":
        return actual is None
    if operator == "is_public_ip":
        return is_public_ip(actual) is True
    if operator == "is_private_ip":
        return is_private_ip(actual) is True
    if operator == "in_list":
        return actual in (expected or [])
    if operator == "not_in_list":
        return actual not in (expected or [])
    raise ValueError(f"Unsupported operator: {operator}")


SUPPORTED_OPERATORS = {
    "equals",
    "equals_any",
    "contains",
    "contains_any",
    "regex",
    "starts_with",
    "ends_with",
    "path_contains",
    "path_under",
    "greater_than",
    "less_than",
    "exists",
    "not_exists",
    "is_public_ip",
    "is_private_ip",
    "in_list",
    "not_in_list",
}


def _lower(value: Any) -> str | None:
    if value is None:
        return None
    return str(value).lower()


def _contains(actual: Any, expected: Any) -> bool:
    if actual is None or expected is None:
        return False
    return str(expected).lower() in str(actual).lower()


def _to_float(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None

