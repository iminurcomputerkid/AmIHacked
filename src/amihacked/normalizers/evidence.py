from typing import Any

from amihacked.utils.paths import extract_executable_path


def normalize_scan_evidence(raw: dict[str, list[dict[str, Any]]]) -> dict[str, list[dict[str, Any]]]:
    return {
        "process": normalize_artifacts(raw.get("process", []), "process"),
        "network": normalize_artifacts(raw.get("network", []), "network"),
        "log": normalize_artifacts(raw.get("log", []), "log"),
        "persistence": normalize_artifacts(raw.get("persistence", []), "persistence"),
    }


def normalize_artifacts(artifacts: list[dict[str, Any]], artifact_type: str) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, artifact in enumerate(artifacts):
        item = dict(artifact)
        item.setdefault("type", artifact_type)
        item.setdefault("artifact_id", f"{artifact_type}:unknown:{index}")
        if artifact_type == "persistence" and not item.get("path"):
            item["path"] = extract_executable_path(item.get("command"))
        if item["artifact_id"] in seen:
            item["artifact_id"] = f"{item['artifact_id']}:{index}"
        seen.add(item["artifact_id"])
        normalized.append(item)
    return sorted(normalized, key=lambda item: str(item.get("artifact_id")))
