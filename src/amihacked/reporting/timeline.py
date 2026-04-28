from typing import Any


def build_timeline(evidence: dict[str, list[dict[str, Any]]], findings: list[Any]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []

    for process in evidence.get("process", []):
        if process.get("create_time"):
            events.append(
                {
                    "timestamp": process["create_time"],
                    "event_type": "process_start",
                    "artifact_id": process.get("artifact_id"),
                    "summary": f"{process.get('name')} pid={process.get('pid')}",
                }
            )

    for log in evidence.get("log", []):
        if log.get("timestamp"):
            events.append(
                {
                    "timestamp": log["timestamp"],
                    "event_type": "log_event",
                    "artifact_id": log.get("artifact_id"),
                    "summary": _trim(log.get("message") or log.get("provider") or log.get("source")),
                }
            )

    for item in evidence.get("persistence", []):
        if item.get("last_modified"):
            events.append(
                {
                    "timestamp": item["last_modified"],
                    "event_type": "persistence_modified",
                    "artifact_id": item.get("artifact_id"),
                    "summary": f"{item.get('source')} {item.get('name')}",
                }
            )

    for finding in findings:
        timestamp = _finding_timestamp(finding, evidence)
        if timestamp:
            events.append(
                {
                    "timestamp": timestamp,
                    "event_type": "finding",
                    "artifact_id": _get(finding, "id"),
                    "summary": _get(finding, "title"),
                }
            )

    return sorted(events, key=lambda item: item["timestamp"])


def _finding_timestamp(finding: Any, evidence: dict[str, list[dict[str, Any]]]) -> str | None:
    by_id = {
        artifact.get("artifact_id"): artifact
        for artifacts in evidence.values()
        for artifact in artifacts
        if artifact.get("artifact_id")
    }
    for ref in _get(finding, "evidence_refs", []) or []:
        artifact = by_id.get(ref)
        if not artifact:
            continue
        timestamp = artifact.get("create_time") or artifact.get("timestamp") or artifact.get("last_modified")
        if timestamp:
            return timestamp
    return None


def _get(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, dict):
        return value.get(key, default)
    return getattr(value, key, default)


def _trim(value: str | None, limit: int = 160) -> str:
    text = (value or "").replace("\n", " ")
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."

