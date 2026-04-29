from typing import Any


def build_evidence_index(evidence: dict[str, list[dict[str, Any]]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for artifacts in evidence.values():
        for artifact in artifacts:
            artifact_id = artifact.get("artifact_id")
            if not artifact_id:
                continue
            index[artifact_id] = {
                "type": artifact.get("type"),
                "summary": summarize_artifact(artifact),
                "artifact": artifact,
            }
    return index


def summarize_artifact(artifact: dict[str, Any]) -> str:
    artifact_type = artifact.get("type")
    if artifact_type == "process":
        return _summarize_process(artifact)
    if artifact_type == "network":
        return _summarize_network(artifact)
    if artifact_type == "log":
        return _summarize_log(artifact)
    if artifact_type == "persistence":
        return _summarize_persistence(artifact)
    if artifact_type == "installed_software":
        return _summarize_installed_software(artifact)
    if artifact_type == "security_posture":
        return _summarize_security_posture(artifact)
    return artifact.get("artifact_id", "unknown artifact")


def _summarize_process(artifact: dict[str, Any]) -> str:
    name = artifact.get("name") or "unknown process"
    pid = artifact.get("pid")
    parent = artifact.get("parent_name")
    path = artifact.get("exe_path")
    parts = [f"{name} pid={pid}"]
    if parent:
        parts.append(f"parent={parent}")
    if path:
        parts.append(f"path={path}")
    return " ".join(parts)


def _summarize_network(artifact: dict[str, Any]) -> str:
    process = artifact.get("process_name") or artifact.get("pid") or "unknown process"
    remote = artifact.get("remote_address") or "no remote"
    remote_port = artifact.get("remote_port") or ""
    status = artifact.get("status") or "unknown status"
    return f"{process} {status} remote={remote}:{remote_port}"


def _summarize_log(artifact: dict[str, Any]) -> str:
    source = artifact.get("source") or "log"
    event_id = artifact.get("event_id")
    provider = artifact.get("provider") or artifact.get("channel")
    message = (artifact.get("message") or "").replace("\n", " ")
    if len(message) > 160:
        message = message[:157] + "..."
    return f"{source} event={event_id} provider={provider}: {message}".strip()


def _summarize_persistence(artifact: dict[str, Any]) -> str:
    source = artifact.get("source") or "persistence"
    name = artifact.get("name") or "unnamed"
    command = artifact.get("command") or artifact.get("path") or ""
    return f"{source} {name} {command}".strip()


def _summarize_installed_software(artifact: dict[str, Any]) -> str:
    name = artifact.get("name") or "unknown software"
    version = artifact.get("version")
    publisher = artifact.get("publisher")
    parts = [str(name)]
    if version:
        parts.append(f"version={version}")
    if publisher:
        parts.append(f"publisher={publisher}")
    return " ".join(parts)


def _summarize_security_posture(artifact: dict[str, Any]) -> str:
    name = artifact.get("name") or artifact.get("source") or "security posture"
    status = artifact.get("status")
    enabled = artifact.get("enabled")
    parts = [str(name)]
    if status:
        parts.append(f"status={status}")
    if enabled is not None:
        parts.append(f"enabled={enabled}")
    return " ".join(parts)
