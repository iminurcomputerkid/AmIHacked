from collections import Counter, defaultdict
from typing import Any


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def sort_findings(findings: list[Any]) -> list[Any]:
    return sorted(
        findings,
        key=lambda finding: (
            SEVERITY_ORDER.get(_get(finding, "severity", "low"), 99),
            -float(_get(finding, "confidence", 0) or 0),
            _get(finding, "title", ""),
        ),
    )


def build_report_context(
    metadata: dict[str, Any],
    findings: list[Any],
    evidence: dict[str, list[dict[str, Any]]],
    collector_results: dict[str, Any] | None = None,
    timeline: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    sorted_findings = sort_findings(findings)
    severity_counts = Counter(_get(finding, "severity", "unknown") for finding in sorted_findings)
    artifact_counts = {source: len(items) for source, items in evidence.items()}
    return {
        "metadata": metadata,
        "summary": {
            "finding_count": len(sorted_findings),
            "severity_counts": dict(severity_counts),
            "artifact_counts": artifact_counts,
            "top_findings": sorted_findings[:5],
        },
        "collection_health": build_collection_health(collector_results or {}, metadata),
        "finding_groups": group_findings(sorted_findings),
        "timeline": (timeline or [])[:200],
    }


def build_collection_health(collector_results: dict[str, Any], metadata: dict[str, Any]) -> dict[str, Any]:
    collectors: list[dict[str, Any]] = []
    for name, result in collector_results.items():
        artifacts = _get(result, "artifacts", [])
        warnings = _get(result, "warnings", [])
        errors = _get(result, "errors", [])
        collectors.append(
            {
                "name": name,
                "status": _get(result, "status", "unknown"),
                "artifact_count": len(artifacts or []),
                "warnings": warnings or [],
                "errors": errors or [],
                "collected_at": _get(result, "collected_at"),
            }
        )

    status_counts = Counter(item["status"] for item in collectors)
    return {
        "elevated": metadata.get("elevated"),
        "privilege_warning": metadata.get("privilege_warning"),
        "collector_count": len(collectors),
        "status_counts": dict(status_counts),
        "collectors": sorted(collectors, key=lambda item: item["name"]),
    }


def group_findings(findings: list[Any]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in findings:
        refs = _get(finding, "evidence_refs", []) or []
        key = "ungrouped"
        for ref in refs:
            if str(ref).startswith("process:"):
                key = str(ref)
                break
            if str(ref).startswith("persistence:"):
                key = str(ref)
                break
            if str(ref).startswith("network:"):
                key = str(ref)
        groups[key].append(_finding_summary(finding))
    return dict(sorted(groups.items()))


def _finding_summary(finding: Any) -> dict[str, Any]:
    return {
        "id": _get(finding, "id"),
        "title": _get(finding, "title"),
        "severity": _get(finding, "severity"),
        "confidence": _get(finding, "confidence"),
        "score_impact": _get(finding, "score_impact"),
    }


def _get(value: Any, key: str, default: Any = None) -> Any:
    if isinstance(value, dict):
        return value.get(key, default)
    return getattr(value, key, default)

