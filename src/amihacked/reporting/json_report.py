from typing import Any


def build_json_report(
    case_id: str,
    findings: list[Any],
    risk_score: Any,
    evidence_index: dict | None = None,
    report_context: dict | None = None,
) -> dict:
    return {
        "case_id": case_id,
        "risk_score": risk_score.model_dump() if hasattr(risk_score, "model_dump") else risk_score,
        "findings": [finding.model_dump() if hasattr(finding, "model_dump") else finding for finding in findings],
        "evidence_index": evidence_index or {},
        "report_context": report_context or {},
    }
