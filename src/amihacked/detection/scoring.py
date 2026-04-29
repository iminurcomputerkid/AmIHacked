from typing import Any

from pydantic import BaseModel, Field

from amihacked.core.models import Finding
from amihacked.utils.paths import looks_user_writable


BASE_SCORES = {
    "critical": 35,
    "high": 25,
    "medium": 10,
    "low": 3,
}


class ScoreReason(BaseModel):
    points: int
    reason: str
    finding_id: str | None = None


class RiskScore(BaseModel):
    score: int
    level: str
    reasons: list[ScoreReason] = Field(default_factory=list)


class ScoringEngine:
    def score(self, findings: list[Finding], evidence: dict[str, list[dict[str, Any]]]) -> RiskScore:
        reasons: list[ScoreReason] = []
        by_ref = {
            artifact.get("artifact_id"): artifact
            for artifacts in evidence.values()
            for artifact in artifacts
            if artifact.get("artifact_id")
        }
        seen_signatures: set[tuple[str, tuple[str, ...]]] = set()

        for finding in findings:
            signature = (finding.matched_rule or finding.title, tuple(sorted(finding.evidence_refs)))
            if signature in seen_signatures:
                finding.score_impact = 0
                finding.modifiers.append("Duplicate finding suppressed for scoring")
                reasons.append(ScoreReason(points=0, reason=f"Duplicate suppressed: {finding.title}", finding_id=finding.id))
                continue
            seen_signatures.add(signature)

            base = BASE_SCORES.get(finding.severity, 0)
            finding.score_impact = base
            finding.score_details.append(f"+{base} {finding.severity.title()} finding")
            reasons.append(ScoreReason(points=base, reason=f"{finding.severity.title()} finding: {finding.title}", finding_id=finding.id))

            refs = [by_ref[ref] for ref in finding.evidence_refs if ref in by_ref]
            if any(ref.get("is_public_remote") is True for ref in refs):
                finding.modifiers.append("External network connection")
                finding.score_impact += 10
                finding.score_details.append("+10 External network connection")
                reasons.append(ScoreReason(points=10, reason="External network connection", finding_id=finding.id))

            if any(ref.get("type") == "persistence" for ref in refs) or "persistence" in finding.title.lower():
                finding.modifiers.append("Persistence mechanism involved")
                finding.score_impact += 15
                finding.score_details.append("+15 Persistence mechanism involved")
                reasons.append(ScoreReason(points=15, reason="Persistence mechanism involved", finding_id=finding.id))

            if any(ref.get("signed") is False for ref in refs):
                finding.modifiers.append("Unsigned binary")
                finding.score_impact += 10
                finding.score_details.append("+10 Unsigned binary")
                reasons.append(ScoreReason(points=10, reason="Unsigned binary", finding_id=finding.id))

            if any(looks_user_writable(ref.get("exe_path") or ref.get("path")) for ref in refs):
                finding.modifiers.append("Running from AppData/Temp or user-writable path")
                finding.score_impact += 10
                finding.score_details.append("+10 Executable from AppData/Temp or user-writable path")
                reasons.append(ScoreReason(points=10, reason="Executable from AppData/Temp or user-writable path", finding_id=finding.id))

            if any((ref.get("parent_name") or "").lower() in {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"} for ref in refs):
                finding.modifiers.append("Office parent process")
                finding.score_impact += 15
                finding.score_details.append("+15 Office parent process")
                reasons.append(ScoreReason(points=15, reason="Office parent process", finding_id=finding.id))

            if any((ref.get("signer") or "").lower() == "microsoft" and _is_system_path(ref.get("exe_path")) for ref in refs):
                finding.modifiers.append("System path and signed Microsoft binary")
                finding.score_impact -= 5
                finding.score_details.append("-5 System path and signed Microsoft binary")
                reasons.append(ScoreReason(points=-5, reason="System path and signed Microsoft binary", finding_id=finding.id))

        total = max(0, min(100, sum(reason.points for reason in reasons)))
        return RiskScore(score=total, level=self._level(total), reasons=reasons)

    @staticmethod
    def _level(score: int) -> str:
        if score <= 20:
            return "Low"
        if score <= 50:
            return "Moderate"
        if score <= 80:
            return "High"
        return "Critical"


def _is_system_path(path: str | None) -> bool:
    if not path:
        return False
    normalized = path.lower().replace("/", "\\")
    return "\\windows\\system32\\" in normalized or "\\program files\\" in normalized
