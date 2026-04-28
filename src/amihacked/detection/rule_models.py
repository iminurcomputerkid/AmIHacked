from typing import Any, Literal

from pydantic import BaseModel, Field


Severity = Literal["critical", "high", "medium", "low"]


class MitreTechnique(BaseModel):
    technique_id: str
    technique_name: str | None = None
    tactic: str | None = None


class DetectionRule(BaseModel):
    id: str
    name: str
    enabled: bool = True
    source: str
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    description: str
    conditions: dict[str, Any]
    mitre: list[MitreTechnique] = Field(default_factory=list)
    recommendation: str | None = None
    status: str | None = None
    created_by: str | None = None


class RuleValidationResult(BaseModel):
    rule_id: str | None = None
    valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

