from typing import Any, Literal
from pydantic import BaseModel, Field


class ArtifactModel(BaseModel):
    artifact_id: str
    type: str


class ProcessArtifact(ArtifactModel):
    type: str = "process"
    pid: int
    ppid: int | None = None
    name: str
    exe_path: str | None = None
    command_line: str | None = None
    username: str | None = None
    create_time: str | None = None
    cwd: str | None = None
    cpu_percent: float | None = None
    memory_percent: float | None = None
    sha256: str | None = None
    signed: bool | None = None
    signer: str | None = None
    parent_name: str | None = None


class NetworkConnectionArtifact(ArtifactModel):
    type: str = "network"
    pid: int | None = None
    process_name: str | None = None
    exe_path: str | None = None
    command_line: str | None = None
    username: str | None = None
    local_address: str | None = None
    local_port: int | None = None
    remote_address: str | None = None
    remote_port: int | None = None
    status: str | None = None
    protocol: str | None = None
    is_public_remote: bool | None = None


class PersistenceArtifact(ArtifactModel):
    type: str = "persistence"
    source: str
    name: str
    command: str | None = None
    path: str | None = None
    user: str | None = None
    enabled: bool | None = None
    last_modified: str | None = None


class LogEventArtifact(ArtifactModel):
    type: str = "log"
    source: str
    channel: str | None = None
    provider: str | None = None
    event_id: int | str | None = None
    record_id: int | str | None = None
    timestamp: str | None = None
    computer: str | None = None
    username: str | None = None
    level: str | None = None
    message: str | None = None
    raw: dict[str, Any] | str | None = None


class InstalledSoftwareArtifact(ArtifactModel):
    type: str = "installed_software"
    source: str
    name: str
    version: str | None = None
    publisher: str | None = None
    install_date: str | None = None
    install_location: str | None = None
    uninstall_string: str | None = None
    quiet_uninstall_string: str | None = None
    registry_hive: str | None = None
    registry_path: str | None = None
    system_component: bool | None = None
    windows_installer: bool | None = None
    estimated_size_kb: int | None = None


class SecurityPostureArtifact(ArtifactModel):
    type: str = "security_posture"
    source: str
    name: str
    status: str | None = None
    enabled: bool | None = None
    details: dict[str, Any] = Field(default_factory=dict)


class CollectorResult(BaseModel):
    collector_name: str
    status: Literal["ok", "partial", "error"]
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    collected_at: str


class RuleMatch(BaseModel):
    rule_id: str
    rule_name: str
    source: str
    severity: str
    confidence: float
    evidence_id: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    reason: str
    matched_fields: dict[str, Any] = Field(default_factory=dict)
    mitre_techniques: list[str] = Field(default_factory=list)
    recommendation: str | None = None
    score_impact: int = 0


class Finding(BaseModel):
    id: str
    title: str
    severity: str
    confidence: float
    description: str
    evidence_type: str
    evidence_id: str | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    matched_rule: str | None = None
    reason: str
    recommendation: str | None = None
    mitre_techniques: list[str] = Field(default_factory=list)
    score_impact: int = 0
    modifiers: list[str] = Field(default_factory=list)
    score_details: list[str] = Field(default_factory=list)
