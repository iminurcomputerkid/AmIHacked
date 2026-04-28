from pydantic import BaseModel, Field


class ManifestFile(BaseModel):
    path: str
    sha256: str
    artifact_type: str


class EvidenceManifest(BaseModel):
    case_id: str
    host: str
    collected_at: str
    collector_version: str
    files: list[ManifestFile] = Field(default_factory=list)

