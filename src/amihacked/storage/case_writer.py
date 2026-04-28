import json
import socket
from pathlib import Path
from typing import Any

from amihacked import __version__
from amihacked.core.evidence_bundle import EvidenceManifest, ManifestFile
from amihacked.utils.hashing import sha256_file
from amihacked.utils.paths import safe_relative


class CaseWriter:
    def __init__(self, case_dir: Path, case_id: str, collected_at: str) -> None:
        self.case_dir = case_dir
        self.case_id = case_id
        self.collected_at = collected_at
        self.manifest = EvidenceManifest(
            case_id=case_id,
            host=socket.gethostname(),
            collected_at=collected_at,
            collector_version=__version__,
        )

    def initialize(self) -> None:
        for relative in ("raw", "normalized", "findings", "reports"):
            (self.case_dir / relative).mkdir(parents=True, exist_ok=True)

    def write_json(self, relative_path: str, data: Any, artifact_type: str) -> Path:
        path = self.case_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(_jsonable(data), indent=2, sort_keys=True), encoding="utf-8")
        self._record_file(path, artifact_type)
        return path

    def write_text(self, relative_path: str, text: str, artifact_type: str) -> Path:
        path = self.case_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        self._record_file(path, artifact_type)
        return path

    def write_manifest(self) -> Path:
        return self.write_json("manifest.json", self.manifest, "manifest")

    def _record_file(self, path: Path, artifact_type: str) -> None:
        relative = safe_relative(path, self.case_dir)
        self.manifest.files = [item for item in self.manifest.files if item.path != relative]
        digest = sha256_file(path)
        if digest:
            self.manifest.files.append(ManifestFile(path=relative, sha256=digest, artifact_type=artifact_type))


def _jsonable(data: Any) -> Any:
    if hasattr(data, "model_dump"):
        return data.model_dump()
    if isinstance(data, list):
        return [_jsonable(item) for item in data]
    if isinstance(data, dict):
        return {key: _jsonable(value) for key, value in data.items()}
    if isinstance(data, Path):
        return str(data)
    return data

