import json
from pathlib import Path
from typing import Any

from pydantic import TypeAdapter

from amihacked.core.models import Finding
from amihacked.detection.scoring import RiskScore


class CaseReader:
    def __init__(self, case_dir: Path) -> None:
        self.case_dir = case_dir

    def read_json(self, relative_path: str, default: Any = None) -> Any:
        path = self.case_dir / relative_path
        if not path.exists():
            return default
        return json.loads(path.read_text(encoding="utf-8"))

    def read_findings(self) -> list[Finding]:
        raw = self.read_json("findings/findings.json", [])
        return TypeAdapter(list[Finding]).validate_python(raw)

    def read_risk_score(self) -> RiskScore:
        raw = self.read_json("findings/risk_score.json", {"score": 0, "level": "Low", "reasons": []})
        return RiskScore.model_validate(raw)

    def read_evidence(self) -> dict[str, list[dict[str, Any]]]:
        return {
            "process": self.read_json("normalized/processes.normalized.json", []),
            "network": self.read_json("normalized/network.normalized.json", []),
            "log": self.read_json("normalized/logs.normalized.json", []),
            "persistence": self.read_json("normalized/persistence.normalized.json", []),
        }

