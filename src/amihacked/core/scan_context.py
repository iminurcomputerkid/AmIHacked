from pathlib import Path
from pydantic import BaseModel


class ScanContext(BaseModel):
    case_id: str
    case_dir: Path
    started_at: str
    platform: str
    mode: str = "basic"
    elevated: bool = False

