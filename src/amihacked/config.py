from pathlib import Path
from pydantic import BaseModel, Field

from amihacked.constants import BUILTIN_RULES_DIR, COMMUNITY_RULES_DIR, DEFAULT_CASES_DIR


class AppConfig(BaseModel):
    cases_dir: Path = DEFAULT_CASES_DIR
    rule_dirs: list[Path] = Field(default_factory=lambda: [BUILTIN_RULES_DIR, COMMUNITY_RULES_DIR])
    include_full_collectors: bool = False
