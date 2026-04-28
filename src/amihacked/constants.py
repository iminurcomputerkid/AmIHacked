from pathlib import Path

PACKAGE_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = PACKAGE_ROOT.parents[1]

DEFAULT_CASES_DIR = PROJECT_ROOT / "output" / "cases"
BUILTIN_RULES_DIR = PROJECT_ROOT / "rules" / "builtin"
COMMUNITY_RULES_DIR = PROJECT_ROOT / "rules" / "community"
PENDING_RULES_DIR = PROJECT_ROOT / "rules" / "pending"
