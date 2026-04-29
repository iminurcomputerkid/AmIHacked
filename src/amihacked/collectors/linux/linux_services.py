import configparser
import shutil
import subprocess
from pathlib import Path
from typing import Any

from amihacked.core.models import CollectorResult
from amihacked.core.scan_context import ScanContext
from amihacked.utils.ids import stable_id
from amihacked.utils.paths import extract_executable_path
from amihacked.utils.time import from_timestamp, utc_now_iso


SYSTEMD_UNIT_DIRS = [
    Path("/etc/systemd/system"),
    Path("/run/systemd/system"),
    Path("/usr/local/lib/systemd/system"),
    Path("/usr/lib/systemd/system"),
    Path("/lib/systemd/system"),
]


class LinuxServicesCollector:
    name = "services"
    supported_platforms = ["linux"]
    requires_admin = False

    def collect(self, context: ScanContext) -> CollectorResult:
        artifacts: list[dict[str, Any]] = []
        warnings: list[str] = []
        unit_state = _systemctl_unit_file_state()
        if unit_state is None:
            warnings.append("systemctl service state unavailable; falling back to unit files only.")
            unit_state = {}

        for unit_path in _iter_service_unit_files():
            try:
                artifact = _service_artifact(unit_path, unit_state.get(unit_path.name))
            except OSError as exc:
                warnings.append(f"Could not read service unit {unit_path}: {exc}")
                continue
            if artifact:
                artifacts.append(artifact)

        if not artifacts and not warnings:
            warnings.append("No systemd service unit files were found in configured locations.")

        return CollectorResult(
            collector_name=self.name,
            status="partial" if warnings else "ok",
            artifacts=artifacts,
            warnings=warnings,
            collected_at=utc_now_iso(),
        )


def _iter_service_unit_files() -> list[Path]:
    files: list[Path] = []
    seen: set[Path] = set()
    seen_names: set[str] = set()
    for directory in SYSTEMD_UNIT_DIRS:
        if not directory.exists():
            continue
        for path in sorted(directory.rglob("*.service")):
            resolved = path.resolve()
            if not path.is_file() or resolved in seen or path.name in seen_names:
                continue
            seen.add(resolved)
            seen_names.add(path.name)
            files.append(path)
    return files


def _service_artifact(path: Path, state: str | None) -> dict[str, Any]:
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    parser.read(path, encoding="utf-8")
    service = parser["Service"] if parser.has_section("Service") else {}
    unit = parser["Unit"] if parser.has_section("Unit") else {}
    install = parser["Install"] if parser.has_section("Install") else {}
    command = _first_command(service)
    return {
        "artifact_id": stable_id("persistence", "linux_service", path.name, command, str(path)),
        "type": "persistence",
        "source": "linux_service",
        "name": path.name,
        "command": command,
        "path": extract_executable_path(command),
        "user": service.get("User"),
        "enabled": _service_enabled(state, install),
        "last_modified": _mtime_iso(path),
        "display_name": unit.get("Description"),
        "status": None,
        "start_type": state,
        "unit_path": str(path),
        "wanted_by": install.get("WantedBy"),
    }


def _first_command(service: Any) -> str | None:
    for key in ("ExecStart", "ExecStartPre", "ExecStartPost"):
        value = service.get(key)
        if value:
            return str(value)
    return None


def _service_enabled(state: str | None, install: Any) -> bool | None:
    if state:
        lowered = state.lower()
        if lowered in {"enabled", "enabled-runtime", "linked", "linked-runtime", "static"}:
            return True
        if lowered in {"disabled", "masked", "masked-runtime"}:
            return False
    if install.get("WantedBy") or install.get("RequiredBy"):
        return True
    return None


def _systemctl_unit_file_state() -> dict[str, str] | None:
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return None
    try:
        completed = subprocess.run(
            [systemctl, "list-unit-files", "--type=service", "--all", "--no-legend", "--no-pager"],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    states: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].endswith(".service"):
            states[parts[0]] = parts[1]
    return states


def _mtime_iso(path: Path) -> str | None:
    try:
        return from_timestamp(path.stat().st_mtime)
    except OSError:
        return None
