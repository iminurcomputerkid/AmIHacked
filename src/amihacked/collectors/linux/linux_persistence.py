from pathlib import Path
from typing import Any

from amihacked.core.models import CollectorResult, PersistenceArtifact
from amihacked.core.scan_context import ScanContext
from amihacked.utils.ids import stable_id
from amihacked.utils.paths import extract_executable_path
from amihacked.utils.time import from_timestamp, utc_now_iso


CRON_FILES = [Path("/etc/crontab")]
CRON_DIRS = [Path("/etc/cron.d"), Path("/var/spool/cron"), Path("/var/spool/cron/crontabs")]
AUTOSTART_DIRS = [Path("/etc/xdg/autostart"), Path.home() / ".config" / "autostart"]


class LinuxPersistenceCollector:
    name = "platform_persistence"
    supported_platforms = ["linux"]
    requires_admin = False

    def collect(self, context: ScanContext) -> CollectorResult:
        cron_artifacts, cron_warnings = _collect_cron()
        autostart_artifacts, autostart_warnings = _collect_xdg_autostart()
        artifacts = [*cron_artifacts, *autostart_artifacts]
        warnings = [*cron_warnings, *autostart_warnings]
        return CollectorResult(
            collector_name=self.name,
            status="partial" if warnings else "ok",
            artifacts=artifacts,
            warnings=warnings,
            collected_at=utc_now_iso(),
        )


def _collect_cron() -> tuple[list[dict[str, Any]], list[str]]:
    artifacts: list[dict[str, Any]] = []
    warnings: list[str] = []
    paths = [path for path in CRON_FILES if path.exists()]
    for directory in CRON_DIRS:
        if directory.exists():
            paths.extend(path for path in sorted(directory.rglob("*")) if path.is_file())
    for path in paths:
        try:
            for line_number, command in _cron_commands(path):
                artifacts.append(_persistence_artifact("linux_cron", path.name, command, path, line_number))
        except PermissionError:
            warnings.append(f"Access denied reading cron file {path}")
        except OSError as exc:
            warnings.append(f"Could not read cron file {path}: {exc}")
    return artifacts, warnings


def _collect_xdg_autostart() -> tuple[list[dict[str, Any]], list[str]]:
    artifacts: list[dict[str, Any]] = []
    warnings: list[str] = []
    for directory in AUTOSTART_DIRS:
        if not directory.exists():
            continue
        for path in sorted(directory.glob("*.desktop")):
            try:
                command = _desktop_exec(path)
            except OSError as exc:
                warnings.append(f"Could not read autostart entry {path}: {exc}")
                continue
            if command:
                artifacts.append(_persistence_artifact("linux_xdg_autostart", path.name, command, path, None))
    return artifacts, warnings


def _cron_commands(path: Path) -> list[tuple[int, str]]:
    commands: list[tuple[int, str]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or _looks_like_env_assignment(stripped):
            continue
        fields = stripped.split()
        if len(fields) < 6:
            continue
        command = " ".join(fields[6:] if path.name == "crontab" or str(path).startswith("/etc/") else fields[5:])
        if command:
            commands.append((line_number, command))
    return commands


def _desktop_exec(path: Path) -> str | None:
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("Exec="):
            return line.partition("=")[2].strip() or None
    return None


def _persistence_artifact(source: str, name: str, command: str, path: Path, line_number: int | None) -> dict[str, Any]:
    artifact = PersistenceArtifact(
        artifact_id=stable_id("persistence", source, str(path), line_number, command),
        source=source,
        name=name,
        command=command,
        path=extract_executable_path(command),
        user=_owner(path),
        enabled=True,
        last_modified=_mtime_iso(path),
    ).model_dump()
    artifact["definition_path"] = str(path)
    artifact["line_number"] = line_number
    return artifact


def _looks_like_env_assignment(value: str) -> bool:
    name, separator, _rest = value.partition("=")
    return bool(separator and name and name.replace("_", "").isalnum() and not name[0].isdigit())


def _owner(path: Path) -> str | None:
    try:
        import pwd

        return pwd.getpwuid(path.stat().st_uid).pw_name
    except (ImportError, KeyError, OSError):
        return None


def _mtime_iso(path: Path) -> str | None:
    try:
        return from_timestamp(path.stat().st_mtime)
    except OSError:
        return None
