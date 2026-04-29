import plistlib
from pathlib import Path
from typing import Any

from amihacked.core.models import CollectorResult, PersistenceArtifact
from amihacked.core.scan_context import ScanContext
from amihacked.utils.ids import stable_id
from amihacked.utils.paths import extract_executable_path
from amihacked.utils.time import from_timestamp, utc_now_iso


LAUNCHD_DIRS = [
    ("user_launch_agent", Path.home() / "Library" / "LaunchAgents"),
    ("global_launch_agent", Path("/Library/LaunchAgents")),
    ("global_launch_daemon", Path("/Library/LaunchDaemons")),
    ("system_launch_agent", Path("/System/Library/LaunchAgents")),
    ("system_launch_daemon", Path("/System/Library/LaunchDaemons")),
]
CRON_FILES = [Path("/etc/crontab")]
CRON_DIRS = [Path("/usr/lib/cron/tabs"), Path("/var/at/tabs")]


class MacOSPersistenceCollector:
    name = "platform_persistence"
    supported_platforms = ["macos"]
    requires_admin = False

    def collect(self, context: ScanContext) -> CollectorResult:
        launchd_artifacts, launchd_warnings = _collect_launchd()
        cron_artifacts, cron_warnings = _collect_cron()
        artifacts = [*launchd_artifacts, *cron_artifacts]
        warnings = [*launchd_warnings, *cron_warnings]
        return CollectorResult(
            collector_name=self.name,
            status="partial" if warnings else "ok",
            artifacts=artifacts,
            warnings=warnings,
            collected_at=utc_now_iso(),
        )


def _collect_launchd() -> tuple[list[dict[str, Any]], list[str]]:
    artifacts: list[dict[str, Any]] = []
    warnings: list[str] = []
    for source, directory in LAUNCHD_DIRS:
        if not directory.exists():
            continue
        for path in sorted(directory.glob("*.plist")):
            try:
                with path.open("rb") as handle:
                    plist = plistlib.load(handle)
            except (OSError, plistlib.InvalidFileException) as exc:
                warnings.append(f"Could not read launchd plist {path}: {exc}")
                continue
            command = _launchd_command(plist)
            artifact = PersistenceArtifact(
                artifact_id=stable_id("persistence", source, str(path), command),
                source=source,
                name=str(plist.get("Label") or path.stem),
                command=command,
                path=extract_executable_path(command),
                user=None,
                enabled=not bool(plist.get("Disabled", False)),
                last_modified=_mtime_iso(path),
            ).model_dump()
            artifact["definition_path"] = str(path)
            artifact["run_at_load"] = plist.get("RunAtLoad")
            artifact["keep_alive"] = plist.get("KeepAlive")
            artifacts.append(artifact)
    return artifacts, warnings


def _collect_cron() -> tuple[list[dict[str, Any]], list[str]]:
    artifacts: list[dict[str, Any]] = []
    warnings: list[str] = []
    paths = [path for path in CRON_FILES if path.exists()]
    for directory in CRON_DIRS:
        if directory.exists():
            paths.extend(path for path in sorted(directory.glob("*")) if path.is_file())
    for path in paths:
        try:
            for line_number, command in _cron_commands(path):
                artifacts.append(_cron_artifact(path, line_number, command))
        except PermissionError:
            warnings.append(f"Access denied reading cron file {path}")
        except OSError as exc:
            warnings.append(f"Could not read cron file {path}: {exc}")
    return artifacts, warnings


def _launchd_command(plist: dict[str, Any]) -> str | None:
    program_arguments = plist.get("ProgramArguments")
    if isinstance(program_arguments, list) and program_arguments:
        return " ".join(str(item) for item in program_arguments)
    program = plist.get("Program")
    if program:
        return str(program)
    return None


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


def _cron_artifact(path: Path, line_number: int, command: str) -> dict[str, Any]:
    artifact = PersistenceArtifact(
        artifact_id=stable_id("persistence", "macos_cron", str(path), line_number, command),
        source="macos_cron",
        name=path.name,
        command=command,
        path=extract_executable_path(command),
        user=None,
        enabled=True,
        last_modified=_mtime_iso(path),
    ).model_dump()
    artifact["definition_path"] = str(path)
    artifact["line_number"] = line_number
    return artifact


def _looks_like_env_assignment(value: str) -> bool:
    name, separator, _rest = value.partition("=")
    return bool(separator and name and name.replace("_", "").isalnum() and not name[0].isdigit())


def _mtime_iso(path: Path) -> str | None:
    try:
        return from_timestamp(path.stat().st_mtime)
    except OSError:
        return None
