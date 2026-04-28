import os
from pathlib import Path
import shutil
import subprocess

from amihacked.core.models import CollectorResult, PersistenceArtifact
from amihacked.core.scan_context import ScanContext
from amihacked.utils.ids import stable_id
from amihacked.utils.time import utc_now_iso


STARTUP_FOLDERS = [
    ("user_startup_folder", "APPDATA", r"Microsoft\Windows\Start Menu\Programs\Startup"),
    ("all_users_startup_folder", "PROGRAMDATA", r"Microsoft\Windows\Start Menu\Programs\StartUp"),
]


class WindowsStartupItemsCollector:
    name = "startup_items"
    supported_platforms = ["windows"]
    requires_admin = True

    def collect(self, context: ScanContext) -> CollectorResult:
        artifacts: list[dict] = []
        warnings: list[str] = []
        for source, env_name, relative in STARTUP_FOLDERS:
            base = os.environ.get(env_name)
            if not base:
                warnings.append(f"Environment variable {env_name} is not set; skipped {source}.")
                continue
            folder = Path(base).joinpath(*relative.split("\\"))
            if not folder.exists():
                continue
            try:
                for item in sorted(folder.iterdir()):
                    if not item.is_file():
                        continue
                    target = _resolve_shortcut_target(item) if item.suffix.lower() == ".lnk" else None
                    artifact = PersistenceArtifact(
                        artifact_id=stable_id("persistence", "startup", source, str(item)),
                        source=source,
                        name=item.name,
                        command=target or str(item),
                        path=target or str(item),
                        user="all_users" if source.startswith("all_users") else None,
                        enabled=True,
                        last_modified=_mtime_iso(item),
                    ).model_dump()
                    artifact["startup_folder"] = str(folder)
                    artifacts.append(artifact)
            except PermissionError:
                warnings.append(f"Access denied reading startup folder {folder}")
            except OSError as exc:
                warnings.append(f"Could not read startup folder {folder}: {exc}")

        return CollectorResult(
            collector_name=self.name,
            status="partial" if warnings else "ok",
            artifacts=artifacts,
            warnings=warnings,
            collected_at=utc_now_iso(),
        )


def _mtime_iso(path: Path) -> str | None:
    try:
        from amihacked.utils.time import from_timestamp

        return from_timestamp(path.stat().st_mtime)
    except OSError:
        return None


def _resolve_shortcut_target(path: Path) -> str | None:
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if not powershell:
        return None
    escaped = str(path).replace("'", "''")
    command = (
        "$shell = New-Object -ComObject WScript.Shell; "
        f"$shortcut = $shell.CreateShortcut('{escaped}'); "
        "if ($shortcut.TargetPath) { $shortcut.TargetPath }"
    )
    try:
        completed = subprocess.run(
            [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0:
        return None
    target = completed.stdout.strip()
    return target or None
