import subprocess

import psutil

from amihacked.core.models import CollectorResult
from amihacked.core.scan_context import ScanContext
from amihacked.utils.ids import stable_id
from amihacked.utils.paths import extract_executable_path
from amihacked.utils.time import utc_now_iso


class WindowsServicesCollector:
    name = "services"
    supported_platforms = ["windows"]
    requires_admin = True

    def collect(self, context: ScanContext) -> CollectorResult:
        artifacts: list[dict] = []
        warnings: list[str] = []
        wmic_paths = _wmic_service_paths()
        if not wmic_paths:
            warnings.append("WMIC service path enrichment unavailable; service binary paths may be missing.")

        try:
            services = psutil.win_service_iter()
        except Exception as exc:
            return CollectorResult(
                collector_name=self.name,
                status="error",
                artifacts=[],
                errors=[f"Could not enumerate Windows services: {exc}"],
                collected_at=utc_now_iso(),
            )

        for service in services:
            try:
                info = service.as_dict()
            except Exception as exc:
                warnings.append(f"Could not read service {getattr(service, 'name', lambda: 'unknown')()}: {exc}")
                continue
            name = info.get("name") or service.name()
            command = wmic_paths.get(name) or info.get("binpath")
            artifact = {
                "artifact_id": stable_id("persistence", "service", name, command),
                "type": "persistence",
                "source": "service",
                "name": name,
                "command": command,
                "path": extract_executable_path(command),
                "user": info.get("username"),
                "enabled": _service_enabled(info.get("start_type")),
                "last_modified": None,
                "display_name": info.get("display_name"),
                "status": info.get("status"),
                "start_type": info.get("start_type"),
                "pid": info.get("pid"),
            }
            artifacts.append(artifact)

        return CollectorResult(
            collector_name=self.name,
            status="partial" if warnings else "ok",
            artifacts=artifacts,
            warnings=warnings,
            collected_at=utc_now_iso(),
        )


def _service_enabled(start_type: str | None) -> bool | None:
    if not start_type:
        return None
    lowered = start_type.lower()
    if lowered == "disabled":
        return False
    if lowered in {"automatic", "manual"}:
        return True
    return None


def _wmic_service_paths() -> dict[str, str]:
    try:
        completed = subprocess.run(
            ["wmic", "service", "get", "Name,PathName", "/format:csv"],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {}
    if completed.returncode != 0:
        return {}

    paths: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        if not line.strip() or line.lower().startswith("node,"):
            continue
        parts = line.split(",", 2)
        if len(parts) != 3:
            continue
        _node, name, path = parts
        if name and path:
            paths[name] = path
    return paths
