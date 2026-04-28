import csv
import subprocess
from io import StringIO

from amihacked.core.models import CollectorResult
from amihacked.core.scan_context import ScanContext
from amihacked.utils.ids import stable_id
from amihacked.utils.paths import extract_executable_path
from amihacked.utils.time import utc_now_iso


class WindowsScheduledTasksCollector:
    name = "scheduled_tasks"
    supported_platforms = ["windows"]
    requires_admin = True

    def collect(self, context: ScanContext) -> CollectorResult:
        try:
            completed = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV", "/v"],
                check=False,
                capture_output=True,
                text=True,
                timeout=180,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return CollectorResult(
                collector_name=self.name,
                status="error",
                artifacts=[],
                errors=[f"Could not execute schtasks: {exc}"],
                collected_at=utc_now_iso(),
            )

        warnings: list[str] = []
        if completed.returncode != 0:
            return CollectorResult(
                collector_name=self.name,
                status="error",
                artifacts=[],
                errors=[completed.stderr.strip() or "schtasks returned a non-zero exit code."],
                collected_at=utc_now_iso(),
            )

        artifacts: list[dict] = []
        reader = csv.DictReader(StringIO(completed.stdout))
        for row in reader:
            name = row.get("TaskName") or row.get("Task Name") or ""
            command = row.get("Task To Run") or row.get("Task To Run ") or row.get("Actions")
            enabled = _task_enabled(row)
            artifact = {
                "artifact_id": stable_id("persistence", "scheduled_task", name, command),
                "type": "persistence",
                "source": "scheduled_task",
                "name": name,
                "command": command,
                "path": extract_executable_path(command),
                "user": row.get("Run As User"),
                "enabled": enabled,
                "last_modified": None,
                "task_status": row.get("Status"),
                "schedule_type": row.get("Schedule Type"),
                "last_run_time": row.get("Last Run Time"),
                "next_run_time": row.get("Next Run Time"),
            }
            artifacts.append(artifact)

        return CollectorResult(
            collector_name=self.name,
            status="partial" if warnings else "ok",
            artifacts=artifacts,
            warnings=warnings,
            collected_at=utc_now_iso(),
        )


def _task_enabled(row: dict[str, str]) -> bool | None:
    status = (row.get("Scheduled Task State") or row.get("Status") or "").lower()
    if "disabled" in status:
        return False
    if "enabled" in status or "ready" in status or "running" in status:
        return True
    return None
