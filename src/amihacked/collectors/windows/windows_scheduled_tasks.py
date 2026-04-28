from amihacked.core.models import CollectorResult
from amihacked.core.scan_context import ScanContext
from amihacked.utils.time import utc_now_iso


class WindowsScheduledTasksCollector:
    name = "scheduled_tasks"
    supported_platforms = ["windows"]
    requires_admin = False

    def collect(self, context: ScanContext) -> CollectorResult:
        return CollectorResult(
            collector_name=self.name,
            status="ok",
            artifacts=[],
            warnings=["Windows scheduled task collection is planned for v0.3."],
            collected_at=utc_now_iso(),
        )

