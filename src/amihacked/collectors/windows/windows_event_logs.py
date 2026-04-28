from amihacked.core.models import CollectorResult
from amihacked.core.scan_context import ScanContext
from amihacked.utils.time import utc_now_iso


class WindowsEventLogsCollector:
    name = "event_logs"
    supported_platforms = ["windows"]
    requires_admin = True

    def collect(self, context: ScanContext) -> CollectorResult:
        return CollectorResult(
            collector_name=self.name,
            status="ok",
            artifacts=[],
            warnings=["Windows event log collection is planned for a later version."],
            collected_at=utc_now_iso(),
        )

