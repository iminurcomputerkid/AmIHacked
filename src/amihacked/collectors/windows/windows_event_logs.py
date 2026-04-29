from amihacked.collectors.common.logs import LogCollector
from amihacked.core.models import CollectorResult
from amihacked.core.scan_context import ScanContext


class WindowsEventLogsCollector(LogCollector):
    name = "event_logs"
    supported_platforms = ["windows"]
    requires_admin = True

    def collect(self, context: ScanContext) -> CollectorResult:
        return self._collect_windows()
