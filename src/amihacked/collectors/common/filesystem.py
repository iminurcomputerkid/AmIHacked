from amihacked.core.models import CollectorResult
from amihacked.core.scan_context import ScanContext
from amihacked.utils.time import utc_now_iso


class FilesystemCollector:
    name = "filesystem"
    supported_platforms = ["windows", "linux", "macos"]
    requires_admin = False

    def collect(self, context: ScanContext) -> CollectorResult:
        return CollectorResult(
            collector_name=self.name,
            status="ok",
            artifacts=[],
            warnings=["Filesystem collection is not implemented in v0.1."],
            collected_at=utc_now_iso(),
        )

