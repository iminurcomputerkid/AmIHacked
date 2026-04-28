from amihacked.core.models import CollectorResult
from amihacked.core.scan_context import ScanContext
from amihacked.utils.time import utc_now_iso


class LinuxServicesCollector:
    name = "linux_services"
    supported_platforms = ["linux"]
    requires_admin = False

    def collect(self, context: ScanContext) -> CollectorResult:
        return CollectorResult(
            collector_name=self.name,
            status="ok",
            artifacts=[],
            warnings=["Linux services collection is planned for a later version."],
            collected_at=utc_now_iso(),
        )

