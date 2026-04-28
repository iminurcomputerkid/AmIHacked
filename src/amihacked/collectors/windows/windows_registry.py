from amihacked.core.models import CollectorResult
from amihacked.core.scan_context import ScanContext
from amihacked.utils.time import utc_now_iso


class WindowsRegistryCollector:
    name = "registry_run_keys"
    supported_platforms = ["windows"]
    requires_admin = False

    def collect(self, context: ScanContext) -> CollectorResult:
        return CollectorResult(
            collector_name=self.name,
            status="ok",
            artifacts=[],
            warnings=["Windows registry collection is planned for v0.3."],
            collected_at=utc_now_iso(),
        )

