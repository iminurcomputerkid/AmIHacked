from amihacked.core.models import CollectorResult
from amihacked.core.scan_context import ScanContext
from amihacked.utils.time import utc_now_iso


class MacOSPersistenceCollector:
    name = "macos_persistence"
    supported_platforms = ["macos"]
    requires_admin = False

    def collect(self, context: ScanContext) -> CollectorResult:
        return CollectorResult(
            collector_name=self.name,
            status="ok",
            artifacts=[],
            warnings=["macOS persistence collection is planned for a later version."],
            collected_at=utc_now_iso(),
        )

