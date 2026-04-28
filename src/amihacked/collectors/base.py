from typing import Protocol

from amihacked.core.models import CollectorResult
from amihacked.core.scan_context import ScanContext


class Collector(Protocol):
    name: str
    supported_platforms: list[str]
    requires_admin: bool

    def collect(self, context: ScanContext) -> CollectorResult:
        ...

