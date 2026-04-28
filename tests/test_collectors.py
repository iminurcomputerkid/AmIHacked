from pathlib import Path

from amihacked.collectors.common.system import SystemCollector
from amihacked.core.scan_context import ScanContext


def test_system_collector_returns_host_artifact(tmp_path: Path):
    context = ScanContext(
        case_id="case-test",
        case_dir=tmp_path,
        started_at="2026-04-25T18:30:00Z",
        platform="linux",
        elevated=False,
    )

    result = SystemCollector().collect(context)

    assert result.collector_name == "system"
    assert result.artifacts
    assert result.artifacts[0]["artifact_id"] == "system:host"

