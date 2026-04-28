import json

from typer.testing import CliRunner

from amihacked.cli import app
from amihacked.core.models import Finding
from amihacked.detection.scoring import RiskScore
from amihacked.reporting.context import build_report_context, sort_findings
from amihacked.reporting.timeline import build_timeline


def test_timeline_combines_process_log_persistence_and_findings():
    finding = Finding(
        id="finding-1",
        title="Test Finding",
        severity="high",
        confidence=0.9,
        description="desc",
        evidence_type="process",
        evidence_refs=["process:1"],
        reason="reason",
    )
    evidence = {
        "process": [{"artifact_id": "process:1", "type": "process", "name": "bad.exe", "pid": 1, "create_time": "2026-04-28T01:00:00Z"}],
        "network": [],
        "log": [{"artifact_id": "log:1", "type": "log", "timestamp": "2026-04-28T01:01:00Z", "message": "log event"}],
        "persistence": [{"artifact_id": "persistence:1", "type": "persistence", "source": "service", "name": "svc", "last_modified": "2026-04-28T01:02:00Z"}],
    }

    timeline = build_timeline(evidence, [finding])

    assert [event["event_type"] for event in timeline] == ["process_start", "finding", "log_event", "persistence_modified"]


def test_report_context_sorts_and_groups_findings():
    low = _finding("low", "Low Finding", ["log:1"])
    high = _finding("high", "High Finding", ["process:1"])
    context = build_report_context(
        {"elevated": True},
        [low, high],
        {"process": [{"artifact_id": "process:1"}], "network": [], "log": [{"artifact_id": "log:1"}], "persistence": []},
        {},
        [],
    )

    assert sort_findings([low, high])[0].severity == "high"
    assert context["summary"]["severity_counts"]["high"] == 1
    assert "process:1" in context["finding_groups"]


def test_report_command_rebuilds_reports_from_existing_case(tmp_path):
    case = tmp_path / "case001"
    (case / "findings").mkdir(parents=True)
    (case / "normalized").mkdir()
    (case / "reports").mkdir()
    (case / "metadata.json").write_text(json.dumps({"case_id": "case001", "elevated": True}), encoding="utf-8")
    (case / "findings" / "findings.json").write_text(json.dumps([_finding("high", "High Finding", ["process:1"]).model_dump()]), encoding="utf-8")
    (case / "findings" / "risk_score.json").write_text(RiskScore(score=25, level="Moderate", reasons=[]).model_dump_json(), encoding="utf-8")
    (case / "normalized" / "processes.normalized.json").write_text(json.dumps([{"artifact_id": "process:1", "type": "process", "name": "bad.exe", "pid": 1}]), encoding="utf-8")
    (case / "normalized" / "network.normalized.json").write_text("[]", encoding="utf-8")
    (case / "normalized" / "logs.normalized.json").write_text("[]", encoding="utf-8")
    (case / "normalized" / "persistence.normalized.json").write_text("[]", encoding="utf-8")

    result = CliRunner().invoke(app, ["report", str(case)])

    assert result.exit_code == 0
    assert (case / "reports" / "report.html").exists()
    report = json.loads((case / "reports" / "report.json").read_text(encoding="utf-8"))
    assert "report_context" in report
    assert report["report_context"]["summary"]["finding_count"] == 1


def _finding(severity: str, title: str, refs: list[str]) -> Finding:
    return Finding(
        id=f"finding-{severity}",
        title=title,
        severity=severity,
        confidence=0.8,
        description="desc",
        evidence_type="test",
        evidence_refs=refs,
        reason="reason",
    )
