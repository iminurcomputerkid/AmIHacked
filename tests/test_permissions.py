import os

from typer.testing import CliRunner

from amihacked.cli import app
from amihacked.core.permissions import _windows_elevated_command


def test_scan_requires_elevation_by_default(monkeypatch):
    runner = CliRunner()

    monkeypatch.setattr("amihacked.cli.elevation_status", lambda: _status(elevated=False))
    monkeypatch.setattr("amihacked.cli.relaunch_with_elevation", lambda: False)

    result = runner.invoke(app, ["scan", "--no-auto-elevate"])

    assert result.exit_code == 2
    assert "requires elevated privileges" in result.output


def test_scan_allows_explicit_unelevated_mode(tmp_path, monkeypatch):
    runner = CliRunner()

    monkeypatch.setattr("amihacked.cli.elevation_status", lambda: _status(elevated=False))
    monkeypatch.setattr("amihacked.cli.is_elevated", lambda: False)
    monkeypatch.setattr("amihacked.cli.SystemCollector.collect", lambda self, context: _result("system", [{"artifact_id": "system:host"}]))
    monkeypatch.setattr("amihacked.cli.ProcessCollector.collect", lambda self, context: _result("processes", []))
    monkeypatch.setattr("amihacked.cli.NetworkCollector.collect", lambda self, context: _result("network_connections", []))
    monkeypatch.setattr("amihacked.cli.LogCollector.collect", lambda self, context: _result("log_events", []))

    result = runner.invoke(app, ["scan", "--allow-unelevated", "--output", str(tmp_path / "case")])

    assert result.exit_code == 0
    assert "Running unelevated" in result.output
    assert (tmp_path / "case" / "metadata.json").exists()


def test_windows_elevated_command_for_module_invocation(monkeypatch):
    monkeypatch.setattr("sys.argv", ["amihacked", "scan", "--full"])

    executable, args = _windows_elevated_command()

    assert executable
    assert args == ["-m", "amihacked", "scan", "--full"]


def _status(elevated: bool):
    from amihacked.core.permissions import ElevationStatus

    return ElevationStatus(
        elevated=elevated,
        platform="linux",
        required_account="root",
        can_auto_elevate=False,
        guidance="Run sudo amihacked scan.",
    )


def _result(name: str, artifacts: list[dict]):
    from amihacked.core.models import CollectorResult

    return CollectorResult(
        collector_name=name,
        status="ok",
        artifacts=artifacts,
        collected_at="2026-04-25T18:30:00Z",
    )
