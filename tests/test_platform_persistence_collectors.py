import plistlib
from pathlib import Path

from amihacked.collectors.linux.linux_persistence import LinuxPersistenceCollector
from amihacked.collectors.linux.linux_services import LinuxServicesCollector
from amihacked.collectors.macos.macos_persistence import MacOSPersistenceCollector
from amihacked.core.scan_context import ScanContext


def test_linux_services_collector_reads_systemd_unit_file(monkeypatch, tmp_path):
    unit_dir = tmp_path / "systemd"
    unit_dir.mkdir()
    unit_file = unit_dir / "bad.service"
    unit_file.write_text(
        "\n".join(
            [
                "[Unit]",
                "Description=Bad Service",
                "[Service]",
                "ExecStart=/tmp/bad --flag",
                "User=alice",
                "[Install]",
                "WantedBy=multi-user.target",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("amihacked.collectors.linux.linux_services.SYSTEMD_UNIT_DIRS", [unit_dir])
    monkeypatch.setattr("amihacked.collectors.linux.linux_services.shutil.which", lambda _name: None)

    result = LinuxServicesCollector().collect(_context(tmp_path, "linux"))

    assert result.artifacts
    assert result.artifacts[0]["source"] == "linux_service"
    assert result.artifacts[0]["name"] == "bad.service"
    assert result.artifacts[0]["path"] == "/tmp/bad"
    assert result.artifacts[0]["enabled"] is True


def test_linux_persistence_collector_reads_cron_and_xdg_autostart(monkeypatch, tmp_path):
    cron_file = tmp_path / "crontab"
    cron_file.write_text("*/5 * * * * root /tmp/job --run\n", encoding="utf-8")
    autostart_dir = tmp_path / "autostart"
    autostart_dir.mkdir()
    (autostart_dir / "updater.desktop").write_text("[Desktop Entry]\nExec=/tmp/updater --start\n", encoding="utf-8")
    monkeypatch.setattr("amihacked.collectors.linux.linux_persistence.CRON_FILES", [cron_file])
    monkeypatch.setattr("amihacked.collectors.linux.linux_persistence.CRON_DIRS", [])
    monkeypatch.setattr("amihacked.collectors.linux.linux_persistence.AUTOSTART_DIRS", [autostart_dir])

    result = LinuxPersistenceCollector().collect(_context(tmp_path, "linux"))

    sources = {artifact["source"] for artifact in result.artifacts}
    assert sources == {"linux_cron", "linux_xdg_autostart"}
    assert any(artifact["path"] == "/tmp/job" for artifact in result.artifacts)
    assert any(artifact["path"] == "/tmp/updater" for artifact in result.artifacts)


def test_macos_persistence_collector_reads_launchd_plist(monkeypatch, tmp_path):
    launchd_dir = tmp_path / "LaunchAgents"
    launchd_dir.mkdir()
    plist_path = launchd_dir / "com.example.agent.plist"
    plist_path.write_bytes(
        plistlib.dumps(
            {
                "Label": "com.example.agent",
                "ProgramArguments": ["/tmp/agent", "--run"],
                "RunAtLoad": True,
            }
        )
    )
    monkeypatch.setattr(
        "amihacked.collectors.macos.macos_persistence.LAUNCHD_DIRS",
        [("user_launch_agent", launchd_dir)],
    )
    monkeypatch.setattr("amihacked.collectors.macos.macos_persistence.CRON_FILES", [])
    monkeypatch.setattr("amihacked.collectors.macos.macos_persistence.CRON_DIRS", [])

    result = MacOSPersistenceCollector().collect(_context(tmp_path, "macos"))

    assert result.artifacts
    assert result.artifacts[0]["source"] == "user_launch_agent"
    assert result.artifacts[0]["name"] == "com.example.agent"
    assert result.artifacts[0]["path"] == "/tmp/agent"
    assert result.artifacts[0]["run_at_load"] is True


def _context(tmp_path: Path, platform: str) -> ScanContext:
    return ScanContext(
        case_id="case-test",
        case_dir=tmp_path,
        started_at="2026-04-25T18:30:00Z",
        platform=platform,
        elevated=True,
    )
