import json
import subprocess

from amihacked.collectors.common.logs import LogCollector
from amihacked.collectors.windows.windows_event_logs import WindowsEventLogsCollector
from amihacked.core.scan_context import ScanContext


def test_systemd_journal_rows_become_log_artifacts(monkeypatch, tmp_path):
    row = {
        "__CURSOR": "cursor-1",
        "__REALTIME_TIMESTAMP": "1760000000000000",
        "_HOSTNAME": "host1",
        "_TRANSPORT": "syslog",
        "SYSLOG_IDENTIFIER": "sshd",
        "PRIORITY": "5",
        "MESSAGE": "Failed password for invalid user admin",
    }

    monkeypatch.setattr("amihacked.collectors.common.logs.shutil.which", lambda name: "/usr/bin/journalctl")
    monkeypatch.setattr(
        "amihacked.collectors.common.logs.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args=args, returncode=0, stdout=json.dumps(row) + "\n", stderr=""),
    )
    monkeypatch.setattr("amihacked.collectors.common.logs.LINUX_LOG_SOURCES", [])

    result = LogCollector(max_lines_per_file=10).collect(_context(tmp_path))

    assert result.artifacts
    assert result.artifacts[0]["source"] == "systemd_journal"
    assert result.artifacts[0]["provider"] == "sshd"
    assert "Failed password" in result.artifacts[0]["message"]


def test_linux_log_collector_warns_when_no_sources_yield_events(monkeypatch, tmp_path):
    monkeypatch.setattr("amihacked.collectors.common.logs.shutil.which", lambda name: None)
    monkeypatch.setattr("amihacked.collectors.common.logs.LINUX_LOG_SOURCES", [])

    result = LogCollector(max_lines_per_file=10).collect(_context(tmp_path))

    assert result.status == "partial"
    assert result.artifacts == []
    assert any("No Linux log events" in warning for warning in result.warnings)


def test_systemd_journal_byte_array_message_is_preserved(monkeypatch, tmp_path):
    row = {
        "__CURSOR": "cursor-2",
        "_TRANSPORT": "stdout",
        "PRIORITY": "6",
        "MESSAGE": [70, 97, 105, 108, 101, 100],
    }

    monkeypatch.setattr("amihacked.collectors.common.logs.shutil.which", lambda name: "/usr/bin/journalctl")
    monkeypatch.setattr(
        "amihacked.collectors.common.logs.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args=args, returncode=0, stdout=json.dumps(row) + "\n", stderr=""),
    )
    monkeypatch.setattr("amihacked.collectors.common.logs.LINUX_LOG_SOURCES", [])

    result = LogCollector(max_lines_per_file=10).collect(_context(tmp_path))

    assert result.artifacts[0]["message"] == "Failed"


def test_windows_event_logs_collector_wraps_common_windows_log_query(monkeypatch, tmp_path):
    row = {
        "LogName": "Security",
        "ProviderName": "Microsoft-Windows-Security-Auditing",
        "Id": 4625,
        "RecordId": 10,
        "TimeCreated": "2026-04-28T01:00:00Z",
        "MachineName": "HOST",
        "LevelDisplayName": "Information",
        "Message": "An account failed to log on.",
    }
    monkeypatch.setattr("amihacked.collectors.common.logs.shutil.which", lambda name: "powershell")
    monkeypatch.setattr(
        "amihacked.collectors.common.logs.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args=args, returncode=0, stdout=json.dumps([row]), stderr=""),
    )

    result = WindowsEventLogsCollector(max_windows_events_per_log=1).collect(
        ScanContext(
            case_id="case-test",
            case_dir=tmp_path,
            started_at="2026-04-25T18:30:00Z",
            platform="windows",
            elevated=True,
        )
    )

    assert result.collector_name == "event_logs"
    assert result.artifacts
    assert result.artifacts[0]["source"] == "windows_event_log"


def _context(tmp_path):
    return ScanContext(
        case_id="case-test",
        case_dir=tmp_path,
        started_at="2026-04-25T18:30:00Z",
        platform="linux",
        elevated=True,
    )
