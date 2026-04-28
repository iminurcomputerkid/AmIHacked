from collections import deque
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
import json
import platform
import shutil
import subprocess

from amihacked.core.models import CollectorResult, LogEventArtifact
from amihacked.core.scan_context import ScanContext
from amihacked.utils.time import utc_now_iso


LINUX_LOG_SOURCES = [
    (Path("/var/log/auth.log"), "authentication", "auth.log"),
    (Path("/var/log/secure"), "authentication", "secure"),
    (Path("/var/log/syslog"), "system", "syslog"),
    (Path("/var/log/messages"), "system", "messages"),
    (Path("/var/log/audit/audit.log"), "audit", "audit.log"),
    (Path("/var/log/kern.log"), "kernel", "kern.log"),
    (Path("/var/log/dpkg.log"), "application", "dpkg.log"),
]

MACOS_LOG_SOURCES = [
    (Path("/var/log/system.log"), "system", "system.log"),
    (Path("/var/log/install.log"), "application", "install.log"),
]

WINDOWS_EVENT_QUERIES = {
    "Security": [4624, 4625, 4634, 4648, 4672, 4688, 4697, 4698, 4720, 4728, 4732, 7045],
    "System": [7036, 7040, 7045, 6005, 6006, 6008],
    "Application": [],
    "Windows PowerShell": [400, 403, 600, 800],
    "Microsoft-Windows-PowerShell/Operational": [4103, 4104],
    "Microsoft-Windows-Windows Defender/Operational": [1116, 1117, 5007],
}


class LogCollector:
    name = "log_events"
    supported_platforms = ["windows", "linux", "macos"]
    requires_admin = True

    def __init__(self, max_lines_per_file: int = 5000, max_windows_events_per_log: int = 500) -> None:
        self.max_lines_per_file = max_lines_per_file
        self.max_windows_events_per_log = max_windows_events_per_log

    def collect(self, context: ScanContext) -> CollectorResult:
        system = platform.system().lower()
        if system.startswith("win"):
            return self._collect_windows()
        if system == "darwin":
            return self._collect_file_logs(MACOS_LOG_SOURCES)
        return self._collect_linux()

    def _collect_linux(self) -> CollectorResult:
        journal_result = self._collect_systemd_journal()
        file_result = self._collect_file_logs(LINUX_LOG_SOURCES)
        artifacts = [*journal_result.artifacts, *file_result.artifacts]
        warnings = [*journal_result.warnings, *file_result.warnings]
        if not artifacts:
            warnings.append(
                "No Linux log events were collected. This usually means classic /var/log sources are absent/empty "
                "and systemd journal access is unavailable or empty for this account."
            )
        return CollectorResult(
            collector_name=self.name,
            status="partial" if warnings else "ok",
            artifacts=artifacts,
            warnings=warnings,
            collected_at=utc_now_iso(),
        )

    def _collect_systemd_journal(self) -> CollectorResult:
        journalctl = shutil.which("journalctl")
        if not journalctl:
            return CollectorResult(
                collector_name=self.name,
                status="partial",
                artifacts=[],
                warnings=["journalctl was not found; systemd journal collection was skipped."],
                collected_at=utc_now_iso(),
            )

        try:
            completed = subprocess.run(
                [journalctl, "--no-pager", "--output=json", f"--lines={self.max_lines_per_file}"],
                check=False,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return CollectorResult(
                collector_name=self.name,
                status="partial",
                artifacts=[],
                warnings=[f"Could not query systemd journal: {exc}"],
                collected_at=utc_now_iso(),
            )

        warnings: list[str] = []
        if completed.returncode != 0:
            stderr = completed.stderr.strip()
            warnings.append(f"journalctl returned {completed.returncode}: {stderr or 'no stderr'}")
            return CollectorResult(
                collector_name=self.name,
                status="partial",
                artifacts=[],
                warnings=warnings,
                collected_at=utc_now_iso(),
            )

        artifacts: list[dict] = []
        for index, line in enumerate(completed.stdout.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                warnings.append(f"Could not parse journalctl JSON line {index}.")
                continue
            message = _coerce_log_message(row.get("MESSAGE"))
            timestamp = _journal_timestamp(row.get("__REALTIME_TIMESTAMP"))
            provider = row.get("SYSLOG_IDENTIFIER") or row.get("_SYSTEMD_UNIT") or row.get("_COMM")
            channel = row.get("_TRANSPORT") or row.get("_SYSTEMD_UNIT") or "journal"
            record = row.get("__CURSOR") or index
            artifact_id = _log_artifact_id("systemd_journal", channel, record, message)
            artifacts.append(
                LogEventArtifact(
                    artifact_id=artifact_id,
                    source="systemd_journal",
                    channel=channel,
                    provider=provider,
                    event_id=row.get("PRIORITY"),
                    record_id=record,
                    timestamp=timestamp,
                    computer=row.get("_HOSTNAME"),
                    username=row.get("_UID"),
                    level=row.get("PRIORITY"),
                    message=message,
                    raw=row,
                ).model_dump()
            )

        return CollectorResult(
            collector_name=self.name,
            status="partial" if warnings else "ok",
            artifacts=artifacts,
            warnings=warnings,
            collected_at=utc_now_iso(),
        )

    def _collect_file_logs(self, sources: list[tuple[Path, str, str]]) -> CollectorResult:
        artifacts: list[dict] = []
        warnings: list[str] = []
        for path, source, channel in sources:
            if not path.exists():
                continue
            try:
                for line_number, line in _tail_lines(path, self.max_lines_per_file):
                    raw_line = line.rstrip("\n")
                    if not raw_line:
                        continue
                    artifact_id = _log_artifact_id(source, channel, line_number, raw_line)
                    artifacts.append(
                        LogEventArtifact(
                            artifact_id=artifact_id,
                            source=source,
                            channel=channel,
                            message=raw_line,
                            raw={"path": str(path), "line_number": line_number, "line": raw_line},
                        ).model_dump()
                    )
            except PermissionError:
                warnings.append(f"Access denied reading {path}")
            except OSError as exc:
                warnings.append(f"Could not read {path}: {exc}")

        if not artifacts and not warnings:
            checked = ", ".join(str(path) for path, _source, _channel in sources)
            warnings.append(f"No readable non-empty file-backed logs found in configured sources: {checked}")

        return CollectorResult(
            collector_name=self.name,
            status="partial" if warnings else "ok",
            artifacts=artifacts,
            warnings=warnings,
            collected_at=utc_now_iso(),
        )

    def _collect_windows(self) -> CollectorResult:
        powershell = shutil.which("powershell") or shutil.which("pwsh")
        if not powershell:
            return CollectorResult(
                collector_name=self.name,
                status="partial",
                artifacts=[],
                warnings=["PowerShell was not found; Windows Event Log collection could not run."],
                collected_at=utc_now_iso(),
            )

        artifacts: list[dict] = []
        warnings: list[str] = []
        for log_name, event_ids in WINDOWS_EVENT_QUERIES.items():
            command = _windows_event_command(log_name, event_ids, self.max_windows_events_per_log)
            try:
                completed = subprocess.run(
                    [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                warnings.append(f"Could not query Windows Event Log {log_name}: {exc}")
                continue

            if completed.returncode != 0:
                stderr = completed.stderr.strip()
                if stderr:
                    warnings.append(f"Windows Event Log {log_name}: {stderr}")
                continue

            try:
                rows = json.loads(completed.stdout) if completed.stdout.strip() else []
            except json.JSONDecodeError as exc:
                warnings.append(f"Could not parse Windows Event Log {log_name}: {exc}")
                continue
            if isinstance(rows, dict):
                rows = [rows]

            for row in rows:
                artifact_id = _log_artifact_id("windows_event_log", log_name, row.get("RecordId"), row.get("Message"))
                artifacts.append(
                    LogEventArtifact(
                        artifact_id=artifact_id,
                        source="windows_event_log",
                        channel=log_name,
                        provider=row.get("ProviderName"),
                        event_id=row.get("Id"),
                        record_id=row.get("RecordId"),
                        timestamp=row.get("TimeCreated"),
                        computer=row.get("MachineName"),
                        level=row.get("LevelDisplayName"),
                        message=row.get("Message"),
                        raw=row,
                    ).model_dump()
                )

        return CollectorResult(
            collector_name=self.name,
            status="partial" if warnings else "ok",
            artifacts=artifacts,
            warnings=warnings,
            collected_at=utc_now_iso(),
        )


def _tail_lines(path: Path, max_lines: int) -> list[tuple[int, str]]:
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        lines = deque(enumerate(handle, start=1), maxlen=max_lines)
    return list(lines)


def _log_artifact_id(source: str, channel: str, record: object, message: object) -> str:
    material = f"{source}|{channel}|{record}|{message}"
    return f"log:{sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _journal_timestamp(value: object) -> str | None:
    if value is None:
        return None
    try:
        seconds = int(str(value)) / 1_000_000
    except ValueError:
        return None
    return datetime.fromtimestamp(seconds, timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _coerce_log_message(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    if isinstance(value, list) and all(isinstance(item, int) for item in value):
        try:
            return bytes(value).decode("utf-8", errors="replace")
        except ValueError:
            return json.dumps(value)
    return json.dumps(value, sort_keys=True)


def _windows_event_command(log_name: str, event_ids: list[int], max_events: int) -> str:
    escaped_log = log_name.replace("'", "''")
    id_clause = ""
    if event_ids:
        ids = ",".join(str(event_id) for event_id in event_ids)
        id_clause = f"; ID={ids}"
    return (
        f"$events = Get-WinEvent -FilterHashtable @{{LogName='{escaped_log}'{id_clause}}} "
        f"-MaxEvents {max_events} -ErrorAction SilentlyContinue; "
        "$events | Select-Object LogName,ProviderName,Id,RecordId,TimeCreated,MachineName,"
        "LevelDisplayName,Message | ConvertTo-Json -Depth 4"
    )
