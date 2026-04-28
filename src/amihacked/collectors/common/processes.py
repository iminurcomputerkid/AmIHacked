import psutil

from amihacked.core.models import CollectorResult, ProcessArtifact
from amihacked.core.scan_context import ScanContext
from amihacked.utils.hashing import sha256_file
from amihacked.utils.time import from_timestamp, utc_now_iso


class ProcessCollector:
    name = "processes"
    supported_platforms = ["windows", "linux", "macos"]
    requires_admin = True

    def collect(self, context: ScanContext) -> CollectorResult:
        artifacts: list[dict] = []
        warnings: list[str] = []

        process_names: dict[int, str] = {}
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                process_names[proc.info["pid"]] = proc.info.get("name") or ""
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        attrs = ["pid", "ppid", "name", "exe", "cmdline", "username", "create_time", "cwd", "memory_percent"]
        for proc in psutil.process_iter(attrs):
            try:
                info = proc.info
                exe_path = info.get("exe")
                command_line = " ".join(info.get("cmdline") or []) or None
                create_time = info.get("create_time")
                artifact = ProcessArtifact(
                    artifact_id=f"process:{info['pid']}",
                    pid=info["pid"],
                    ppid=info.get("ppid"),
                    name=info.get("name") or "unknown",
                    exe_path=exe_path,
                    command_line=command_line,
                    username=info.get("username"),
                    create_time=from_timestamp(create_time) if create_time else None,
                    cwd=info.get("cwd"),
                    cpu_percent=proc.cpu_percent(interval=None),
                    memory_percent=info.get("memory_percent"),
                    sha256=sha256_file(exe_path) if exe_path else None,
                    signed=None,
                    signer=None,
                    parent_name=process_names.get(info.get("ppid")) if info.get("ppid") is not None else None,
                )
                artifacts.append(artifact.model_dump())
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                continue
            except psutil.AccessDenied as exc:
                warnings.append(f"Access denied collecting process {proc.pid}: {exc}")
            except Exception as exc:
                warnings.append(f"Could not collect process {getattr(proc, 'pid', 'unknown')}: {exc}")

        return CollectorResult(
            collector_name=self.name,
            status="partial" if warnings else "ok",
            artifacts=artifacts,
            warnings=warnings,
            collected_at=utc_now_iso(),
        )
