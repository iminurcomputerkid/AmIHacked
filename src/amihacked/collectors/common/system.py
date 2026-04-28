import getpass
import platform
import socket
import time

import psutil

from amihacked.core.models import CollectorResult
from amihacked.core.permissions import is_elevated
from amihacked.core.scan_context import ScanContext
from amihacked.utils.time import from_timestamp, utc_now_iso


class SystemCollector:
    name = "system"
    supported_platforms = ["windows", "linux", "macos"]
    requires_admin = False

    def collect(self, context: ScanContext) -> CollectorResult:
        errors: list[str] = []
        warnings: list[str] = []

        try:
            hostname = socket.gethostname()
        except OSError as exc:
            hostname = "unknown"
            errors.append(str(exc))

        local_ips: list[str] = []
        try:
            for addresses in psutil.net_if_addrs().values():
                for address in addresses:
                    if address.family == socket.AF_INET and address.address:
                        local_ips.append(address.address)
        except Exception as exc:
            warnings.append(f"Could not enumerate local IP addresses: {exc}")

        artifact = {
            "artifact_id": "system:host",
            "type": "system",
            "hostname": hostname,
            "os": platform.system(),
            "os_version": platform.version(),
            "platform": platform.platform(),
            "architecture": platform.machine(),
            "boot_time": from_timestamp(psutil.boot_time()),
            "current_user": getpass.getuser(),
            "domain_or_workgroup": None,
            "timezone": time.tzname[0] if time.tzname else None,
            "local_ips": sorted(set(local_ips)),
            "admin_elevated": is_elevated(),
        }

        return CollectorResult(
            collector_name=self.name,
            status="partial" if errors else "ok",
            artifacts=[artifact],
            errors=errors,
            warnings=warnings,
            collected_at=utc_now_iso(),
        )

