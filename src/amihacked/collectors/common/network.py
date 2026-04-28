import socket

import psutil

from amihacked.core.models import CollectorResult, NetworkConnectionArtifact
from amihacked.core.scan_context import ScanContext
from amihacked.utils.ip_utils import is_public_ip
from amihacked.utils.time import utc_now_iso


class NetworkCollector:
    name = "network_connections"
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

        try:
            connections = psutil.net_connections(kind="inet")
        except psutil.AccessDenied as exc:
            connections = []
            warnings.append(f"Access denied enumerating network connections: {exc}")

        for index, connection in enumerate(connections):
            local_address, local_port = self._split_address(connection.laddr)
            remote_address, remote_port = self._split_address(connection.raddr)
            protocol = self._protocol_name(connection.type)
            pid = connection.pid
            remote_token = remote_address or "none"
            remote_port_token = remote_port if remote_port is not None else "none"
            local_port_token = local_port if local_port is not None else "none"
            artifact = NetworkConnectionArtifact(
                artifact_id=f"network:{pid or 'unknown'}:{remote_token}:{remote_port_token}:{local_port_token}:{index}",
                pid=pid,
                process_name=process_names.get(pid) if pid else None,
                local_address=local_address,
                local_port=local_port,
                remote_address=remote_address,
                remote_port=remote_port,
                status=connection.status,
                protocol=protocol,
                is_public_remote=is_public_ip(remote_address),
            )
            artifacts.append(artifact.model_dump())

        return CollectorResult(
            collector_name=self.name,
            status="partial" if warnings else "ok",
            artifacts=artifacts,
            warnings=warnings,
            collected_at=utc_now_iso(),
        )

    @staticmethod
    def _split_address(address) -> tuple[str | None, int | None]:
        if not address:
            return None, None
        return getattr(address, "ip", None), getattr(address, "port", None)

    @staticmethod
    def _protocol_name(sock_type: int) -> str | None:
        if sock_type == socket.SOCK_STREAM:
            return "tcp"
        if sock_type == socket.SOCK_DGRAM:
            return "udp"
        return None
