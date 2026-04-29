import importlib
from typing import Any

from amihacked.core.models import CollectorResult, InstalledSoftwareArtifact
from amihacked.core.scan_context import ScanContext
from amihacked.utils.ids import stable_id
from amihacked.utils.time import utc_now_iso


UNINSTALL_PATH = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
WOW64_UNINSTALL_PATH = r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"


class WindowsInstalledSoftwareCollector:
    name = "installed_software"
    supported_platforms = ["windows"]
    requires_admin = False

    def collect(self, context: ScanContext) -> CollectorResult:
        try:
            winreg = importlib.import_module("winreg")
        except ImportError as exc:
            return CollectorResult(
                collector_name=self.name,
                status="error",
                artifacts=[],
                errors=[f"Windows registry module unavailable: {exc}"],
                collected_at=utc_now_iso(),
            )

        artifacts: list[dict[str, Any]] = []
        warnings: list[str] = []
        seen: set[tuple[str | None, str | None, str | None]] = set()
        for hive_name, hive, path in _registry_locations(winreg):
            try:
                items = _read_uninstall_key(winreg, hive, hive_name, path)
            except FileNotFoundError:
                continue
            except PermissionError:
                warnings.append(f"Access denied reading {hive_name}\\{path}")
                continue
            except OSError as exc:
                warnings.append(f"Could not read {hive_name}\\{path}: {exc}")
                continue
            for item in items:
                dedupe_key = (item.get("name"), item.get("version"), item.get("publisher"))
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)
                artifacts.append(item)

        return CollectorResult(
            collector_name=self.name,
            status="partial" if warnings else "ok",
            artifacts=artifacts,
            warnings=warnings,
            collected_at=utc_now_iso(),
        )


def _registry_locations(winreg) -> list[tuple[str, Any, str]]:
    return [
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, UNINSTALL_PATH),
        ("HKLM", winreg.HKEY_LOCAL_MACHINE, WOW64_UNINSTALL_PATH),
        ("HKCU", winreg.HKEY_CURRENT_USER, UNINSTALL_PATH),
    ]


def _read_uninstall_key(winreg, hive, hive_name: str, path: str) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    access = getattr(winreg, "KEY_READ", 0)
    with winreg.OpenKey(hive, path, 0, access) as root:
        index = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(root, index)
            except OSError:
                break
            index += 1
            subkey_path = f"{path}\\{subkey_name}"
            try:
                artifact = _read_uninstall_entry(winreg, hive, hive_name, subkey_path)
            except (FileNotFoundError, PermissionError, OSError):
                continue
            if artifact:
                artifacts.append(artifact)
    return artifacts


def _read_uninstall_entry(winreg, hive, hive_name: str, subkey_path: str) -> dict[str, Any] | None:
    access = getattr(winreg, "KEY_READ", 0)
    with winreg.OpenKey(hive, subkey_path, 0, access) as key:
        name = _read_value(winreg, key, "DisplayName")
        if not name:
            return None
        version = _read_value(winreg, key, "DisplayVersion")
        publisher = _read_value(winreg, key, "Publisher")
        return InstalledSoftwareArtifact(
            artifact_id=stable_id("installed_software", hive_name, subkey_path, name, version),
            source="registry_uninstall_key",
            name=str(name),
            version=_string_or_none(version),
            publisher=_string_or_none(publisher),
            install_date=_string_or_none(_read_value(winreg, key, "InstallDate")),
            install_location=_string_or_none(_read_value(winreg, key, "InstallLocation")),
            uninstall_string=_string_or_none(_read_value(winreg, key, "UninstallString")),
            quiet_uninstall_string=_string_or_none(_read_value(winreg, key, "QuietUninstallString")),
            registry_hive=hive_name,
            registry_path=subkey_path,
            system_component=_bool_or_none(_read_value(winreg, key, "SystemComponent")),
            windows_installer=_bool_or_none(_read_value(winreg, key, "WindowsInstaller")),
            estimated_size_kb=_int_or_none(_read_value(winreg, key, "EstimatedSize")),
        ).model_dump()


def _read_value(winreg, key, name: str) -> Any:
    try:
        value, _value_type = winreg.QueryValueEx(key, name)
    except OSError:
        return None
    return value


def _string_or_none(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def _int_or_none(value: Any) -> int | None:
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _bool_or_none(value: Any) -> bool | None:
    if value in (None, ""):
        return None
    try:
        return bool(int(value))
    except (TypeError, ValueError):
        return bool(value)
