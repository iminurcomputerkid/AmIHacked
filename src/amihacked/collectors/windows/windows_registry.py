from amihacked.core.models import CollectorResult, PersistenceArtifact
from amihacked.core.scan_context import ScanContext
from amihacked.utils.ids import stable_id
from amihacked.utils.paths import extract_executable_path
from amihacked.utils.time import utc_now_iso


REGISTRY_RUN_KEYS = [
    ("HKCU", "registry_run_key", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", "registry_runonce_key", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", "registry_run_key", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", "registry_runonce_key", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", "registry_run_key", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", "registry_runonce_key", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
]


class WindowsRegistryCollector:
    name = "registry_run_keys"
    supported_platforms = ["windows"]
    requires_admin = True

    def collect(self, context: ScanContext) -> CollectorResult:
        try:
            import winreg
        except ImportError:
            return CollectorResult(
                collector_name=self.name,
                status="error",
                artifacts=[],
                errors=["winreg is unavailable; registry collection only works on Windows."],
                collected_at=utc_now_iso(),
            )

        hive_map = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
        artifacts: list[dict] = []
        warnings: list[str] = []
        for hive_label, source, subkey in REGISTRY_RUN_KEYS:
            try:
                with winreg.OpenKey(hive_map[hive_label], subkey, 0, winreg.KEY_READ) as key:
                    index = 0
                    while True:
                        try:
                            name, value, value_type = winreg.EnumValue(key, index)
                        except OSError:
                            break
                        command = str(value) if value is not None else None
                        artifact = PersistenceArtifact(
                            artifact_id=stable_id("persistence", "registry", hive_label, subkey, name, command),
                            source=source,
                            name=name or "(Default)",
                            command=command,
                            path=extract_executable_path(command),
                            user=hive_label,
                            enabled=True,
                        ).model_dump()
                        artifact["registry_hive"] = hive_label
                        artifact["registry_path"] = rf"{hive_label}\{subkey}"
                        artifact["registry_value_type"] = value_type
                        artifacts.append(artifact)
                        index += 1
            except FileNotFoundError:
                continue
            except PermissionError:
                warnings.append(f"Access denied reading {hive_label}\\{subkey}")
            except OSError as exc:
                warnings.append(f"Could not read {hive_label}\\{subkey}: {exc}")

        return CollectorResult(
            collector_name=self.name,
            status="partial" if warnings else "ok",
            artifacts=artifacts,
            warnings=warnings,
            collected_at=utc_now_iso(),
        )
