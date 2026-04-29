import importlib
import json
import shutil
import subprocess
from typing import Any

from amihacked.core.models import CollectorResult, SecurityPostureArtifact
from amihacked.core.scan_context import ScanContext
from amihacked.utils.ids import stable_id
from amihacked.utils.time import utc_now_iso


UAC_REGISTRY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Policies\System"
DEFENDER_FEATURES_PATH = r"SOFTWARE\Microsoft\Windows Defender\Features"


class WindowsSecurityPostureCollector:
    name = "security_posture"
    supported_platforms = ["windows"]
    requires_admin = False

    def collect(self, context: ScanContext) -> CollectorResult:
        artifacts: list[dict[str, Any]] = []
        warnings: list[str] = []

        defender = _collect_defender_status()
        if defender is None:
            warnings.append("Microsoft Defender status unavailable through PowerShell.")
        else:
            artifacts.append(_defender_artifact(defender))

        firewall_profiles = _collect_firewall_profiles()
        if firewall_profiles is None:
            warnings.append("Windows Firewall profiles unavailable through PowerShell.")
        else:
            artifacts.extend(_firewall_artifacts(firewall_profiles))

        antivirus_products = _collect_security_center_antivirus()
        if antivirus_products:
            artifacts.extend(_antivirus_artifacts(antivirus_products))

        registry_artifacts, registry_warnings = _collect_registry_posture()
        artifacts.extend(registry_artifacts)
        warnings.extend(registry_warnings)

        return CollectorResult(
            collector_name=self.name,
            status="partial" if warnings else "ok",
            artifacts=artifacts,
            warnings=warnings,
            collected_at=utc_now_iso(),
        )


def _collect_defender_status() -> dict[str, Any] | None:
    command = (
        "if (Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue) { "
        "Get-MpComputerStatus | Select-Object "
        "AMServiceEnabled,AntivirusEnabled,AntispywareEnabled,RealTimeProtectionEnabled,"
        "BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,OnAccessProtectionEnabled,"
        "IsTamperProtected,AntivirusSignatureLastUpdated,QuickScanAge,FullScanAge "
        "| ConvertTo-Json -Depth 4 }"
    )
    payload = _run_powershell_json(command)
    return payload if isinstance(payload, dict) else None


def _collect_firewall_profiles() -> list[dict[str, Any]] | None:
    command = (
        "if (Get-Command Get-NetFirewallProfile -ErrorAction SilentlyContinue) { "
        "Get-NetFirewallProfile | Select-Object "
        "Name,Enabled,DefaultInboundAction,DefaultOutboundAction,NotifyOnListen,"
        "LogFileName,LogAllowed,LogBlocked | ConvertTo-Json -Depth 4 }"
    )
    payload = _run_powershell_json(command)
    return _json_items(payload)


def _collect_security_center_antivirus() -> list[dict[str, Any]] | None:
    command = (
        "try { "
        "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct "
        "| Select-Object displayName,instanceGuid,pathToSignedProductExe,pathToSignedReportingExe,"
        "productState,timestamp | ConvertTo-Json -Depth 4 "
        "} catch {}"
    )
    payload = _run_powershell_json(command)
    return _json_items(payload)


def _collect_registry_posture() -> tuple[list[dict[str, Any]], list[str]]:
    try:
        winreg = importlib.import_module("winreg")
    except ImportError:
        return [], ["Windows registry module unavailable for security posture checks."]

    artifacts: list[dict[str, Any]] = []
    warnings: list[str] = []
    uac_values = _read_registry_values(
        winreg,
        winreg.HKEY_LOCAL_MACHINE,
        UAC_REGISTRY_PATH,
        ["EnableLUA", "ConsentPromptBehaviorAdmin", "PromptOnSecureDesktop"],
    )
    if uac_values:
        enabled = _bool_or_none(uac_values.get("EnableLUA"))
        artifacts.append(
            SecurityPostureArtifact(
                artifact_id=stable_id("security_posture", "uac", UAC_REGISTRY_PATH),
                source="windows_registry",
                name="User Account Control",
                status="enabled" if enabled else "disabled" if enabled is False else "unknown",
                enabled=enabled,
                details=uac_values,
            ).model_dump()
        )
    else:
        warnings.append("Could not read UAC registry posture values.")

    tamper_values = _read_registry_values(winreg, winreg.HKEY_LOCAL_MACHINE, DEFENDER_FEATURES_PATH, ["TamperProtection"])
    if tamper_values:
        enabled = _tamper_protection_enabled(tamper_values.get("TamperProtection"))
        artifacts.append(
            SecurityPostureArtifact(
                artifact_id=stable_id("security_posture", "defender_tamper", DEFENDER_FEATURES_PATH),
                source="windows_registry",
                name="Microsoft Defender Tamper Protection",
                status="enabled" if enabled else "disabled" if enabled is False else "unknown",
                enabled=enabled,
                details=tamper_values,
            ).model_dump()
        )
    return artifacts, warnings


def _defender_artifact(status: dict[str, Any]) -> dict[str, Any]:
    enabled = _bool_or_none(status.get("AntivirusEnabled"))
    return SecurityPostureArtifact(
        artifact_id=stable_id("security_posture", "defender"),
        source="microsoft_defender",
        name="Microsoft Defender Antivirus",
        status="enabled" if enabled else "disabled" if enabled is False else "unknown",
        enabled=enabled,
        details=status,
    ).model_dump()


def _firewall_artifacts(profiles: list[dict[str, Any]]) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for profile in profiles:
        name = str(profile.get("Name") or "unknown")
        enabled = _bool_or_none(profile.get("Enabled"))
        artifacts.append(
            SecurityPostureArtifact(
                artifact_id=stable_id("security_posture", "firewall", name),
                source="windows_firewall",
                name=f"Windows Firewall {name} profile",
                status="enabled" if enabled else "disabled" if enabled is False else "unknown",
                enabled=enabled,
                details=profile,
            ).model_dump()
        )
    return artifacts


def _antivirus_artifacts(products: list[dict[str, Any]]) -> list[dict[str, Any]]:
    artifacts: list[dict[str, Any]] = []
    for product in products:
        name = str(product.get("displayName") or "Unknown antivirus product")
        artifacts.append(
            SecurityPostureArtifact(
                artifact_id=stable_id("security_posture", "security_center_av", name, product.get("instanceGuid")),
                source="windows_security_center",
                name=name,
                status=_string_or_none(product.get("productState")),
                enabled=None,
                details=product,
            ).model_dump()
        )
    return artifacts


def _run_powershell_json(command: str) -> Any:
    powershell = shutil.which("powershell") or shutil.which("pwsh")
    if not powershell:
        return None
    try:
        completed = subprocess.run(
            [powershell, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if completed.returncode != 0 or not completed.stdout.strip():
        return None
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError:
        return None


def _json_items(payload: Any) -> list[dict[str, Any]] | None:
    if payload is None:
        return None
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return None


def _read_registry_values(winreg, hive, path: str, names: list[str]) -> dict[str, Any]:
    values: dict[str, Any] = {}
    access = getattr(winreg, "KEY_READ", 0)
    try:
        with winreg.OpenKey(hive, path, 0, access) as key:
            for name in names:
                try:
                    value, _value_type = winreg.QueryValueEx(key, name)
                except OSError:
                    continue
                values[name] = value
    except (FileNotFoundError, PermissionError, OSError):
        return {}
    return values


def _tamper_protection_enabled(value: Any) -> bool | None:
    if value in (None, ""):
        return None
    try:
        return int(value) in {1, 5}
    except (TypeError, ValueError):
        return None


def _bool_or_none(value: Any) -> bool | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        return value
    try:
        return bool(int(value))
    except (TypeError, ValueError):
        return bool(value)


def _string_or_none(value: Any) -> str | None:
    if value in (None, ""):
        return None
    return str(value)
