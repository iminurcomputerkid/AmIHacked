import subprocess
import sys
from pathlib import Path

import psutil
from amihacked.collectors.windows.windows_installed_software import WindowsInstalledSoftwareCollector
from amihacked.collectors.windows.windows_registry import WindowsRegistryCollector
from amihacked.collectors.windows.windows_scheduled_tasks import WindowsScheduledTasksCollector
from amihacked.collectors.windows.windows_security_posture import WindowsSecurityPostureCollector
from amihacked.collectors.windows.windows_services import WindowsServicesCollector
from amihacked.collectors.windows.windows_startup_items import WindowsStartupItemsCollector
from amihacked.core.scan_context import ScanContext
from amihacked.utils.paths import extract_executable_path


def test_extract_executable_path_handles_quoted_windows_command():
    assert extract_executable_path('"C:\\Users\\Alice\\AppData\\bad.exe" --flag') == "C:\\Users\\Alice\\AppData\\bad.exe"


def test_windows_startup_items_collector_reads_startup_folder(tmp_path, monkeypatch):
    appdata = tmp_path / "AppData" / "Roaming"
    startup = appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    startup.mkdir(parents=True)
    item = startup / "Updater.lnk"
    item.write_text("shortcut", encoding="utf-8")
    monkeypatch.setenv("APPDATA", str(appdata))
    monkeypatch.delenv("PROGRAMDATA", raising=False)

    result = WindowsStartupItemsCollector().collect(_context(tmp_path))

    assert result.artifacts
    assert result.artifacts[0]["source"] == "user_startup_folder"
    assert result.artifacts[0]["name"] == "Updater.lnk"


def test_windows_scheduled_tasks_collector_parses_csv(monkeypatch, tmp_path):
    csv_output = (
        '"HostName","TaskName","Task To Run","Run As User","Status","Scheduled Task State"\n'
        '"HOST","\\BadTask","C:\\Users\\Alice\\AppData\\bad.exe","Alice","Ready","Enabled"\n'
    )
    monkeypatch.setattr(
        "amihacked.collectors.windows.windows_scheduled_tasks.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args=args, returncode=0, stdout=csv_output, stderr=""),
    )

    result = WindowsScheduledTasksCollector().collect(_context(tmp_path))

    assert result.artifacts
    assert result.artifacts[0]["source"] == "scheduled_task"
    assert result.artifacts[0]["enabled"] is True
    assert result.artifacts[0]["path"] == "C:\\Users\\Alice\\AppData\\bad.exe"


def test_windows_services_collector_uses_wmic_path_enrichment(monkeypatch, tmp_path):
    class FakeService:
        def name(self):
            return "BadSvc"

        def as_dict(self):
            return {
                "name": "BadSvc",
                "display_name": "Bad Service",
                "status": "running",
                "start_type": "automatic",
                "username": "LocalSystem",
                "pid": 1234,
            }

    monkeypatch.setattr(psutil, "win_service_iter", lambda: [FakeService()], raising=False)
    monkeypatch.setattr(
        "amihacked.collectors.windows.windows_services.subprocess.run",
        lambda *args, **kwargs: subprocess.CompletedProcess(
            args=args,
            returncode=0,
            stdout="Node,Name,PathName\nHOST,BadSvc,C:\\Users\\Public\\badsvc.exe\n",
            stderr="",
        ),
    )

    result = WindowsServicesCollector().collect(_context(tmp_path))

    assert result.artifacts
    assert result.artifacts[0]["source"] == "service"
    assert result.artifacts[0]["command"] == "C:\\Users\\Public\\badsvc.exe"
    assert result.artifacts[0]["enabled"] is True


def test_windows_services_collector_uses_cim_when_wmic_is_missing(monkeypatch, tmp_path):
    class FakeService:
        def name(self):
            return "ModernSvc"

        def as_dict(self):
            return {
                "name": "ModernSvc",
                "display_name": "Modern Service",
                "status": "running",
                "start_type": "automatic",
                "username": "LocalSystem",
                "pid": 4321,
            }

    def fake_run(args, **kwargs):
        if "Get-CimInstance Win32_Service" in args[-1]:
            return subprocess.CompletedProcess(
                args=args,
                returncode=0,
                stdout='[{"Name":"ModernSvc","PathName":"C:\\\\Program Files\\\\Modern\\\\svc.exe"}]',
                stderr="",
            )
        return subprocess.CompletedProcess(args=args, returncode=1, stdout="", stderr="wmic missing")

    monkeypatch.setattr(psutil, "win_service_iter", lambda: [FakeService()], raising=False)
    monkeypatch.setattr("amihacked.collectors.windows.windows_services.shutil.which", lambda _name: "powershell")
    monkeypatch.setattr("amihacked.collectors.windows.windows_services.subprocess.run", fake_run)

    result = WindowsServicesCollector().collect(_context(tmp_path))

    assert result.status == "ok"
    assert result.artifacts[0]["command"] == "C:\\Program Files\\Modern\\svc.exe"


def test_windows_registry_collector_reads_run_keys(monkeypatch, tmp_path):
    values = [("BadRun", "C:\\Users\\Alice\\AppData\\bad.exe", 1)]

    class FakeKey:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class FakeWinreg:
        HKEY_CURRENT_USER = object()
        HKEY_LOCAL_MACHINE = object()
        KEY_READ = 1

        @staticmethod
        def OpenKey(_hive, subkey, *_args):
            if subkey.endswith("Run"):
                return FakeKey()
            raise FileNotFoundError

        @staticmethod
        def EnumValue(_key, index):
            if index >= len(values):
                raise OSError
            return values[index]

    monkeypatch.setitem(sys.modules, "winreg", FakeWinreg)

    result = WindowsRegistryCollector().collect(_context(tmp_path))

    assert result.artifacts
    assert result.artifacts[0]["source"] == "registry_run_key"
    assert result.artifacts[0]["name"] == "BadRun"


def test_windows_installed_software_collector_reads_uninstall_keys(monkeypatch, tmp_path):
    class FakeKey:
        def __init__(self, path):
            self.path = path

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    values = {
        r"Software\Microsoft\Windows\CurrentVersion\Uninstall\AcmeApp": {
            "DisplayName": "Acme App",
            "DisplayVersion": "1.2.3",
            "Publisher": "Acme",
            "InstallLocation": r"C:\Program Files\Acme",
        }
    }

    class FakeWinreg:
        HKEY_CURRENT_USER = "HKCU"
        HKEY_LOCAL_MACHINE = "HKLM"
        KEY_READ = 1

        @staticmethod
        def OpenKey(_hive, subkey, *_args):
            if subkey == r"Software\Microsoft\Windows\CurrentVersion\Uninstall":
                return FakeKey(subkey)
            if subkey in values:
                return FakeKey(subkey)
            raise FileNotFoundError

        @staticmethod
        def EnumKey(key, index):
            if key.path == r"Software\Microsoft\Windows\CurrentVersion\Uninstall" and index == 0:
                return "AcmeApp"
            raise OSError

        @staticmethod
        def QueryValueEx(key, name):
            value = values[key.path].get(name)
            if value is None:
                raise OSError
            return value, 1

    monkeypatch.setitem(sys.modules, "winreg", FakeWinreg)

    result = WindowsInstalledSoftwareCollector().collect(_context(tmp_path))

    assert result.artifacts
    assert result.artifacts[0]["type"] == "installed_software"
    assert result.artifacts[0]["name"] == "Acme App"
    assert result.artifacts[0]["version"] == "1.2.3"


def test_windows_security_posture_collector_reads_powershell_and_registry(monkeypatch, tmp_path):
    class FakeKey:
        def __init__(self, path):
            self.path = path

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    registry = {
        r"Software\Microsoft\Windows\CurrentVersion\Policies\System": {
            "EnableLUA": 1,
            "ConsentPromptBehaviorAdmin": 5,
            "PromptOnSecureDesktop": 1,
        },
        r"SOFTWARE\Microsoft\Windows Defender\Features": {
            "TamperProtection": 5,
        },
    }

    class FakeWinreg:
        HKEY_LOCAL_MACHINE = "HKLM"
        KEY_READ = 1

        @staticmethod
        def OpenKey(_hive, subkey, *_args):
            if subkey in registry:
                return FakeKey(subkey)
            raise FileNotFoundError

        @staticmethod
        def QueryValueEx(key, name):
            value = registry[key.path].get(name)
            if value is None:
                raise OSError
            return value, 1

    def fake_run(args, **kwargs):
        command = args[-1]
        if "Get-MpComputerStatus" in command:
            stdout = '{"AntivirusEnabled":true,"RealTimeProtectionEnabled":true}'
        elif "Get-NetFirewallProfile" in command:
            stdout = '[{"Name":"Domain","Enabled":true},{"Name":"Public","Enabled":false}]'
        else:
            stdout = "[]"
        return subprocess.CompletedProcess(args=args, returncode=0, stdout=stdout, stderr="")

    monkeypatch.setitem(sys.modules, "winreg", FakeWinreg)
    monkeypatch.setattr("amihacked.collectors.windows.windows_security_posture.shutil.which", lambda _name: "powershell")
    monkeypatch.setattr("amihacked.collectors.windows.windows_security_posture.subprocess.run", fake_run)

    result = WindowsSecurityPostureCollector().collect(_context(tmp_path))

    names = {artifact["name"] for artifact in result.artifacts}
    assert "Microsoft Defender Antivirus" in names
    assert "Windows Firewall Domain profile" in names
    assert "User Account Control" in names
    assert "Microsoft Defender Tamper Protection" in names


def _context(tmp_path: Path) -> ScanContext:
    return ScanContext(
        case_id="case-test",
        case_dir=tmp_path,
        started_at="2026-04-25T18:30:00Z",
        platform="windows",
        elevated=True,
    )
