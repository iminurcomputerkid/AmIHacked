import os
import platform
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


def is_elevated() -> bool:
    if platform.system().lower().startswith("win"):
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    return hasattr(os, "geteuid") and os.geteuid() == 0


@dataclass(frozen=True)
class ElevationStatus:
    elevated: bool
    platform: str
    required_account: str
    can_auto_elevate: bool
    guidance: str


def elevation_status() -> ElevationStatus:
    system = platform.system().lower()
    elevated = is_elevated()
    if system.startswith("win"):
        return ElevationStatus(
            elevated=elevated,
            platform="windows",
            required_account="Administrator",
            can_auto_elevate=not elevated,
            guidance="Open an elevated PowerShell or Command Prompt, then run amihacked scan again.",
        )
    if system == "darwin":
        return ElevationStatus(
            elevated=elevated,
            platform="macos",
            required_account="root",
            can_auto_elevate=not elevated and sys.stdin.isatty() and shutil.which("sudo") is not None,
            guidance="Run sudo amihacked scan, or use --allow-unelevated for an incomplete development scan.",
        )
    return ElevationStatus(
        elevated=elevated,
        platform="linux",
        required_account="root",
        can_auto_elevate=not elevated and sys.stdin.isatty() and shutil.which("sudo") is not None,
        guidance="Run sudo amihacked scan, or use --allow-unelevated for an incomplete development scan.",
    )


def relaunch_with_elevation() -> bool:
    """Try to relaunch the current command with elevated privileges."""
    if is_elevated():
        return False

    system = platform.system().lower()
    if system.startswith("win"):
        return _windows_runas()

    sudo = shutil.which("sudo")
    if sudo and sys.stdin.isatty():
        os.execvp(sudo, [sudo, "-E", *sys.argv])
    return False


def _windows_runas() -> bool:
    try:
        import ctypes
    except Exception:
        return False

    executable, args = _windows_elevated_command()
    parameters = subprocess.list2cmdline(args)

    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        executable,
        parameters,
        None,
        1,
    )
    return result > 32


def _windows_elevated_command() -> tuple[str, list[str]]:
    invoked = Path(sys.argv[0])
    if invoked.suffix.lower() == ".exe":
        return str(invoked), sys.argv[1:]
    if invoked.suffix.lower() == ".py":
        return sys.executable, sys.argv
    return sys.executable, ["-m", "amihacked", *sys.argv[1:]]
