from pathlib import Path
import os
import re
import shlex


USER_WRITABLE_MARKERS = (
    "\\appdata\\",
    "/appdata/",
    "\\temp\\",
    "/temp/",
    "\\tmp\\",
    "/tmp/",
    "\\users\\public\\",
    "/users/public/",
)


def looks_user_writable(path: str | None) -> bool:
    if not path:
        return False
    normalized = path.lower().replace("/", "\\")
    return any(marker.replace("/", "\\") in normalized for marker in USER_WRITABLE_MARKERS)


def safe_relative(path: Path, base: Path) -> str:
    return path.resolve().relative_to(base.resolve()).as_posix()


def extract_executable_path(command: str | None) -> str | None:
    if not command:
        return None
    expanded = os.path.expandvars(command.strip())
    quoted = re.match(r'^\s*"([^"]+)"', expanded)
    if quoted:
        return quoted.group(1)
    single_quoted = re.match(r"^\s*'([^']+)'", expanded)
    if single_quoted:
        return single_quoted.group(1)
    try:
        parts = shlex.split(expanded, posix=False)
    except ValueError:
        parts = expanded.split()
    if not parts:
        return None
    first = parts[0].strip("\"'")
    if first.lower() in {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe"} and len(parts) > 1:
        return parts[1].strip("\"'")
    return first
