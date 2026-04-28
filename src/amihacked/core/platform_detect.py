import platform


def current_platform() -> str:
    system = platform.system().lower()
    if system == "darwin":
        return "macos"
    if system.startswith("win"):
        return "windows"
    if system == "linux":
        return "linux"
    return system or "unknown"

