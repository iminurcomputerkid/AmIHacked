from pathlib import Path


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

