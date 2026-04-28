from hashlib import sha256
from pathlib import Path


def sha256_file(path: str | Path) -> str | None:
    file_path = Path(path)
    try:
        digest = sha256()
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return None

