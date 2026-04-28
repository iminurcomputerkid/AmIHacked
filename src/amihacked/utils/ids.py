from hashlib import sha256


def stable_id(prefix: str, *parts: object, length: int = 12) -> str:
    material = "|".join("" if part is None else str(part) for part in parts)
    digest = sha256(material.encode("utf-8")).hexdigest()[:length]
    return f"{prefix}-{digest}"

