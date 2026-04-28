import ipaddress


def is_public_ip(value: str | None) -> bool | None:
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return address.is_global


def is_private_ip(value: str | None) -> bool | None:
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return address.is_private

