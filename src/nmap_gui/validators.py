"""Strict validation for a single target and numeric Nmap port selections."""

import ipaddress
import re


class ValidationError(ValueError):
    """An input cannot safely or meaningfully be passed to Nmap."""


def validate_target(value: str) -> str:
    target = value.strip(" ")
    if not target or len(target) > 253:
        raise ValidationError("Enter one IP address, hostname or CIDR subnet (max 253 characters).")
    if not re.fullmatch(r"[A-Za-z0-9.:/\-]+", target):
        raise ValidationError("Target contains unsupported characters. Shell syntax and multiple targets are forbidden.")
    if "/" in target:
        try:
            return str(ipaddress.ip_network(target, strict=False))
        except ValueError as exc:
            raise ValidationError("Invalid IPv4 or IPv6 CIDR subnet.") from exc
    try:
        return str(ipaddress.ip_address(target))
    except ValueError:
        pass
    if ":" in target or re.fullmatch(r"[0-9.]+", target):
        raise ValidationError("Invalid IP address.")
    hostname = target.removesuffix(".")
    if not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
               for label in hostname.split(".")):
        raise ValidationError("Invalid hostname. Use DNS labels with letters, digits and internal hyphens.")
    return target.lower()


def target_is_ipv6(target: str) -> bool:
    """IP literals/CIDRs select -6 automatically; DNS names use an explicit UI option."""
    return ":" in validate_target(target)


def validate_ports(value: str) -> str:
    if not value or len(value) > 4096 or not re.fullmatch(r"[0-9,-]+", value):
        raise ValidationError("Use ports such as 22,80,443,8000-9000; spaces and shell syntax are forbidden.")
    normalized = []
    for part in value.split(","):
        bounds = part.split("-")
        if len(bounds) > 2 or any(not item for item in bounds):
            raise ValidationError("Invalid port range.")
        numbers = [int(item) for item in bounds]
        if not all(1 <= port <= 65535 for port in numbers):
            raise ValidationError("Ports must be between 1 and 65535.")
        if len(numbers) == 2 and numbers[0] > numbers[1]:
            raise ValidationError("Port ranges must be in ascending order.")
        normalized.append("-".join(str(number) for number in numbers))
    return ",".join(normalized)
