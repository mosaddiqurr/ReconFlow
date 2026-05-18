"""Input validation utilities for scans."""

import ipaddress
import re
from urllib.parse import urlparse


DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$"
)


def detect_target_type(target: str) -> str:
    """Detect whether a target is a domain, IP address, URL, or invalid."""
    normalized_target = target.strip()
    if not normalized_target:
        return "invalid"

    try:
        ipaddress.ip_address(normalized_target)
    except ValueError:
        pass
    else:
        return "ip"

    parsed_url = urlparse(normalized_target)
    if parsed_url.scheme in {"http", "https"} and parsed_url.netloc:
        return "url"

    if DOMAIN_PATTERN.fullmatch(normalized_target):
        return "domain"

    return "invalid"


def validate_target(target: str) -> bool:
    """Return whether a target can be classified for a scan."""
    return detect_target_type(target) != "invalid"
