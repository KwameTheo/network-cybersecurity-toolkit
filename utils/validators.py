"""
Input Validation & Security Sanitizer
Validates IP addresses, domain names, and port numbers to prevent Command Injection.
"""

import ipaddress
import re
from typing import Optional, Tuple


# Regex for valid RFC 1123 domain names / hostnames
HOSTNAME_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$|"
    r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)

# Dangerous characters commonly used in shell command injection attacks
FORBIDDEN_SHELL_CHARS = set(";&|`$><\"'\\*?!()[]{}~\n\r\t")


def is_safe_string(text: str) -> bool:
    """Checks if the string contains any forbidden shell metacharacters."""
    if not text or not isinstance(text, str):
        return False
    return not any(char in FORBIDDEN_SHELL_CHARS for char in text)


def validate_ip_address(ip_str: str) -> Tuple[bool, Optional[str]]:
    """
    Validates whether the given string is a valid IPv4 or IPv6 address.
    Returns (is_valid, normalized_ip_or_error_message).
    """
    if not ip_str or not isinstance(ip_str, str):
        return False, "IP address cannot be empty."

    ip_clean = ip_str.strip()
    if not is_safe_string(ip_clean):
        return False, "Input contains prohibited characters (command injection protection)."

    try:
        ip_obj = ipaddress.ip_address(ip_clean)
        return True, str(ip_obj)
    except ValueError:
        return False, f"'{ip_clean}' is not a valid IPv4 or IPv6 address."


def validate_domain_name(domain_str: str) -> Tuple[bool, Optional[str]]:
    """
    Validates whether the given string is a valid hostname or fully qualified domain name (FQDN).
    Returns (is_valid, normalized_domain_or_error_message).
    """
    if not domain_str or not isinstance(domain_str, str):
        return False, "Domain/Host cannot be empty."

    domain_clean = domain_str.strip().lower()
    if len(domain_clean) > 253:
        return False, "Domain name exceeds maximum length (253 characters)."

    if not is_safe_string(domain_clean):
        return False, "Input contains prohibited characters (command injection protection)."

    if HOSTNAME_REGEX.match(domain_clean):
        return True, domain_clean

    return False, f"'{domain_clean}' is not a valid domain name or hostname."


def validate_target(target_str: str) -> Tuple[bool, str, str]:
    """
    Validates a target which can be either an IP address (IPv4/IPv6) or a domain name.
    Returns (is_valid, normalized_target, target_type ['ip' | 'domain' | 'invalid']).
    """
    if not target_str or not isinstance(target_str, str):
        return False, "Target cannot be empty.", "invalid"

    clean_target = target_str.strip()

    # First check if it's a valid IP
    is_ip, ip_res = validate_ip_address(clean_target)
    if is_ip:
        return True, ip_res, "ip"

    # Next check if it's a valid Domain/Hostname
    is_domain, domain_res = validate_domain_name(clean_target)
    if is_domain:
        return True, domain_res, "domain"

    return False, f"Invalid IP address or domain name: '{clean_target}'", "invalid"


def validate_port(port_val: any) -> Tuple[bool, Optional[int], Optional[str]]:
    """
    Validates that a port is an integer between 1 and 65535.
    Returns (is_valid, port_int, error_message).
    """
    try:
        port_num = int(port_val)
        if 1 <= port_num <= 65535:
            return True, port_num, None
        return False, None, f"Port {port_num} is out of valid range (1 - 65535)."
    except (ValueError, TypeError):
        return False, None, f"'{port_val}' is not a valid port number."
