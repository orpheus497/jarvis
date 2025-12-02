"""
Jarvis - Utility functions.

Created by orpheus497
Version: 2.4.0

Provides various utility functions for formatting, validation, and helpers.

Security improvements:
- Specific exception handling instead of bare except clauses
- Better error handling for timestamp parsing
"""

import ipaddress
import logging
import re
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


def format_timestamp(iso_timestamp: str, format_str: str = "%Y-%m-%d %H:%M:%S") -> str:
    """
    Format an ISO timestamp to a human-readable string.

    Args:
        iso_timestamp: ISO 8601 timestamp string
        format_str: strftime format string

    Returns:
        Formatted timestamp string, or original if parsing fails
    """
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
        return dt.strftime(format_str)
    except (ValueError, TypeError, AttributeError) as e:
        # Invalid timestamp format, type, or attribute error
        logger.debug(f"Failed to parse timestamp '{iso_timestamp}': {e}")
        return iso_timestamp


def format_timestamp_relative(iso_timestamp: str) -> str:
    """
    Format an ISO timestamp as relative time (e.g., '5 minutes ago').

    Args:
        iso_timestamp: ISO 8601 timestamp string

    Returns:
        Relative time string, or original if parsing fails
    """
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        diff = now - dt

        seconds = diff.total_seconds()

        if seconds < 60:
            return "just now"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            return f'{minutes} minute{"s" if minutes != 1 else ""} ago'
        elif seconds < 86400:
            hours = int(seconds / 3600)
            return f'{hours} hour{"s" if hours != 1 else ""} ago'
        elif seconds < 604800:
            days = int(seconds / 86400)
            return f'{days} day{"s" if days != 1 else ""} ago'
        else:
            return format_timestamp(iso_timestamp, "%Y-%m-%d")
    except (ValueError, TypeError, AttributeError) as e:
        # Invalid timestamp format, type, or attribute error
        logger.debug(f"Failed to parse relative timestamp '{iso_timestamp}': {e}")
        return iso_timestamp


def validate_port(port: int) -> bool:
    """
    Validate a port number.

    Args:
        port: Port number to validate

    Returns:
        True if valid, False otherwise
    """
    return 1024 <= port <= 65535


def validate_ip(ip: str, allow_private: bool = True, allow_loopback: bool = False) -> bool:
    """
    Validate an IP address (IPv4 or IPv6) with proper range checking.

    Rejects invalid IPs, loopback addresses (unless allow_loopback=True),
    unspecified addresses (0.0.0.0, ::), reserved addresses, link-local,
    and multicast addresses.

    Args:
        ip: IP address string (IPv4 or IPv6)
        allow_private: Whether to allow private IP ranges (default: True)
        allow_loopback: Whether to allow loopback addresses (default: False)

    Returns:
        True if valid IP address, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip)

        # Handle loopback addresses (127.0.0.0/8, ::1)
        if ip_obj.is_loopback:
            # Return True if loopback is explicitly allowed, False otherwise
            return allow_loopback

        # Reject unspecified addresses (0.0.0.0, ::)
        if ip_obj.is_unspecified:
            return False

        # Reject reserved addresses (except loopback which is handled above)
        if ip_obj.is_reserved:
            return False

        # Reject link-local addresses (169.254.0.0/16, fe80::/10)
        if ip_obj.is_link_local:
            return False

        # Reject multicast addresses
        if ip_obj.is_multicast:
            return False

        # Optionally reject private addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, etc.)
        return not (not allow_private and ip_obj.is_private)

    except ValueError:
        # Invalid IP address format
        return False


def validate_hostname(hostname: str) -> bool:
    """
    Validate a hostname.

    Args:
        hostname: Hostname string

    Returns:
        True if valid hostname, False otherwise
    """
    # Empty hostnames are invalid
    if not hostname:
        return False

    if len(hostname) > 255:
        return False

    if hostname[-1] == ".":
        hostname = hostname[:-1]

    # Check again after stripping trailing dot
    if not hostname:
        return False

    pattern = r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
    return bool(re.match(pattern, hostname))


def validate_uid(uid: str) -> bool:
    """
    Validate a UID format.

    Args:
        uid: UID string

    Returns:
        True if valid UID format, False otherwise
    """
    # UID should be 32 hexadecimal characters
    pattern = r"^[a-f0-9]{32}$"
    return bool(re.match(pattern, uid))


def validate_group_uid(gid: str) -> bool:
    """
    Validate a group UID format.

    Args:
        gid: Group ID string

    Returns:
        True if valid group ID format, False otherwise
    """
    # Group ID should be 'g' followed by 31 hexadecimal characters
    pattern = r"^g[a-f0-9]{31}$"
    return bool(re.match(pattern, gid))


def truncate_string(s: str, max_length: int, suffix: str = "...") -> str:
    """
    Truncate a string to a maximum length.

    Args:
        s: String to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated

    Returns:
        Truncated string
    """
    if len(s) <= max_length:
        return s
    return s[: max_length - len(suffix)] + suffix


def format_fingerprint(fingerprint: str) -> str:
    """
    Format a fingerprint for display with spaces every 4 characters.

    Args:
        fingerprint: Hex fingerprint string

    Returns:
        Formatted fingerprint
    """
    return " ".join(fingerprint[i : i + 4] for i in range(0, len(fingerprint), 4))


def get_initials(name: str) -> str:
    """
    Get initials from a name.

    Args:
        name: Name string

    Returns:
        Initials (up to 2 characters)
    """
    parts = name.strip().split()
    if len(parts) == 0:
        return "??"
    elif len(parts) == 1:
        return parts[0][:2].upper()
    else:
        return (parts[0][0] + parts[-1][0]).upper()


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename by removing invalid characters.

    Args:
        filename: Filename to sanitize

    Returns:
        Sanitized filename
    """
    # Remove invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, "_")

    # Remove leading/trailing spaces and dots
    filename = filename.strip(". ")

    # Ensure not empty
    if not filename:
        filename = "unnamed"

    return filename


def get_platform_info() -> str:
    """
    Get platform information string.

    Returns:
        Platform information
    """
    import platform

    return f"{platform.system()} {platform.release()}"
