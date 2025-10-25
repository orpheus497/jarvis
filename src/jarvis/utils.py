"""
Jarvis - Utility functions.

Created by orpheus497

Provides various utility functions for formatting, validation, and helpers.
"""

import re
from datetime import datetime, timezone
from typing import Optional


def format_timestamp(iso_timestamp: str, format_str: str = '%Y-%m-%d %H:%M:%S') -> str:
    """
    Format an ISO timestamp to a human-readable string.
    
    Args:
        iso_timestamp: ISO 8601 timestamp string
        format_str: strftime format string
    
    Returns:
        Formatted timestamp string
    """
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace('Z', '+00:00'))
        return dt.strftime(format_str)
    except:
        return iso_timestamp


def format_timestamp_relative(iso_timestamp: str) -> str:
    """
    Format an ISO timestamp as relative time (e.g., '5 minutes ago').
    
    Args:
        iso_timestamp: ISO 8601 timestamp string
    
    Returns:
        Relative time string
    """
    try:
        dt = datetime.fromisoformat(iso_timestamp.replace('Z', '+00:00'))
        now = datetime.now(timezone.utc)
        diff = now - dt
        
        seconds = diff.total_seconds()
        
        if seconds < 60:
            return 'just now'
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
            return format_timestamp(iso_timestamp, '%Y-%m-%d')
    except:
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


def validate_ip(ip: str) -> bool:
    """
    Validate an IP address (IPv4).
    
    Args:
        ip: IP address string
    
    Returns:
        True if valid IPv4, False otherwise
    """
    pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if not re.match(pattern, ip):
        return False
    
    parts = ip.split('.')
    return all(0 <= int(part) <= 255 for part in parts)


def validate_hostname(hostname: str) -> bool:
    """
    Validate a hostname.
    
    Args:
        hostname: Hostname string
    
    Returns:
        True if valid hostname, False otherwise
    """
    if len(hostname) > 255:
        return False
    
    if hostname[-1] == '.':
        hostname = hostname[:-1]
    
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
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
    pattern = r'^[a-f0-9]{32}$'
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
    pattern = r'^g[a-f0-9]{31}$'
    return bool(re.match(pattern, gid))


def truncate_string(s: str, max_length: int, suffix: str = '...') -> str:
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
    return s[:max_length - len(suffix)] + suffix


def format_fingerprint(fingerprint: str) -> str:
    """
    Format a fingerprint for display with spaces every 4 characters.
    
    Args:
        fingerprint: Hex fingerprint string
    
    Returns:
        Formatted fingerprint
    """
    return ' '.join(fingerprint[i:i+4] for i in range(0, len(fingerprint), 4))


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
        return '??'
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
        filename = filename.replace(char, '_')
    
    # Remove leading/trailing spaces and dots
    filename = filename.strip('. ')
    
    # Ensure not empty
    if not filename:
        filename = 'unnamed'
    
    return filename


def get_platform_info() -> str:
    """
    Get platform information string.
    
    Returns:
        Platform information
    """
    import platform
    return f"{platform.system()} {platform.release()}"
