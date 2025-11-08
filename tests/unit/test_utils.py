"""
Unit tests for jarvis.utils module.

Created by orpheus497

Tests utility functions for formatting, validation, and helpers.
"""

from jarvis.utils import (
    format_fingerprint,
    get_initials,
    sanitize_filename,
    truncate_string,
    validate_group_uid,
    validate_hostname,
    validate_ip,
    validate_port,
    validate_uid,
)


class TestPortValidation:
    """Test port number validation."""

    def test_valid_ports(self):
        """Test that valid port numbers are accepted."""
        assert validate_port(1024) is True
        assert validate_port(5000) is True
        assert validate_port(8080) is True
        assert validate_port(65535) is True

    def test_invalid_ports(self):
        """Test that invalid port numbers are rejected."""
        assert validate_port(0) is False
        assert validate_port(1023) is False
        assert validate_port(65536) is False
        assert validate_port(100000) is False


class TestIPValidation:
    """Test IP address validation."""

    def test_valid_ipv4(self):
        """Test that valid IPv4 addresses are accepted."""
        assert validate_ip("192.168.1.1") is True
        assert validate_ip("10.0.0.1") is True

    def test_valid_ipv6(self):
        """Test that valid IPv6 addresses are accepted."""
        assert validate_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True
        assert validate_ip("::1", allow_loopback=True) is True

    def test_invalid_ips(self):
        """Test that invalid IP addresses are rejected."""
        assert validate_ip("256.1.1.1") is False
        assert validate_ip("not_an_ip") is False
        assert validate_ip("") is False

    def test_loopback_rejection(self):
        """Test that loopback addresses are rejected by default."""
        assert validate_ip("127.0.0.1") is False
        assert validate_ip("::1") is False

    def test_loopback_allowed(self):
        """Test that loopback addresses are allowed when specified."""
        assert validate_ip("127.0.0.1", allow_loopback=True) is True
        assert validate_ip("::1", allow_loopback=True) is True


class TestHostnameValidation:
    """Test hostname validation."""

    def test_valid_hostnames(self):
        """Test that valid hostnames are accepted."""
        assert validate_hostname("example.com") is True
        assert validate_hostname("sub.example.com") is True
        assert validate_hostname("example-site.com") is True

    def test_invalid_hostnames(self):
        """Test that invalid hostnames are rejected."""
        assert validate_hostname("") is False
        assert validate_hostname("-example.com") is False
        assert validate_hostname("example-.com") is False
        assert validate_hostname("a" * 256) is False


class TestUIDValidation:
    """Test UID format validation."""

    def test_valid_uid(self):
        """Test that valid UIDs are accepted."""
        assert validate_uid("a" * 32) is True
        assert validate_uid("0123456789abcdef" * 2) is True

    def test_invalid_uid(self):
        """Test that invalid UIDs are rejected."""
        assert validate_uid("a" * 31) is False  # Too short
        assert validate_uid("a" * 33) is False  # Too long
        assert validate_uid("z" * 32) is False  # Invalid character
        assert validate_uid("ABCD" * 8) is False  # Uppercase


class TestGroupUIDValidation:
    """Test group UID format validation."""

    def test_valid_group_uid(self):
        """Test that valid group UIDs are accepted."""
        assert validate_group_uid("g" + "a" * 31) is True

    def test_invalid_group_uid(self):
        """Test that invalid group UIDs are rejected."""
        assert validate_group_uid("a" * 32) is False  # Missing 'g' prefix
        assert validate_group_uid("g" + "a" * 30) is False  # Too short


class TestStringUtilities:
    """Test string utility functions."""

    def test_truncate_string(self):
        """Test string truncation."""
        assert truncate_string("short", 10) == "short"
        assert truncate_string("this is a long string", 10) == "this is..."
        assert truncate_string("test", 10, "~") == "test"

    def test_format_fingerprint(self):
        """Test fingerprint formatting."""
        fp = "0123456789abcdef"
        result = format_fingerprint(fp)
        assert result == "0123 4567 89ab cdef"

    def test_get_initials(self):
        """Test initial extraction from names."""
        assert get_initials("John Doe") == "JD"
        assert get_initials("Alice") == "AL"
        assert get_initials("") == "??"
        assert get_initials("Bob Smith Jones") == "BJ"

    def test_sanitize_filename(self):
        """Test filename sanitization."""
        assert sanitize_filename("normal.txt") == "normal.txt"
        assert sanitize_filename("file<>name.txt") == "file__name.txt"
        assert sanitize_filename("path/to/file.txt") == "path_to_file.txt"
        assert sanitize_filename("") == "unnamed"
        assert sanitize_filename("   ") == "unnamed"
