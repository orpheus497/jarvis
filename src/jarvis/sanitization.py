"""
Jarvis - Input Sanitization and Validation

Provides comprehensive input sanitization for all user-supplied data
to prevent injection attacks and ensure data integrity.

Author: orpheus497
Version: 2.3.0
"""

import html
import re
from typing import Optional


class InputSanitizer:
    """Sanitize and validate user inputs."""

    # Shell-unsafe characters
    SHELL_UNSAFE = r'[`$();|&<>"\'\\\n\r\t]'

    # AppleScript-unsafe characters
    APPLESCRIPT_UNSAFE = r'["\\\n\r]'

    # XML-unsafe characters (handled by html.escape)

    @staticmethod
    def sanitize_for_shell(text: str, max_length: int = 1000) -> str:
        """
        Sanitize text for use in shell commands.

        Removes all potentially dangerous shell metacharacters.

        Args:
            text: Input text to sanitize
            max_length: Maximum allowed length

        Returns:
            Sanitized text safe for shell use
        """
        if not isinstance(text, str):
            text = str(text)

        # Truncate to max length
        text = text[:max_length]

        # Remove shell metacharacters
        text = re.sub(InputSanitizer.SHELL_UNSAFE, "", text)

        # Remove control characters
        text = "".join(char for char in text if ord(char) >= 32 or char in "\n\r\t")

        return text.strip()

    @staticmethod
    def sanitize_for_applescript(text: str, max_length: int = 1000) -> str:
        """
        Sanitize text for use in AppleScript.

        Escapes quotes and backslashes, removes newlines.

        Args:
            text: Input text to sanitize
            max_length: Maximum allowed length

        Returns:
            Sanitized text safe for AppleScript
        """
        if not isinstance(text, str):
            text = str(text)

        # Truncate
        text = text[:max_length]

        # Escape backslashes first (order matters)
        text = text.replace("\\", "\\\\")

        # Escape quotes
        text = text.replace('"', '\\"')

        # Remove newlines and control characters
        text = " ".join(text.splitlines())
        text = "".join(char for char in text if ord(char) >= 32)

        return text.strip()

    @staticmethod
    def sanitize_for_xml(text: str, max_length: int = 1000) -> str:
        """
        Sanitize text for use in XML/HTML.

        Uses html.escape for proper XML entity encoding.

        Args:
            text: Input text to sanitize
            max_length: Maximum allowed length

        Returns:
            XML-safe text
        """
        if not isinstance(text, str):
            text = str(text)

        # Truncate
        text = text[:max_length]

        # HTML escape (handles &, <, >, ", ')
        text = html.escape(text, quote=True)

        return text.strip()

    @staticmethod
    def sanitize_for_display(text: str, max_length: int = 5000) -> str:
        """
        Sanitize text for terminal display.

        Removes ANSI escape sequences and control characters
        that could manipulate terminal.

        Args:
            text: Input text to sanitize
            max_length: Maximum allowed length

        Returns:
            Display-safe text
        """
        if not isinstance(text, str):
            text = str(text)

        # Truncate
        text = text[:max_length]

        # Remove ANSI escape sequences
        ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        text = ansi_escape.sub("", text)

        # Remove other control characters except newline and tab
        text = "".join(char for char in text if ord(char) >= 32 or char in "\n\t")

        return text

    @staticmethod
    def validate_notification_text(text: str) -> Optional[str]:
        """
        Validate and sanitize notification text.

        Returns None if text is invalid, sanitized text otherwise.

        Args:
            text: Text to validate

        Returns:
            Sanitized text or None if invalid
        """
        if not text or not isinstance(text, str):
            return None

        # Remove excessive whitespace
        text = " ".join(text.split())

        # Check length
        if len(text) > 500:
            text = text[:497] + "..."

        if len(text) < 1:
            return None

        return text


# Create global instance
_sanitizer = InputSanitizer()


def sanitize_for_shell(text: str) -> str:
    """Convenience function for shell sanitization."""
    return _sanitizer.sanitize_for_shell(text)


def sanitize_for_applescript(text: str) -> str:
    """Convenience function for AppleScript sanitization."""
    return _sanitizer.sanitize_for_applescript(text)


def sanitize_for_xml(text: str) -> str:
    """Convenience function for XML sanitization."""
    return _sanitizer.sanitize_for_xml(text)


def sanitize_for_display(text: str) -> str:
    """Convenience function for display sanitization."""
    return _sanitizer.sanitize_for_display(text)
