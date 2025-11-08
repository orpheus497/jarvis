"""
Jarvis - Custom Exception Classes and Error Codes

This module defines all custom exceptions and error codes used throughout
the Jarvis application. Each error has a unique code for logging and debugging.

Author: orpheus497
Version: 2.0.0
"""

from enum import Enum
from typing import Any, Dict, Optional


class ErrorCode(Enum):
    """Enumeration of all Jarvis error codes."""

    # General Errors (E001-E099)
    E001_UNKNOWN_ERROR = "E001"
    E002_INVALID_ARGUMENT = "E002"
    E003_FILE_NOT_FOUND = "E003"
    E004_PERMISSION_DENIED = "E004"
    E005_OPERATION_FAILED = "E005"

    # Crypto Errors (E100-E199)
    E100_CRYPTO_ERROR = "E100"
    E101_ENCRYPTION_FAILED = "E101"
    E102_DECRYPTION_FAILED = "E102"
    E103_INVALID_KEY = "E103"
    E104_KEY_GENERATION_FAILED = "E104"
    E105_SIGNATURE_FAILED = "E105"
    E106_VERIFICATION_FAILED = "E106"
    E107_RATCHET_ERROR = "E107"
    E108_KEY_DERIVATION_FAILED = "E108"

    # Network Errors (E200-E299)
    E200_NETWORK_ERROR = "E200"
    E201_CONNECTION_FAILED = "E201"
    E202_CONNECTION_TIMEOUT = "E202"
    E203_CONNECTION_CLOSED = "E203"
    E204_SEND_FAILED = "E204"
    E205_RECEIVE_FAILED = "E205"
    E206_INVALID_MESSAGE = "E206"
    E207_MESSAGE_TOO_LARGE = "E207"
    E208_RATE_LIMIT_EXCEEDED = "E208"
    E209_HANDSHAKE_FAILED = "E209"

    # Identity Errors (E300-E399)
    E300_IDENTITY_ERROR = "E300"
    E301_IDENTITY_NOT_FOUND = "E301"
    E302_IDENTITY_ALREADY_EXISTS = "E302"
    E303_IDENTITY_LOAD_FAILED = "E303"
    E304_IDENTITY_SAVE_FAILED = "E304"
    E305_INVALID_IDENTITY = "E305"

    # Contact Errors (E400-E499)
    E400_CONTACT_ERROR = "E400"
    E401_CONTACT_NOT_FOUND = "E401"
    E402_CONTACT_ALREADY_EXISTS = "E402"
    E403_CONTACT_LOAD_FAILED = "E403"
    E404_CONTACT_SAVE_FAILED = "E404"
    E405_INVALID_CONTACT = "E405"

    # Group Errors (E500-E599)
    E500_GROUP_ERROR = "E500"
    E501_GROUP_NOT_FOUND = "E501"
    E502_GROUP_ALREADY_EXISTS = "E502"
    E503_GROUP_LOAD_FAILED = "E503"
    E504_GROUP_SAVE_FAILED = "E504"
    E505_INVALID_GROUP = "E505"
    E506_NOT_GROUP_ADMIN = "E506"
    E507_GROUP_FULL = "E507"

    # File Transfer Errors (E600-E699)
    E600_FILE_TRANSFER_ERROR = "E600"
    E601_FILE_TOO_LARGE = "E601"
    E602_CHUNK_FAILED = "E602"
    E603_CHECKSUM_MISMATCH = "E603"
    E604_TRANSFER_TIMEOUT = "E604"
    E605_TRANSFER_CANCELLED = "E605"
    E606_INVALID_CHUNK = "E606"

    # Config Errors (E700-E799)
    E700_CONFIG_ERROR = "E700"
    E701_CONFIG_LOAD_FAILED = "E701"
    E702_CONFIG_SAVE_FAILED = "E702"
    E703_INVALID_CONFIG = "E703"
    E704_CONFIG_PARSE_ERROR = "E704"

    # Server Errors (E800-E899)
    E800_SERVER_ERROR = "E800"
    E801_SERVER_START_FAILED = "E801"
    E802_SERVER_ALREADY_RUNNING = "E802"
    E803_SERVER_NOT_RUNNING = "E803"
    E804_INVALID_COMMAND = "E804"


class JarvisError(Exception):
    """Base exception class for all Jarvis errors.

    All custom exceptions in Jarvis inherit from this class.
    Provides standardized error handling and logging.

    Attributes:
        code: Error code from ErrorCode enum
        message: Human-readable error message
        details: Additional error details (optional)
    """

    def __init__(self, code: ErrorCode, message: str, details: Optional[Dict[str, Any]] = None):
        """Initialize a Jarvis error.

        Args:
            code: Error code from ErrorCode enum
            message: Human-readable error message
            details: Additional error context (optional)
        """
        self.code = code
        self.message = message
        self.details = details or {}
        super().__init__(f"[{code.value}] {message}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary for serialization.

        Returns:
            Dictionary containing error information
        """
        return {"code": self.code.value, "message": self.message, "details": self.details}


class CryptoError(JarvisError):
    """Exception raised for cryptographic operation failures.

    This includes encryption, decryption, key generation, signing,
    verification, and ratchet operations.
    """

    def __init__(
        self,
        code: ErrorCode = ErrorCode.E100_CRYPTO_ERROR,
        message: str = "Cryptographic operation failed",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(code, message, details)


class NetworkError(JarvisError):
    """Exception raised for network operation failures.

    This includes connection errors, timeouts, send/receive failures,
    and protocol violations.
    """

    def __init__(
        self,
        code: ErrorCode = ErrorCode.E200_NETWORK_ERROR,
        message: str = "Network operation failed",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(code, message, details)


class IdentityError(JarvisError):
    """Exception raised for identity management failures.

    This includes loading, saving, and validation of user identities.
    """

    def __init__(
        self,
        code: ErrorCode = ErrorCode.E300_IDENTITY_ERROR,
        message: str = "Identity operation failed",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(code, message, details)


class ContactError(JarvisError):
    """Exception raised for contact management failures.

    This includes adding, removing, updating, and loading contacts.
    """

    def __init__(
        self,
        code: ErrorCode = ErrorCode.E400_CONTACT_ERROR,
        message: str = "Contact operation failed",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(code, message, details)


class GroupError(JarvisError):
    """Exception raised for group management failures.

    This includes creating, modifying, and managing group chats.
    """

    def __init__(
        self,
        code: ErrorCode = ErrorCode.E500_GROUP_ERROR,
        message: str = "Group operation failed",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(code, message, details)


class FileTransferError(JarvisError):
    """Exception raised for file transfer failures.

    This includes chunking, encryption, transmission, and verification errors.
    """

    def __init__(
        self,
        code: ErrorCode = ErrorCode.E600_FILE_TRANSFER_ERROR,
        message: str = "File transfer operation failed",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(code, message, details)


class ConfigError(JarvisError):
    """Exception raised for configuration failures.

    This includes loading, parsing, and validating configuration files.
    """

    def __init__(
        self,
        code: ErrorCode = ErrorCode.E700_CONFIG_ERROR,
        message: str = "Configuration operation failed",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(code, message, details)


class ServerError(JarvisError):
    """Exception raised for server operation failures.

    This includes server startup, shutdown, and command processing errors.
    """

    def __init__(
        self,
        code: ErrorCode = ErrorCode.E800_SERVER_ERROR,
        message: str = "Server operation failed",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(code, message, details)
