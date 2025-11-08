"""
Jarvis - Secure Peer-to-Peer Messaging Application

A privacy-focused, end-to-end encrypted messaging system with
file transfer, group chat, NAT traversal, and advanced security features.

Author: orpheus497
Version: 2.1.0
License: MIT
"""

__version__ = "2.1.0"
__author__ = "orpheus497"
__license__ = "MIT"

# Import core modules for easy access
from .config import Config
from .constants import APP_NAME, VERSION
from .errors import (
    ConfigError,
    ContactError,
    CryptoError,
    ErrorCode,
    FileTransferError,
    GroupError,
    IdentityError,
    JarvisError,
    NetworkError,
    ServerError,
)
from .rate_limiter import RateLimiter, TokenBucket

__all__ = [
    "APP_NAME",
    "VERSION",
    "Config",
    "ConfigError",
    "ContactError",
    "CryptoError",
    "ErrorCode",
    "FileTransferError",
    "GroupError",
    "IdentityError",
    "JarvisError",
    "NetworkError",
    "RateLimiter",
    "ServerError",
    "TokenBucket",
    "__author__",
    "__license__",
    "__version__",
]
