"""
Jarvis - Secure Peer-to-Peer Messaging Application

A privacy-focused, end-to-end encrypted messaging system with
file transfer, group chat, NAT traversal, and advanced security features.

Author: orpheus497
Version: 2.1.0
License: MIT
"""

__version__ = '2.1.0'
__author__ = 'orpheus497'
__license__ = 'MIT'

# Import core modules for easy access
from .constants import VERSION, APP_NAME
from .errors import (
    JarvisError,
    CryptoError,
    NetworkError,
    IdentityError,
    ContactError,
    GroupError,
    FileTransferError,
    ConfigError,
    ServerError,
    ErrorCode,
)
from .config import Config
from .rate_limiter import RateLimiter, TokenBucket

__all__ = [
    '__version__',
    '__author__',
    '__license__',
    'VERSION',
    'APP_NAME',
    'JarvisError',
    'CryptoError',
    'NetworkError',
    'IdentityError',
    'ContactError',
    'GroupError',
    'FileTransferError',
    'ConfigError',
    'ServerError',
    'ErrorCode',
    'Config',
    'RateLimiter',
    'TokenBucket',
]
