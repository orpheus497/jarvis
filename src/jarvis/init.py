"""
Jarvis - A terminal-based peer-to-peer end-to-end encrypted messenger.

Created by orpheus497
Licensed under the MIT License - see LICENSE file for details.

Philosophy:
- Direct peer-to-peer connections (no servers, no cloud)
- Five-layer encryption (AES-256-GCM + ChaCha20-Poly1305)
- Complete privacy and security
- Group chat functionality
- Cross-platform terminal interface
- Background operation with notifications
- Zero external dependencies

Security Features:
- X25519 Elliptic Curve Diffie-Hellman key exchange
- Five-layer encryption alternating between AES-256-GCM and ChaCha20-Poly1305
- Argon2id key derivation (3 iterations, 64 MB memory)
- Unique session keys per connection
- Message authentication and integrity verification
- Secure identity storage with password protection

Dependencies:
- textual: Terminal UI framework (MIT License)
- cryptography: Cryptographic primitives (Apache 2.0/BSD)
- argon2-cffi: Argon2 password hashing (MIT License)
- rich: Terminal formatting (MIT License)

All dependencies are free, open-source, and royalty-free.
"""

__version__ = '1.0.0'
__author__ = 'orpheus497'
__license__ = 'MIT'
__description__ = 'A terminal-based peer-to-peer end-to-end encrypted messenger with multi-layer encryption and group chat'
