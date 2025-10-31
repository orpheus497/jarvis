"""
Jarvis - Multi-layer cryptographic operations.

Created by orpheus497

This module implements a supreme five-layer encryption system:
- Layer 1: X25519 ECDH key exchange for session establishment
- Layer 2: AES-256-GCM encryption (first layer)
- Layer 3: ChaCha20-Poly1305 encryption (second layer)
- Layer 4: AES-256-GCM encryption (third layer)
- Layer 5: ChaCha20-Poly1305 encryption (fourth layer)
- Layer 6: AES-256-GCM encryption (fifth layer)
- Layer 7: Argon2id-based identity derivation
- Layer 8: Message authentication and integrity verification

All cryptographic operations use well-tested, open-source libraries:
- cryptography library (Apache 2.0/BSD License)
- argon2-cffi (MIT License)
"""

import os
import json
import base64
import secrets
import hashlib
from typing import Dict, Tuple, Optional, List
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
from argon2.low_level import hash_secret_raw, Type

# Import Double Ratchet for forward secrecy (optional)
try:
    from .ratchet import RatchetSession
    RATCHET_AVAILABLE = True
except ImportError:
    RATCHET_AVAILABLE = False
    RatchetSession = None


class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass


class IdentityKeyPair:
    """
    Represents a user's identity key pair for P2P communication.
    Uses X25519 Elliptic Curve Diffie-Hellman for key agreement.
    
    X25519 provides:
    - 128-bit security level
    - Fast key agreement
    - Small key size (32 bytes)
    - Resistance to timing attacks
    """
    
    def __init__(self, private_key: Optional[x25519.X25519PrivateKey] = None):
        if private_key is None:
            self.private_key = x25519.X25519PrivateKey.generate()
        else:
            self.private_key = private_key
        self.public_key = self.private_key.public_key()
    
    def get_public_key_bytes(self) -> bytes:
        """Get public key as raw bytes."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def get_private_key_bytes(self) -> bytes:
        """Get private key as raw bytes."""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    def to_dict(self) -> Dict[str, str]:
        """Export key pair to dictionary for storage."""
        return {
            'private': base64.b64encode(self.get_private_key_bytes()).decode('utf-8'),
            'public': base64.b64encode(self.get_public_key_bytes()).decode('utf-8')
        }
    
    @staticmethod
    def from_dict(data: Dict[str, str]) -> 'IdentityKeyPair':
        """Import key pair from dictionary."""
        private_bytes = base64.b64decode(data['private'])
        private_key = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
        return IdentityKeyPair(private_key)
    
    @staticmethod
    def from_public_bytes(public_bytes: bytes) -> x25519.X25519PublicKey:
        """Load a public key from raw bytes."""
        return x25519.X25519PublicKey.from_public_bytes(public_bytes)


def derive_identity_key(username: str, password: str, salt: bytes) -> bytes:
    """
    Derive an identity seed from username and password using Argon2id.
    
    Argon2id is the winner of the Password Hashing Competition (2015) and provides:
    - Resistance to GPU/ASIC attacks
    - Memory-hard function
    - Protection against side-channel attacks
    
    Parameters (matching pwick philosophy):
        - Time cost: 3 iterations
        - Memory cost: 65536 KB (64 MB)
        - Parallelism: 1 thread
        - Output: 32 bytes (256 bits)
    
    This makes brute-force attacks computationally expensive while remaining
    fast enough for legitimate users on modern hardware (~1-2 seconds).
    """
    combined = f"{username}:{password}".encode('utf-8')
    return hash_secret_raw(
        secret=combined,
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=1,
        hash_len=32,
        type=Type.ID
    )


def perform_key_exchange(local_private: x25519.X25519PrivateKey,
                        remote_public: x25519.X25519PublicKey) -> Tuple[bytes, bytes, bytes, bytes, bytes]:
    """
    Perform X25519 key exchange and derive FIVE independent session keys using HKDF.
    
    This implements multi-layer key derivation where each layer uses a different
    hash function and salt to ensure complete independence between layers.
    
    Returns five 32-byte session keys for five-layer encryption:
    - Key 1: First AES-256-GCM encryption layer (SHA-256 derivation)
    - Key 2: First ChaCha20-Poly1305 encryption layer (SHA-384 derivation)
    - Key 3: Second AES-256-GCM encryption layer (SHA-512 derivation)
    - Key 4: Second ChaCha20-Poly1305 encryption layer (SHA-256 derivation)
    - Key 5: Third AES-256-GCM encryption layer (SHA-384 derivation)
    
    HKDF (HMAC-based Key Derivation Function) ensures:
    - Cryptographically strong key derivation
    - Key independence
    - Proper key stretching
    """
    shared_secret = local_private.exchange(remote_public)
    
    # Derive first session key (AES) using SHA-256
    hkdf1 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'jarvis-session-key-aes-layer-1'
    )
    session_key_1 = hkdf1.derive(shared_secret)
    
    # Derive second session key (ChaCha20) using SHA-384
    hkdf2 = HKDF(
        algorithm=hashes.SHA384(),
        length=32,
        salt=session_key_1[:16],
        info=b'jarvis-session-key-chacha-layer-2'
    )
    session_key_2 = hkdf2.derive(shared_secret)
    
    # Derive third session key (AES) using SHA-512
    hkdf3 = HKDF(
        algorithm=hashes.SHA512(),
        length=32,
        salt=session_key_2[:16],
        info=b'jarvis-session-key-aes-layer-3'
    )
    session_key_3 = hkdf3.derive(shared_secret)
    
    # Derive fourth session key (ChaCha20) using SHA-256
    hkdf4 = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=session_key_3[:16],
        info=b'jarvis-session-key-chacha-layer-4'
    )
    session_key_4 = hkdf4.derive(shared_secret)
    
    # Derive fifth session key (AES) using SHA-384
    hkdf5 = HKDF(
        algorithm=hashes.SHA384(),
        length=32,
        salt=session_key_4[:16],
        info=b'jarvis-session-key-aes-layer-5'
    )
    session_key_5 = hkdf5.derive(shared_secret)
    
    return session_key_1, session_key_2, session_key_3, session_key_4, session_key_5


def encrypt_message_five_layer(plaintext: str, 
                               session_keys: Tuple[bytes, bytes, bytes, bytes, bytes]) -> Dict[str, str]:
    """
    Encrypt a message using FIVE-LAYER encryption alternating between 
    AES-256-GCM and ChaCha20-Poly1305.
    
    Each layer uses:
    - Independent encryption key
    - Unique random nonce (12 bytes for GCM, 12 bytes for ChaCha20)
    - Authenticated encryption (prevents tampering)
    
    Encryption flow (nested encryption):
    1. Plaintext → AES-256-GCM (Key 1) → Ciphertext 1
    2. Ciphertext 1 → ChaCha20-Poly1305 (Key 2) → Ciphertext 2
    3. Ciphertext 2 → AES-256-GCM (Key 3) → Ciphertext 3
    4. Ciphertext 3 → ChaCha20-Poly1305 (Key 4) → Ciphertext 4
    5. Ciphertext 4 → AES-256-GCM (Key 5) → Final Ciphertext
    
    Why alternate between AES and ChaCha20?
    - Defense in depth: Different algorithms, different attack surfaces
    - AES-GCM: Hardware acceleration on modern CPUs (AES-NI)
    - ChaCha20: Constant-time software implementation (side-channel resistant)
    - If one algorithm is compromised, others still protect the data
    
    Returns dict with nonces and ciphertext for each layer.
    """
    key1, key2, key3, key4, key5 = session_keys
    
    # Layer 1: First AES-256-GCM encryption
    aesgcm1 = AESGCM(key1)
    nonce1 = os.urandom(12)  # 96-bit nonce for GCM
    ciphertext1 = aesgcm1.encrypt(nonce1, plaintext.encode('utf-8'), None)
    
    # Layer 2: First ChaCha20-Poly1305 encryption
    chacha1 = ChaCha20Poly1305(key2)
    nonce2 = os.urandom(12)  # 96-bit nonce for ChaCha20
    ciphertext2 = chacha1.encrypt(nonce2, ciphertext1, None)
    
    # Layer 3: Second AES-256-GCM encryption
    aesgcm2 = AESGCM(key3)
    nonce3 = os.urandom(12)
    ciphertext3 = aesgcm2.encrypt(nonce3, ciphertext2, None)
    
    # Layer 4: Second ChaCha20-Poly1305 encryption
    chacha2 = ChaCha20Poly1305(key4)
    nonce4 = os.urandom(12)
    ciphertext4 = chacha2.encrypt(nonce4, ciphertext3, None)
    
    # Layer 5: Third AES-256-GCM encryption
    aesgcm3 = AESGCM(key5)
    nonce5 = os.urandom(12)
    ciphertext5 = aesgcm3.encrypt(nonce5, ciphertext4, None)
    
    return {
        'nonce1': base64.b64encode(nonce1).decode('utf-8'),
        'nonce2': base64.b64encode(nonce2).decode('utf-8'),
        'nonce3': base64.b64encode(nonce3).decode('utf-8'),
        'nonce4': base64.b64encode(nonce4).decode('utf-8'),
        'nonce5': base64.b64encode(nonce5).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext5).decode('utf-8'),
        'version': '1.0',
        'layers': 5
    }


def decrypt_message_five_layer(encrypted_data: Dict[str, str], 
                               session_keys: Tuple[bytes, bytes, bytes, bytes, bytes]) -> str:
    """
    Decrypt a message using FIVE-LAYER decryption.
    Reverses the encryption process layer by layer.
    
    Decryption flow (reverse order):
    1. Final Ciphertext → AES-256-GCM (Key 5) → Ciphertext 4
    2. Ciphertext 4 → ChaCha20-Poly1305 (Key 4) → Ciphertext 3
    3. Ciphertext 3 → AES-256-GCM (Key 3) → Ciphertext 2
    4. Ciphertext 2 → ChaCha20-Poly1305 (Key 2) → Ciphertext 1
    5. Ciphertext 1 → AES-256-GCM (Key 1) → Plaintext
    
    Each layer verifies authentication tags to ensure:
    - Data has not been tampered with
    - Decryption is with the correct key
    - Message integrity is maintained
    
    Returns plaintext string or raises CryptoError if decryption fails.
    """
    key1, key2, key3, key4, key5 = session_keys
    
    try:
        # Extract all nonces and final ciphertext
        nonce1 = base64.b64decode(encrypted_data['nonce1'])
        nonce2 = base64.b64decode(encrypted_data['nonce2'])
        nonce3 = base64.b64decode(encrypted_data['nonce3'])
        nonce4 = base64.b64decode(encrypted_data['nonce4'])
        nonce5 = base64.b64decode(encrypted_data['nonce5'])
        ciphertext5 = base64.b64decode(encrypted_data['ciphertext'])
        
        # Layer 5: Third AES-256-GCM decryption
        aesgcm3 = AESGCM(key5)
        ciphertext4 = aesgcm3.decrypt(nonce5, ciphertext5, None)
        
        # Layer 4: Second ChaCha20-Poly1305 decryption
        chacha2 = ChaCha20Poly1305(key4)
        ciphertext3 = chacha2.decrypt(nonce4, ciphertext4, None)
        
        # Layer 3: Second AES-256-GCM decryption
        aesgcm2 = AESGCM(key3)
        ciphertext2 = aesgcm2.decrypt(nonce3, ciphertext3, None)
        
        # Layer 2: First ChaCha20-Poly1305 decryption
        chacha1 = ChaCha20Poly1305(key2)
        ciphertext1 = chacha1.decrypt(nonce2, ciphertext2, None)
        
        # Layer 1: First AES-256-GCM decryption
        aesgcm1 = AESGCM(key1)
        plaintext_bytes = aesgcm1.decrypt(nonce1, ciphertext1, None)
        
        return plaintext_bytes.decode('utf-8')
    except Exception as e:
        raise CryptoError(f"Decryption failed: {str(e)}")


def encrypt_identity_file(identity_data: Dict, password: str) -> Dict[str, str]:
    """
    Encrypt identity file with password using AES-256-GCM.
    Uses Argon2id for key derivation with the same parameters as message encryption.
    
    This protects the user's identity (private key) at rest with:
    - Strong password-based key derivation (Argon2id)
    - AES-256-GCM authenticated encryption
    - Unique salt per identity file
    - Unique nonce per encryption
    
    Parameters:
        - Time cost: 3 iterations
        - Memory cost: 65536 KB (64 MB)
        - Parallelism: 1 thread
        - Unique 16-byte salt per file
        - Unique 12-byte nonce per encryption
    """
    salt = os.urandom(16)
    key = hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=1,
        hash_len=32,
        type=Type.ID
    )
    
    json_data = json.dumps(identity_data)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, json_data.encode('utf-8'), None)
    
    return {
        'salt': base64.b64encode(salt).decode('utf-8'),
        'nonce': base64.b64encode(nonce).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
        'version': '1.0'
    }


def decrypt_identity_file(encrypted_data: Dict[str, str], password: str) -> Dict:
    """
    Decrypt identity file with password.
    
    Raises CryptoError if:
    - Password is incorrect
    - File is corrupted
    - Authentication tag verification fails
    """
    salt = base64.b64decode(encrypted_data['salt'])
    key = hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=1,
        hash_len=32,
        type=Type.ID
    )
    
    aesgcm = AESGCM(key)
    nonce = base64.b64decode(encrypted_data['nonce'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return json.loads(plaintext.decode('utf-8'))
    except Exception as e:
        raise CryptoError("Failed to decrypt identity. Incorrect password or corrupted file.")


def generate_fingerprint(public_key_bytes: bytes) -> str:
    """
    Generate a human-readable fingerprint from a public key using SHA-256.
    
    The fingerprint serves as:
    - A short representation of the public key
    - A way to verify key authenticity out-of-band
    - Protection against man-in-the-middle attacks
    
    Users should verify fingerprints through a trusted channel (phone call, in person, etc.)
    before trusting a contact's key.
    
    Returns a 64-character hexadecimal fingerprint.
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(public_key_bytes)
    return digest.finalize().hex()


def generate_uid() -> str:
    """
    Generate a unique user ID (UID) using cryptographically secure random bytes.
    
    The UID is:
    - 16 bytes (128 bits) of random data
    - Encoded as 32 hexadecimal characters
    - Globally unique with negligible collision probability
    - Used to identify users across the P2P network
    
    Format: 32 lowercase hexadecimal characters (e.g., "a1b2c3d4e5f6...")
    """
    return secrets.token_hex(16)


def generate_group_uid() -> str:
    """
    Generate a unique group ID (GID) using cryptographically secure random bytes.
    
    Similar to user UIDs but prefixed with 'g' to distinguish group identifiers.
    
    Format: g + 31 hexadecimal characters (e.g., "ga1b2c3d4e5f...")
    Total length: 32 characters
    
    Note: Group UIDs have 124 bits of entropy (31 hex chars) compared to 128 bits
    for user UIDs (32 hex chars). This is still cryptographically secure with
    negligible collision probability (2^124 ≈ 2.13×10^37 possible values).
    """
    # Generate 15 bytes (30 hex chars) + 1 additional hex digit = 31 hex chars (124 bits)
    return 'g' + secrets.token_hex(15) + format(secrets.randbelow(16), 'x')


def generate_secure_token(length: int = 32) -> str:
    """
    Generate a cryptographically secure random token.
    
    Used for:
    - Session IDs
    - Verification codes
    - Temporary authentication tokens
    - Challenge-response protocols
    """
    return secrets.token_hex(length)


def compute_message_hash(message_data: bytes) -> str:
    """
    Compute SHA-384 hash of message data for integrity verification.
    
    SHA-384 provides:
    - 384-bit security level
    - Fast hashing on 64-bit platforms
    - Collision resistance
    - Pre-image resistance
    
    Used to detect:
    - Data corruption
    - Transmission errors
    - Tampering attempts
    """
    return hashlib.sha384(message_data).hexdigest()


def verify_message_integrity(message_data: bytes, provided_hash: str) -> bool:
    """
    Verify message integrity using SHA-384 hash.
    
    Uses constant-time comparison to prevent timing attacks.
    
    Returns True if hash matches, False otherwise.
    """
    computed_hash = compute_message_hash(message_data)
    return secrets.compare_digest(computed_hash, provided_hash)


def derive_group_keys(group_secret: bytes, num_members: int) -> List[bytes]:
    """
    Derive individual encryption keys for each group member from a shared group secret.
    
    This implements a key derivation scheme where:
    - Each member gets a unique key derived from the group secret
    - Keys are independent and cannot be derived from each other
    - Group messages are encrypted once with each member's key
    
    Returns a list of 32-byte keys, one per member.
    """
    keys = []
    for i in range(num_members):
        hkdf = HKDF(
            algorithm=hashes.SHA384(),
            length=32,
            salt=None,
            info=f'jarvis-group-member-key-{i}'.encode('utf-8')
        )
        member_key = hkdf.derive(group_secret + i.to_bytes(4, 'big'))
        keys.append(member_key)
    return keys


# Double Ratchet Integration (v2.0)

class RatchetSessionManager:
    """
    Manages Double Ratchet sessions for contacts.

    Provides forward secrecy and self-healing properties through
    the Double Ratchet algorithm. Sessions are created on-demand
    and cached for performance.
    """

    def __init__(self):
        """Initialize ratchet session manager."""
        self.sessions: Dict[str, 'RatchetSession'] = {}

    def get_or_create_session(
        self,
        contact_uid: str,
        shared_secret: bytes,
        sending: bool = True
    ) -> Optional['RatchetSession']:
        """
        Get existing ratchet session or create new one.

        Args:
            contact_uid: Contact unique identifier
            shared_secret: Shared secret from key exchange
            sending: True if initiating, False if receiving

        Returns:
            RatchetSession instance or None if ratchet unavailable
        """
        if not RATCHET_AVAILABLE:
            return None

        if contact_uid not in self.sessions:
            self.sessions[contact_uid] = RatchetSession(shared_secret, sending)

        return self.sessions[contact_uid]

    def remove_session(self, contact_uid: str) -> None:
        """Remove ratchet session for a contact."""
        if contact_uid in self.sessions:
            del self.sessions[contact_uid]


def encrypt_with_ratchet(
    plaintext: str,
    ratchet_session: 'RatchetSession'
) -> Dict[str, str]:
    """
    Encrypt message using Double Ratchet.

    Provides forward secrecy - each message uses a unique key
    that is deleted immediately after encryption.

    Args:
        plaintext: Message to encrypt
        ratchet_session: Active ratchet session

    Returns:
        Dictionary with encrypted data and ratchet metadata

    Raises:
        CryptoError: If encryption fails
    """
    if not RATCHET_AVAILABLE or not ratchet_session:
        raise CryptoError("Double Ratchet not available")

    try:
        plaintext_bytes = plaintext.encode('utf-8')

        # Encrypt with ratchet
        ciphertext, dh_public, msg_number = ratchet_session.encrypt_message(plaintext_bytes)

        # Return encrypted data with ratchet metadata
        return {
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'dh_public': base64.b64encode(dh_public).decode('utf-8'),
            'msg_number': msg_number,
            'ratchet': True  # Flag to indicate ratchet encryption
        }
    except Exception as e:
        raise CryptoError(f"Ratchet encryption failed: {e}")


def decrypt_with_ratchet(
    encrypted_data: Dict[str, str],
    ratchet_session: 'RatchetSession'
) -> str:
    """
    Decrypt message using Double Ratchet.

    Handles out-of-order messages and automatic key rotation.

    Args:
        encrypted_data: Dictionary with encrypted data
        ratchet_session: Active ratchet session

    Returns:
        Decrypted plaintext string

    Raises:
        CryptoError: If decryption fails
    """
    if not RATCHET_AVAILABLE or not ratchet_session:
        raise CryptoError("Double Ratchet not available")

    try:
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        dh_public = base64.b64decode(encrypted_data['dh_public'])
        msg_number = encrypted_data['msg_number']

        # Decrypt with ratchet
        plaintext_bytes = ratchet_session.decrypt_message(
            ciphertext,
            dh_public,
            msg_number
        )

        return plaintext_bytes.decode('utf-8')
    except Exception as e:
        raise CryptoError(f"Ratchet decryption failed: {e}")


def encrypt_message_with_ratchet_option(
    plaintext: str,
    session_keys: Tuple[bytes, bytes, bytes, bytes, bytes],
    ratchet_session: Optional['RatchetSession'] = None,
    use_ratchet: bool = False
) -> Dict[str, str]:
    """
    Encrypt message with optional Double Ratchet.

    Uses ratchet if available and enabled, otherwise falls back
    to five-layer encryption for backward compatibility.

    Args:
        plaintext: Message to encrypt
        session_keys: Five session keys for traditional encryption
        ratchet_session: Optional ratchet session
        use_ratchet: Whether to prefer ratchet encryption

    Returns:
        Dictionary with encrypted data
    """
    # Use ratchet if available and requested
    if use_ratchet and RATCHET_AVAILABLE and ratchet_session:
        return encrypt_with_ratchet(plaintext, ratchet_session)

    # Fallback to traditional five-layer encryption
    return encrypt_message_five_layer(plaintext, session_keys)


def decrypt_message_with_ratchet_option(
    encrypted_data: Dict[str, str],
    session_keys: Tuple[bytes, bytes, bytes, bytes, bytes],
    ratchet_session: Optional['RatchetSession'] = None
) -> str:
    """
    Decrypt message with automatic ratchet detection.

    Automatically detects if message was encrypted with ratchet
    and uses appropriate decryption method.

    Args:
        encrypted_data: Encrypted message data
        session_keys: Five session keys for traditional decryption
        ratchet_session: Optional ratchet session

    Returns:
        Decrypted plaintext string
    """
    # Check if message was encrypted with ratchet
    if encrypted_data.get('ratchet', False):
        if not RATCHET_AVAILABLE or not ratchet_session:
            raise CryptoError("Message encrypted with ratchet but ratchet unavailable")
        return decrypt_with_ratchet(encrypted_data, ratchet_session)

    # Use traditional five-layer decryption
    return decrypt_message_five_layer(encrypted_data, session_keys)
