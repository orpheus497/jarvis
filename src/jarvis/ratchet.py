"""
Jarvis - Double Ratchet Encryption Implementation

This module implements the Double Ratchet algorithm for forward secrecy
and self-healing in secure messaging. Based on the Signal Protocol.

The Double Ratchet combines:
- Diffie-Hellman ratchet (X25519) for key agreement
- Symmetric ratchet (HKDF) for key derivation
- Message keys that are deleted immediately after use

Author: orpheus497
Version: 2.3.0
"""

import logging
import secrets
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .constants import KEY_SIZE, NONCE_SIZE, RATCHET_MAX_SKIP
from .errors import CryptoError, ErrorCode

logger = logging.getLogger(__name__)


class RatchetState:
    """State for a Double Ratchet session.

    Maintains the current state of both DH and symmetric ratchets,
    including chain keys, message keys, and skipped message keys.

    Attributes:
        dh_private: Current Diffie-Hellman private key
        dh_public: Current Diffie-Hellman public key
        dh_remote: Remote party's DH public key
        root_key: Current root chain key
        send_chain_key: Sending chain key
        recv_chain_key: Receiving chain key
        send_msg_number: Next message number to send
        recv_msg_number: Next message number to receive
        prev_send_count: Messages sent with previous chain
        skipped_keys: Stored keys for out-of-order messages
    """

    def __init__(self):
        """Initialize an empty ratchet state."""
        self.dh_private: Optional[x25519.X25519PrivateKey] = None
        self.dh_public: Optional[bytes] = None
        self.dh_remote: Optional[bytes] = None
        self.root_key: Optional[bytes] = None
        self.send_chain_key: Optional[bytes] = None
        self.recv_chain_key: Optional[bytes] = None
        self.send_msg_number: int = 0
        self.recv_msg_number: int = 0
        self.prev_send_count: int = 0
        self.skipped_keys: Dict[Tuple[bytes, int], bytes] = {}

    def generate_dh_keypair(self) -> None:
        """Generate a new Diffie-Hellman key pair."""
        self.dh_private = x25519.X25519PrivateKey.generate()
        self.dh_public = self.dh_private.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )

    def perform_dh(self, remote_public: bytes) -> bytes:
        """Perform Diffie-Hellman key exchange.

        Args:
            remote_public: Remote party's public key

        Returns:
            Shared secret

        Raises:
            CryptoError: If DH operation fails
        """
        if self.dh_private is None:
            raise CryptoError(ErrorCode.E103_INVALID_KEY, "No DH private key available")

        try:
            remote_key = x25519.X25519PublicKey.from_public_bytes(remote_public)
            shared_secret = self.dh_private.exchange(remote_key)
            return shared_secret
        except Exception as e:
            raise CryptoError(
                ErrorCode.E107_RATCHET_ERROR, f"DH exchange failed: {e}", {"error": str(e)}
            )


class RatchetSession:
    """Double Ratchet session for secure messaging.

    Manages encryption and decryption using the Double Ratchet algorithm.
    Provides forward secrecy and self-healing properties.
    """

    def __init__(self, shared_secret: bytes, sending: bool = True):
        """Initialize a Double Ratchet session.

        Args:
            shared_secret: Initial shared secret from key exchange
            sending: True if this is the sending party (initiator)

        Raises:
            CryptoError: If initialization fails
        """
        if len(shared_secret) != KEY_SIZE:
            raise CryptoError(ErrorCode.E103_INVALID_KEY, f"Shared secret must be {KEY_SIZE} bytes")

        self.state = RatchetState()
        self.state.generate_dh_keypair()

        # Initialize root key from shared secret
        self.state.root_key = shared_secret

        if sending:
            # Sender initializes send chain
            self.state.send_chain_key = self._derive_chain_key(shared_secret, b"send")
            logger.debug("Initialized ratchet session as sender")
        else:
            # Receiver initializes recv chain
            self.state.recv_chain_key = self._derive_chain_key(shared_secret, b"recv")
            logger.debug("Initialized ratchet session as receiver")

    def _kdf_rk(self, root_key: bytes, dh_output: bytes) -> Tuple[bytes, bytes]:
        """KDF for root key derivation.

        Derives a new root key and chain key from the current root key
        and DH output.

        Args:
            root_key: Current root key
            dh_output: Diffie-Hellman shared secret

        Returns:
            Tuple of (new_root_key, chain_key)
        """
        kdf = HKDF(algorithm=hashes.SHA256(), length=64, salt=root_key, info=b"ratchet-root")
        output = kdf.derive(dh_output)
        return output[:32], output[32:]

    def _kdf_ck(self, chain_key: bytes) -> Tuple[bytes, bytes]:
        """KDF for chain key derivation.

        Derives a new chain key and message key from the current chain key.

        Args:
            chain_key: Current chain key

        Returns:
            Tuple of (new_chain_key, message_key)
        """
        # Derive message key
        msg_kdf = HKDF(
            algorithm=hashes.SHA256(), length=KEY_SIZE, salt=chain_key, info=b"ratchet-message"
        )
        message_key = msg_kdf.derive(b"\x01")

        # Derive next chain key
        chain_kdf = HKDF(
            algorithm=hashes.SHA256(), length=KEY_SIZE, salt=chain_key, info=b"ratchet-chain"
        )
        new_chain_key = chain_kdf.derive(b"\x02")

        return new_chain_key, message_key

    def _derive_chain_key(self, key_material: bytes, info: bytes) -> bytes:
        """Derive initial chain key from key material.

        Args:
            key_material: Key material to derive from
            info: Info string for KDF

        Returns:
            Derived chain key
        """
        kdf = HKDF(algorithm=hashes.SHA256(), length=KEY_SIZE, salt=b"", info=info)
        return kdf.derive(key_material)

    def _dh_ratchet_step(self, remote_public: bytes) -> None:
        """Perform a Diffie-Hellman ratchet step.

        Args:
            remote_public: Remote party's new public key

        Raises:
            CryptoError: If ratchet step fails
        """
        # Perform DH with remote's new public key
        dh_output = self.state.perform_dh(remote_public)

        # Derive new root key and receive chain key
        self.state.root_key, self.state.recv_chain_key = self._kdf_rk(
            self.state.root_key, dh_output
        )

        # Update remote public key
        self.state.dh_remote = remote_public

        # Generate new DH key pair
        self.state.generate_dh_keypair()

        # Perform DH with our new key
        dh_output = self.state.perform_dh(remote_public)

        # Derive new root key and send chain key
        self.state.root_key, self.state.send_chain_key = self._kdf_rk(
            self.state.root_key, dh_output
        )

        # Reset message counters
        self.state.prev_send_count = self.state.send_msg_number
        self.state.send_msg_number = 0
        self.state.recv_msg_number = 0

        logger.debug("Performed DH ratchet step")

    def encrypt_message(self, plaintext: bytes) -> Tuple[bytes, bytes, int]:
        """Encrypt a message using the Double Ratchet.

        Args:
            plaintext: Message to encrypt

        Returns:
            Tuple of (ciphertext, dh_public_key, message_number)

        Raises:
            CryptoError: If encryption fails
        """
        if self.state.send_chain_key is None:
            raise CryptoError(ErrorCode.E101_ENCRYPTION_FAILED, "Send chain key not initialized")

        # Derive message key
        self.state.send_chain_key, message_key = self._kdf_ck(self.state.send_chain_key)

        # Encrypt with message key
        try:
            cipher = ChaCha20Poly1305(message_key)
            nonce = secrets.token_bytes(NONCE_SIZE)
            ciphertext = cipher.encrypt(nonce, plaintext, None)

            # Prepend nonce to ciphertext
            encrypted = nonce + ciphertext

            # Get current message number
            msg_number = self.state.send_msg_number
            self.state.send_msg_number += 1

            # Securely delete message key
            message_key = None

            logger.debug(f"Encrypted message #{msg_number}")
            return encrypted, self.state.dh_public, msg_number

        except Exception as e:
            raise CryptoError(
                ErrorCode.E101_ENCRYPTION_FAILED,
                f"Message encryption failed: {e}",
                {"error": str(e)},
            )

    def decrypt_message(self, ciphertext: bytes, dh_public: bytes, msg_number: int) -> bytes:
        """Decrypt a message using the Double Ratchet.

        Args:
            ciphertext: Encrypted message
            dh_public: Sender's DH public key
            msg_number: Message number in the chain

        Returns:
            Decrypted plaintext

        Raises:
            CryptoError: If decryption fails
        """
        # Check if we need to perform DH ratchet
        if self.state.dh_remote != dh_public:
            self._skip_message_keys(msg_number)
            self._dh_ratchet_step(dh_public)

        # Check for skipped message
        skip_key = (dh_public, msg_number)
        if skip_key in self.state.skipped_keys:
            message_key = self.state.skipped_keys.pop(skip_key)
            return self._decrypt_with_key(ciphertext, message_key)

        # Skip any intermediate messages
        self._skip_message_keys(msg_number)

        # Derive message key
        if self.state.recv_chain_key is None:
            raise CryptoError(ErrorCode.E102_DECRYPTION_FAILED, "Receive chain key not initialized")

        self.state.recv_chain_key, message_key = self._kdf_ck(self.state.recv_chain_key)
        self.state.recv_msg_number += 1

        return self._decrypt_with_key(ciphertext, message_key)

    def _decrypt_with_key(self, ciphertext: bytes, message_key: bytes) -> bytes:
        """Decrypt ciphertext with a specific message key.

        Args:
            ciphertext: Encrypted message (nonce + ciphertext)
            message_key: Message key to use

        Returns:
            Decrypted plaintext

        Raises:
            CryptoError: If decryption fails
        """
        try:
            # Extract nonce and actual ciphertext
            nonce = ciphertext[:NONCE_SIZE]
            actual_ciphertext = ciphertext[NONCE_SIZE:]

            cipher = ChaCha20Poly1305(message_key)
            plaintext = cipher.decrypt(nonce, actual_ciphertext, None)

            # Securely delete message key
            message_key = None

            logger.debug("Successfully decrypted message")
            return plaintext

        except Exception as e:
            raise CryptoError(
                ErrorCode.E102_DECRYPTION_FAILED,
                f"Message decryption failed: {e}",
                {"error": str(e)},
            )

    def _skip_message_keys(self, until: int) -> None:
        """Store message keys for skipped messages.

        Args:
            until: Skip messages until this number

        Raises:
            CryptoError: If too many messages are skipped
        """
        if self.state.recv_chain_key is None:
            return

        skipped = until - self.state.recv_msg_number
        if skipped > RATCHET_MAX_SKIP:
            raise CryptoError(
                ErrorCode.E107_RATCHET_ERROR,
                f"Too many skipped messages: {skipped} > {RATCHET_MAX_SKIP}",
            )

        if skipped > 0:
            logger.debug(f"Skipping {skipped} message keys")

        while self.state.recv_msg_number < until:
            self.state.recv_chain_key, message_key = self._kdf_ck(self.state.recv_chain_key)

            skip_key = (self.state.dh_remote, self.state.recv_msg_number)
            self.state.skipped_keys[skip_key] = message_key

            self.state.recv_msg_number += 1

            # Limit stored skipped keys
            if len(self.state.skipped_keys) > RATCHET_MAX_SKIP:
                # Remove oldest key
                oldest = min(self.state.skipped_keys.keys(), key=lambda x: x[1])
                del self.state.skipped_keys[oldest]
                logger.warning("Removed oldest skipped message key")

    def get_state_dict(self) -> Dict:
        """Get ratchet state as dictionary for serialization.

        Returns:
            Dictionary containing ratchet state

        Note:
            This includes sensitive key material and should be
            encrypted before storage.
        """
        return {
            "dh_public": self.state.dh_public.hex() if self.state.dh_public else None,
            "dh_remote": self.state.dh_remote.hex() if self.state.dh_remote else None,
            "root_key": self.state.root_key.hex() if self.state.root_key else None,
            "send_chain_key": (
                self.state.send_chain_key.hex() if self.state.send_chain_key else None
            ),
            "recv_chain_key": (
                self.state.recv_chain_key.hex() if self.state.recv_chain_key else None
            ),
            "send_msg_number": self.state.send_msg_number,
            "recv_msg_number": self.state.recv_msg_number,
            "prev_send_count": self.state.prev_send_count,
        }
