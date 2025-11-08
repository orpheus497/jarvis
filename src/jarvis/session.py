"""
Jarvis - Secure Session Management System

This module manages login sessions with encryption, expiration, and integrity
verification. Sessions are encrypted at rest and automatically expire after
7 days or 24 hours of inactivity.

Security features:
- Sessions encrypted with AES-256-GCM using master password-derived key
- HMAC-SHA256 integrity verification
- Automatic expiration (7-day absolute, 24-hour idle timeout)
- Secure session token generation using secrets module
- Atomic file writes to prevent corruption

Author: orpheus497
Version: 2.4.0
"""

import hashlib
import hmac
import json
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import ErrorCode, JarvisError

logger = logging.getLogger(__name__)

# Session timeout constants
SESSION_ABSOLUTE_TIMEOUT_DAYS = 7  # Sessions expire after 7 days
SESSION_IDLE_TIMEOUT_HOURS = 24  # Sessions expire after 24 hours of inactivity
SESSION_NONCE_SIZE = 12  # 96 bits for AES-GCM
SESSION_KEY_SIZE = 32  # 256 bits for AES-256


class SessionError(JarvisError):
    """Session-related errors."""

    pass


class Session:
    """Represents an encrypted login session with expiration.

    Attributes:
        session_id: Unique session identifier (cryptographically random)
        identity_uid: UID of the logged-in identity
        created_at: UTC timestamp of session creation
        last_active: UTC timestamp of last activity
        ip_address: IP address of the session
        enabled: Whether the session is enabled
    """

    def __init__(self, session_id: str, identity_uid: str):
        """Initialize a new session.

        Args:
            session_id: Unique session identifier
            identity_uid: UID of the identity
        """
        self.session_id = session_id
        self.identity_uid = identity_uid
        self.created_at = datetime.now(timezone.utc)
        self.last_active = self.created_at
        self.ip_address = "localhost"
        self.enabled = True

    def to_dict(self) -> Dict:
        """Export session to dictionary for serialization.

        Returns:
            Dictionary representation of the session
        """
        return {
            "session_id": self.session_id,
            "identity_uid": self.identity_uid,
            "created_at": self.created_at.isoformat(),
            "last_active": self.last_active.isoformat(),
            "ip_address": self.ip_address,
            "enabled": self.enabled,
        }

    @staticmethod
    def from_dict(data: Dict) -> "Session":
        """Import session from dictionary.

        Args:
            data: Dictionary containing session data

        Returns:
            Session object

        Raises:
            SessionError: If session data is invalid
        """
        try:
            session = Session(data["session_id"], data["identity_uid"])
            session.created_at = datetime.fromisoformat(data["created_at"])
            session.last_active = datetime.fromisoformat(data["last_active"])
            session.ip_address = data.get("ip_address", "localhost")
            session.enabled = data.get("enabled", True)
            return session
        except (KeyError, ValueError) as e:
            raise SessionError(
                ErrorCode.E002_INVALID_ARGUMENT, f"Invalid session data: {e}"
            ) from e

    def update_activity(self) -> None:
        """Update last active timestamp to current time."""
        self.last_active = datetime.now(timezone.utc)

    def is_expired(self) -> bool:
        """Check if session has expired.

        A session is expired if:
        - It was created more than SESSION_ABSOLUTE_TIMEOUT_DAYS ago
        - It has been idle for more than SESSION_IDLE_TIMEOUT_HOURS

        Returns:
            True if session has expired
        """
        now = datetime.now(timezone.utc)

        # Check absolute timeout
        absolute_expiry = self.created_at + timedelta(days=SESSION_ABSOLUTE_TIMEOUT_DAYS)
        if now > absolute_expiry:
            logger.debug(f"Session {self.session_id} expired (absolute timeout)")
            return True

        # Check idle timeout
        idle_expiry = self.last_active + timedelta(hours=SESSION_IDLE_TIMEOUT_HOURS)
        if now > idle_expiry:
            logger.debug(f"Session {self.session_id} expired (idle timeout)")
            return True

        return False


class SessionManager:
    """Manages encrypted login sessions with expiration and integrity verification.

    Sessions are stored in an encrypted file using AES-256-GCM with a key derived
    from the master password. Each session file includes an HMAC for integrity
    verification.

    Attributes:
        sessions_file: Path to the encrypted sessions file
        encryption_key: AES-256 key for session encryption
        sessions: Dictionary mapping session_id to Session objects
        current_session_id: ID of the current active session
    """

    def __init__(self, sessions_file: str, master_password: str):
        """Initialize the session manager with encryption.

        Args:
            sessions_file: Path to the encrypted sessions file
            master_password: Master password for key derivation

        Raises:
            SessionError: If initialization fails
        """
        self.sessions_file = Path(sessions_file)
        self.sessions: Dict[str, Session] = {}
        self.current_session_id: Optional[str] = None

        # Derive encryption key from master password
        # Using SHA-256(password + salt) for session encryption
        # This is separate from identity encryption
        salt = b"jarvis_session_encryption_v1"
        key_material = (master_password.encode() + salt)
        self.encryption_key = hashlib.sha256(key_material).digest()

        # Ensure parent directory exists
        self.sessions_file.parent.mkdir(parents=True, exist_ok=True)

        # Load existing sessions
        self._load_sessions()

        logger.info(f"Session manager initialized: {len(self.sessions)} sessions loaded")

    def _compute_hmac(self, data: bytes) -> bytes:
        """Compute HMAC-SHA256 for data integrity verification.

        Args:
            data: Data to compute HMAC for

        Returns:
            HMAC digest (32 bytes)
        """
        return hmac.new(self.encryption_key, data, hashlib.sha256).digest()

    def _load_sessions(self) -> None:
        """Load and decrypt sessions from file.

        Sessions are automatically validated:
        - HMAC integrity check
        - Expiration check
        - Schema validation

        Expired or invalid sessions are discarded.
        """
        if not self.sessions_file.exists():
            logger.debug("No existing sessions file found")
            return

        try:
            # Read encrypted file
            encrypted_data = self.sessions_file.read_bytes()

            if len(encrypted_data) < SESSION_NONCE_SIZE + 32:
                logger.warning("Sessions file too short, ignoring")
                return

            # Extract components: nonce + ciphertext + hmac
            nonce = encrypted_data[:SESSION_NONCE_SIZE]
            hmac_digest = encrypted_data[-32:]
            ciphertext = encrypted_data[SESSION_NONCE_SIZE:-32]

            # Verify HMAC
            expected_hmac = self._compute_hmac(nonce + ciphertext)
            if not hmac.compare_digest(expected_hmac, hmac_digest):
                logger.error("Sessions file HMAC verification failed - possible tampering")
                return

            # Decrypt sessions
            cipher = AESGCM(self.encryption_key)
            plaintext = cipher.decrypt(nonce, ciphertext, None)

            # Parse JSON
            data = json.loads(plaintext.decode('utf-8'))

            # Import sessions and validate
            for session_id, session_data in data.items():
                try:
                    session = Session.from_dict(session_data)

                    # Check if session is expired
                    if session.is_expired():
                        logger.debug(f"Discarding expired session: {session_id}")
                        continue

                    self.sessions[session_id] = session

                except SessionError as e:
                    logger.warning(f"Skipping invalid session {session_id}: {e}")
                    continue

            logger.info(f"Loaded {len(self.sessions)} valid sessions")

        except json.JSONDecodeError as e:
            logger.error(f"Sessions file JSON decoding failed: {e}")
        except Exception as e:
            logger.error(f"Failed to load sessions: {e}", exc_info=True)

    def save_sessions(self) -> None:
        """Encrypt and save sessions to file with HMAC integrity protection.

        Uses atomic write (write to temp file, then rename) to prevent
        corruption during crashes or interruptions.

        Raises:
            SessionError: If save operation fails
        """
        try:
            # Clean up expired sessions before saving
            self._cleanup_expired_sessions()

            # Serialize sessions to JSON
            data = {sid: session.to_dict() for sid, session in self.sessions.items()}
            plaintext = json.dumps(data, indent=2).encode('utf-8')

            # Encrypt with AES-256-GCM
            nonce = secrets.token_bytes(SESSION_NONCE_SIZE)
            cipher = AESGCM(self.encryption_key)
            ciphertext = cipher.encrypt(nonce, plaintext, None)

            # Compute HMAC for integrity
            hmac_digest = self._compute_hmac(nonce + ciphertext)

            # Combine: nonce + ciphertext + hmac
            encrypted_data = nonce + ciphertext + hmac_digest

            # Atomic write: write to temp file, then rename
            temp_file = self.sessions_file.with_suffix('.tmp')
            temp_file.write_bytes(encrypted_data)
            temp_file.replace(self.sessions_file)

            logger.debug(f"Saved {len(self.sessions)} sessions to {self.sessions_file}")

        except OSError as e:
            logger.error(f"Failed to save sessions: {e}")
            raise SessionError(
                ErrorCode.E004_FILE_WRITE_ERROR, f"Cannot save sessions: {e}"
            ) from e

    def _cleanup_expired_sessions(self) -> None:
        """Remove expired sessions from memory."""
        expired_ids = [
            sid for sid, session in self.sessions.items() if session.is_expired()
        ]

        for sid in expired_ids:
            logger.debug(f"Removing expired session: {sid}")
            del self.sessions[sid]

            # Clear current session if it expired
            if self.current_session_id == sid:
                self.current_session_id = None

    def create_session(self, identity_uid: str) -> Session:
        """Create a new encrypted session.

        Args:
            identity_uid: UID of the identity to create session for

        Returns:
            Newly created session

        Raises:
            SessionError: If session creation fails
        """
        try:
            # Generate cryptographically secure session ID
            session_id = secrets.token_urlsafe(32)

            # Create session
            session = Session(session_id, identity_uid)
            self.sessions[session_id] = session
            self.current_session_id = session_id

            # Persist to disk
            self.save_sessions()

            logger.info(f"Created new session for identity {identity_uid}")
            return session

        except Exception as e:
            logger.error(f"Session creation failed: {e}")
            raise SessionError(
                ErrorCode.E002_INVALID_ARGUMENT, f"Cannot create session: {e}"
            ) from e

    def get_session(self, session_id: str) -> Optional[Session]:
        """Get a session by ID and validate it.

        Args:
            session_id: Session identifier

        Returns:
            Session object if valid and not expired, None otherwise
        """
        session = self.sessions.get(session_id)

        if session is None:
            return None

        # Check if expired
        if session.is_expired():
            logger.debug(f"Session {session_id} has expired")
            del self.sessions[session_id]
            return None

        return session

    def get_current_session(self) -> Optional[Session]:
        """Get the current active session.

        Returns:
            Current session if valid and not expired, None otherwise
        """
        if self.current_session_id:
            return self.get_session(self.current_session_id)
        return None

    def delete_session(self, session_id: str) -> bool:
        """Delete a session and persist changes.

        Args:
            session_id: Session identifier to delete

        Returns:
            True if session was deleted, False if not found
        """
        if session_id in self.sessions:
            del self.sessions[session_id]

            # Clear current session if it was deleted
            if self.current_session_id == session_id:
                self.current_session_id = None

            self.save_sessions()
            logger.info(f"Deleted session: {session_id}")
            return True

        return False

    def delete_all_sessions(self) -> None:
        """Delete all sessions and clear the sessions file.

        Raises:
            SessionError: If deletion fails
        """
        self.sessions.clear()
        self.current_session_id = None

        try:
            if self.sessions_file.exists():
                self.sessions_file.unlink()
            logger.info("Deleted all sessions")
        except OSError as e:
            logger.error(f"Failed to delete sessions file: {e}")
            raise SessionError(
                ErrorCode.E004_FILE_WRITE_ERROR, f"Cannot delete sessions file: {e}"
            ) from e

    def update_session_activity(
        self, session_id: str, ip_address: Optional[str] = None
    ) -> bool:
        """Update session activity timestamp and optionally IP address.

        Args:
            session_id: Session identifier
            ip_address: Optional new IP address

        Returns:
            True if session was updated, False if not found or expired
        """
        session = self.get_session(session_id)

        if session is None:
            return False

        session.update_activity()
        if ip_address:
            session.ip_address = ip_address

        self.save_sessions()
        return True

    def revoke_session(self, session_id: str) -> bool:
        """Revoke a session by disabling it.

        Args:
            session_id: Session identifier to revoke

        Returns:
            True if session was revoked, False if not found
        """
        session = self.get_session(session_id)

        if session is None:
            return False

        session.enabled = False
        self.save_sessions()
        logger.info(f"Revoked session: {session_id}")
        return True

    def list_active_sessions(self) -> list[Session]:
        """Get list of all active (non-expired, enabled) sessions.

        Returns:
            List of active Session objects
        """
        active = []
        for session in list(self.sessions.values()):
            if not session.is_expired() and session.enabled:
                active.append(session)

        return active

    def cleanup(self) -> int:
        """Remove all expired sessions and persist changes.

        Returns:
            Number of sessions cleaned up
        """
        initial_count = len(self.sessions)
        self._cleanup_expired_sessions()
        cleaned_count = initial_count - len(self.sessions)

        if cleaned_count > 0:
            self.save_sessions()
            logger.info(f"Cleaned up {cleaned_count} expired sessions")

        return cleaned_count
