"""
Jarvis - Backup Management System

This module handles encrypted backups of Jarvis data including messages,
contacts, groups, and configuration. Supports scheduled backups, rotation,
restoration, and verification.

Author: orpheus497
Version: 2.0.0
"""

import asyncio
import logging
import tarfile
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from .constants import (
    BACKUP_COMPRESSION_LEVEL,
    BACKUP_DIR,
    BACKUP_MAX_COUNT,
    BACKUP_RETENTION_DAYS,
    BACKUP_SCHEDULE_INTERVAL,
    DEFAULT_DATA_DIR,
    KEY_SIZE,
    NONCE_SIZE,
    SALT_SIZE,
)
from .errors import ErrorCode, JarvisError

logger = logging.getLogger(__name__)


class BackupManager:
    """Manages encrypted backups of Jarvis data.

    Handles backup creation, encryption, scheduling, rotation,
    restoration, and verification of Jarvis user data.

    Attributes:
        data_dir: Path to Jarvis data directory
        backup_dir: Path to backups directory
        retention_days: Number of days to keep backups
        max_backups: Maximum number of backups to keep
        schedule_task: Asyncio task for scheduled backups
    """

    def __init__(
        self,
        data_dir: Optional[Path] = None,
        backup_dir: Optional[Path] = None,
        retention_days: int = BACKUP_RETENTION_DAYS,
        max_backups: int = BACKUP_MAX_COUNT,
    ):
        """Initialize backup manager.

        Args:
            data_dir: Path to Jarvis data directory
            backup_dir: Path to store backups
            retention_days: Number of days to keep backups
            max_backups: Maximum number of backups to keep
        """
        if data_dir is None:
            data_dir = Path(DEFAULT_DATA_DIR).expanduser()

        if backup_dir is None:
            backup_dir = data_dir / BACKUP_DIR

        self.data_dir = Path(data_dir)
        self.backup_dir = Path(backup_dir)
        self.retention_days = retention_days
        self.max_backups = max_backups
        self.schedule_task: Optional[asyncio.Task] = None

        # Ensure backup directory exists
        self.backup_dir.mkdir(parents=True, exist_ok=True)

        logger.info(
            f"Backup manager initialized: {self.backup_dir} "
            f"(retention={retention_days} days, max={max_backups})"
        )

    def create_backup(self, password: Optional[str] = None) -> Path:
        """Create a backup of Jarvis data.

        Args:
            password: Optional password for backup encryption

        Returns:
            Path to the created backup file

        Raises:
            JarvisError: If backup creation fails
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"jarvis_backup_{timestamp}.tar.gz"

        if password:
            backup_name += ".enc"

        backup_path = self.backup_dir / backup_name

        logger.info(f"Creating backup: {backup_name}")

        try:
            # Create temporary unencrypted backup
            temp_backup = self.backup_dir / f"temp_{timestamp}.tar.gz"

            # Create tar.gz archive
            with tarfile.open(temp_backup, "w:gz", compresslevel=BACKUP_COMPRESSION_LEVEL) as tar:
                # Add all files from data directory
                for item in self.data_dir.iterdir():
                    # Skip backups directory and temp files
                    if item.name == BACKUP_DIR or item.name.startswith("."):
                        continue

                    # Add to archive
                    tar.add(item, arcname=item.name)
                    logger.debug(f"Added to backup: {item.name}")

            # Encrypt if password provided
            if password:
                self._encrypt_backup(temp_backup, backup_path, password)
                temp_backup.unlink()  # Remove unencrypted temp file
            else:
                temp_backup.rename(backup_path)

            # Get backup size
            backup_size = backup_path.stat().st_size

            logger.info(f"Backup created: {backup_name} ({backup_size} bytes)")

            # Clean up old backups
            self.delete_old_backups()

            return backup_path

        except Exception as e:
            # Clean up temp files on error
            if "temp_backup" in locals() and Path(temp_backup).exists():
                Path(temp_backup).unlink()

            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR, f"Backup creation failed: {e}", {"error": str(e)}
            )

    def _encrypt_backup(self, source: Path, dest: Path, password: str) -> None:
        """Encrypt a backup file with a password.

        Args:
            source: Source unencrypted file
            dest: Destination encrypted file
            password: Encryption password

        Raises:
            JarvisError: If encryption fails
        """
        try:
            # Generate salt
            salt = self._generate_salt()

            # Derive key from password
            key = self._derive_key(password, salt)

            # Read source file
            with open(source, "rb") as f:
                plaintext = f.read()

            # Encrypt
            cipher = ChaCha20Poly1305(key)
            nonce = self._generate_nonce()
            ciphertext = cipher.encrypt(nonce, plaintext, None)

            # Write encrypted file: salt + nonce + ciphertext
            with open(dest, "wb") as f:
                f.write(salt)
                f.write(nonce)
                f.write(ciphertext)

            logger.debug(f"Encrypted backup: {dest.name}")

        except Exception as e:
            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR, f"Backup encryption failed: {e}", {"error": str(e)}
            )

    def _decrypt_backup(self, source: Path, dest: Path, password: str) -> None:
        """Decrypt a backup file.

        Args:
            source: Source encrypted file
            dest: Destination decrypted file
            password: Decryption password

        Raises:
            JarvisError: If decryption fails
        """
        try:
            # Read encrypted file
            with open(source, "rb") as f:
                salt = f.read(SALT_SIZE)
                nonce = f.read(NONCE_SIZE)
                ciphertext = f.read()

            # Derive key from password
            key = self._derive_key(password, salt)

            # Decrypt
            cipher = ChaCha20Poly1305(key)
            plaintext = cipher.decrypt(nonce, ciphertext, None)

            # Write decrypted file
            with open(dest, "wb") as f:
                f.write(plaintext)

            logger.debug(f"Decrypted backup: {source.name}")

        except Exception as e:
            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR, f"Backup decryption failed: {e}", {"error": str(e)}
            )

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password.

        Args:
            password: User password
            salt: Random salt

        Returns:
            Derived key
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password.encode())

    def _generate_salt(self) -> bytes:
        """Generate random salt.

        Returns:
            Random salt bytes
        """
        import secrets

        return secrets.token_bytes(SALT_SIZE)

    def _generate_nonce(self) -> bytes:
        """Generate random nonce.

        Returns:
            Random nonce bytes
        """
        import secrets

        return secrets.token_bytes(NONCE_SIZE)

    def restore_backup(self, backup_path: Path, password: Optional[str] = None) -> None:
        """Restore from a backup file.

        Args:
            backup_path: Path to backup file
            password: Password if backup is encrypted

        Raises:
            JarvisError: If restoration fails
        """
        if not backup_path.exists():
            raise JarvisError(
                ErrorCode.E003_FILE_NOT_FOUND, f"Backup file not found: {backup_path}"
            )

        logger.info(f"Restoring from backup: {backup_path.name}")

        try:
            # Decrypt if needed
            if backup_path.suffix == ".enc":
                if not password:
                    raise JarvisError(
                        ErrorCode.E002_INVALID_ARGUMENT, "Password required for encrypted backup"
                    )

                temp_decrypted = self.backup_dir / f"temp_decrypt_{backup_path.stem}"
                self._decrypt_backup(backup_path, temp_decrypted, password)
                extract_file = temp_decrypted
            else:
                extract_file = backup_path

            # Extract tar.gz
            with tarfile.open(extract_file, "r:gz") as tar:
                # Extract to data directory
                tar.extractall(path=self.data_dir)
                logger.info("Backup extracted successfully")

            # Clean up temp files
            if backup_path.suffix == ".enc" and extract_file.exists():
                extract_file.unlink()

            logger.info(f"Backup restored: {backup_path.name}")

        except JarvisError:
            raise
        except Exception as e:
            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR, f"Backup restoration failed: {e}", {"error": str(e)}
            )

    def list_backups(self) -> List[Dict]:
        """List all available backups.

        Returns:
            List of backup information dictionaries
        """
        backups = []

        for backup_file in sorted(self.backup_dir.glob("jarvis_backup_*.tar.gz*")):
            if backup_file.name.startswith("temp_"):
                continue

            stat = backup_file.stat()
            backups.append(
                {
                    "filename": backup_file.name,
                    "path": str(backup_file),
                    "size": stat.st_size,
                    "created": stat.st_mtime,
                    "encrypted": backup_file.suffix == ".enc",
                }
            )

        return backups

    def delete_old_backups(self) -> int:
        """Delete old backups based on retention policy.

        Returns:
            Number of backups deleted
        """
        backups = self.list_backups()

        if not backups:
            return 0

        deleted_count = 0
        now = datetime.now().timestamp()
        retention_seconds = self.retention_days * 86400

        # Delete by age
        for backup in backups:
            age = now - backup["created"]
            if age > retention_seconds:
                backup_path = Path(backup["path"])
                backup_path.unlink()
                logger.info(f"Deleted old backup: {backup['filename']}")
                deleted_count += 1

        # Delete excess backups (keep max_backups newest)
        remaining = [b for b in backups if Path(b["path"]).exists()]
        if len(remaining) > self.max_backups:
            # Sort by creation time
            remaining.sort(key=lambda x: x["created"])

            # Delete oldest excess backups
            excess = len(remaining) - self.max_backups
            for backup in remaining[:excess]:
                backup_path = Path(backup["path"])
                backup_path.unlink()
                logger.info(f"Deleted excess backup: {backup['filename']}")
                deleted_count += 1

        if deleted_count > 0:
            logger.info(f"Deleted {deleted_count} old backups")

        return deleted_count

    def verify_backup(self, backup_path: Path, password: Optional[str] = None) -> bool:
        """Verify a backup file integrity.

        Args:
            backup_path: Path to backup file
            password: Password if backup is encrypted

        Returns:
            True if backup is valid

        Raises:
            JarvisError: If verification fails
        """
        try:
            # Decrypt if needed
            if backup_path.suffix == ".enc":
                if not password:
                    raise JarvisError(
                        ErrorCode.E002_INVALID_ARGUMENT, "Password required for encrypted backup"
                    )

                temp_decrypted = self.backup_dir / f"temp_verify_{backup_path.stem}"
                self._decrypt_backup(backup_path, temp_decrypted, password)
                verify_file = temp_decrypted
            else:
                verify_file = backup_path

            # Try to open and list contents
            with tarfile.open(verify_file, "r:gz") as tar:
                members = tar.getmembers()
                logger.debug(f"Backup contains {len(members)} items")

            # Clean up temp files
            if backup_path.suffix == ".enc" and verify_file.exists():
                verify_file.unlink()

            logger.info(f"Backup verified: {backup_path.name}")
            return True

        except Exception as e:
            logger.error(f"Backup verification failed: {e}")
            return False

    async def schedule_backup(
        self, interval: int = BACKUP_SCHEDULE_INTERVAL, password: Optional[str] = None
    ) -> None:
        """Schedule automatic backups.

        Args:
            interval: Backup interval in seconds
            password: Optional password for backup encryption
        """
        logger.info(f"Scheduled backups enabled: every {interval} seconds")

        while True:
            try:
                await asyncio.sleep(interval)
                self.create_backup(password=password)
                logger.info("Scheduled backup completed")
            except asyncio.CancelledError:
                logger.info("Scheduled backups cancelled")
                break
            except Exception as e:
                logger.error(f"Scheduled backup failed: {e}")

    def start_scheduled_backups(
        self, interval: int = BACKUP_SCHEDULE_INTERVAL, password: Optional[str] = None
    ) -> None:
        """Start scheduled backups as an asyncio task.

        Args:
            interval: Backup interval in seconds
            password: Optional password for backup encryption
        """
        if self.schedule_task and not self.schedule_task.done():
            logger.warning("Scheduled backups already running")
            return

        self.schedule_task = asyncio.create_task(self.schedule_backup(interval, password))
        logger.info("Started scheduled backup task")

    def stop_scheduled_backups(self) -> None:
        """Stop scheduled backups."""
        if self.schedule_task and not self.schedule_task.done():
            self.schedule_task.cancel()
            logger.info("Stopped scheduled backup task")

    def get_stats(self) -> Dict:
        """Get backup statistics.

        Returns:
            Dictionary with backup statistics
        """
        backups = self.list_backups()

        total_size = sum(b["size"] for b in backups)
        encrypted_count = sum(1 for b in backups if b["encrypted"])

        return {
            "total_backups": len(backups),
            "encrypted_backups": encrypted_count,
            "total_size_bytes": total_size,
            "backup_directory": str(self.backup_dir),
            "retention_days": self.retention_days,
            "max_backups": self.max_backups,
        }
