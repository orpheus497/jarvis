"""
Jarvis - Identity management system.

Created by orpheus497

Manages user identity, UID generation, and secure storage.
"""

import json
import os
import logging
import aiofiles
from typing import Dict, Optional
from datetime import datetime, timezone

from . import crypto

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class Identity:
    """Represents user's identity with UID and cryptographic keys."""
    
    def __init__(self, uid: str, username: str, keypair: crypto.IdentityKeyPair):
        self.uid = uid
        self.username = username
        self.keypair = keypair
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.fingerprint = crypto.generate_fingerprint(keypair.get_public_key_bytes())
        self.listen_port = 5000  # Default port
    
    def to_dict(self) -> Dict:
        """Export identity to dictionary."""
        return {
            'uid': self.uid,
            'username': self.username,
            'keypair': self.keypair.to_dict(),
            'created_at': self.created_at,
            'fingerprint': self.fingerprint,
            'listen_port': self.listen_port
        }
    
    @staticmethod
    def from_dict(data: Dict) -> 'Identity':
        """Import identity from dictionary."""
        keypair = crypto.IdentityKeyPair.from_dict(data['keypair'])
        identity = Identity(data['uid'], data['username'], keypair)
        identity.created_at = data['created_at']
        identity.fingerprint = data['fingerprint']
        identity.listen_port = data.get('listen_port', 5000)
        return identity
    
    def get_shareable_info(self) -> Dict:
        """
        Get shareable identity information for adding as a contact.
        Does not include private key.
        """
        import base64
        return {
            'uid': self.uid,
            'username': self.username,
            'public_key': base64.b64encode(self.keypair.get_public_key_bytes()).decode('utf-8'),
            'fingerprint': self.fingerprint
        }


class IdentityManager:
    """Manages user identity with encrypted storage."""
    
    def __init__(self, identity_file: str):
        self.identity_file = identity_file
        self.identity: Optional[Identity] = None
    
    def create_identity(self, username: str, password: str, 
                       listen_port: int = 5000) -> Identity:
        """
        Create identity with unique UID.
        
        UID generation process:
        1. Generate cryptographically secure random UID
        2. Check for collisions (extremely unlikely)
        3. Generate keypair
        4. Store encrypted with password
        """
        # Generate unique UID
        uid = crypto.generate_uid()
        
        # Generate keypair
        keypair = crypto.IdentityKeyPair()
        
        # Create identity
        identity = Identity(uid, username, keypair)
        identity.listen_port = listen_port
        
        self.identity = identity
        self.save_identity(password)
        return identity
    
    def load_identity(self, password: str) -> Optional[Identity]:
        """
        Load identity from encrypted file.
        Returns None if file doesn't exist or password is incorrect.
        """
        if not os.path.exists(self.identity_file):
            logger.debug(f"Identity file does not exist: {self.identity_file}")
            return None

        try:
            with open(self.identity_file, 'r', encoding='utf-8') as f:
                encrypted_data = json.load(f)

            identity_data = crypto.decrypt_identity_file(encrypted_data, password)
            self.identity = Identity.from_dict(identity_data)
            logger.info(f"Identity loaded: {self.identity.username}")
            return self.identity
        except crypto.CryptoError as e:
            logger.warning(f"Failed to decrypt identity (incorrect password?): {e}")
            return None
        except json.JSONDecodeError as e:
            logger.error(f"Corrupted identity file (invalid JSON): {e}")
            return None
        except Exception as e:
            logger.error(f"Failed to load identity: {e}", exc_info=True)
            return None
    
    def save_identity(self, password: str) -> None:
        """Save identity to encrypted file (synchronous)."""
        if not self.identity:
            logger.warning("No identity to save")
            return

        try:
            identity_data = self.identity.to_dict()
            encrypted_data = crypto.encrypt_identity_file(identity_data, password)

            # Write atomically by writing to temp file first
            temp_file = self.identity_file + '.tmp'
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(encrypted_data, f, indent=2, ensure_ascii=False)

            # Rename temp file to actual file (atomic on POSIX systems)
            os.replace(temp_file, self.identity_file)
            logger.info(f"Identity saved: {self.identity.username}")
        except Exception as e:
            logger.error(f"Failed to save identity: {e}", exc_info=True)
            raise IOError(f"Failed to save identity: {e}") from e

    async def save_identity_async(self, password: str) -> None:
        """Save identity to encrypted file asynchronously."""
        if not self.identity:
            logger.warning("No identity to save")
            return

        try:
            identity_data = self.identity.to_dict()
            encrypted_data = crypto.encrypt_identity_file(identity_data, password)
            json_data = json.dumps(encrypted_data, indent=2, ensure_ascii=False)

            # Write atomically using async I/O
            temp_file = self.identity_file + '.tmp'
            async with aiofiles.open(temp_file, 'w', encoding='utf-8') as f:
                await f.write(json_data)

            # Rename temp file to actual file (atomic on POSIX systems)
            os.replace(temp_file, self.identity_file)
            logger.info(f"Identity saved (async): {self.identity.username}")
        except Exception as e:
            logger.error(f"Failed to save identity (async): {e}", exc_info=True)
            raise IOError(f"Failed to save identity: {e}") from e
    
    def identity_exists(self) -> bool:
        """Check if identity file exists."""
        return os.path.exists(self.identity_file)
    
    def update_listen_port(self, port: int, password: str):
        """Update listen port and save."""
        if self.identity:
            self.identity.listen_port = port
            self.save_identity(password)
    
    def change_password(self, old_password: str, new_password: str) -> bool:
        """
        Change identity password.
        Returns True if successful, False if old password is incorrect.
        """
        # Try to load with old password
        if not self.load_identity(old_password):
            return False
        
        # Save with new password
        self.save_identity(new_password)
        return True
    
    def export_complete_account(self, password: str, export_path: str,
                                contact_manager, message_store,
                                group_manager) -> bool:
        """
        Export complete account including identity, contacts, messages, and groups.

        Args:
            password: Account password for verification
            export_path: Path to save the complete export
            contact_manager: ContactManager instance for exporting contacts
            message_store: MessageStore instance for exporting messages
            group_manager: GroupManager instance for exporting groups

        Returns:
            True if successful, False if password is incorrect
        """
        # Verify password first
        if not self.load_identity(password):
            logger.error("Export failed: incorrect password")
            return False

        try:
            # Collect all account data
            export_data = {
                'version': '1.0',
                'export_type': 'complete_account',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'identity': self.identity.to_dict(),
                'contacts': {uid: contact.to_dict() for uid, contact in contact_manager.contacts.items()},
                'groups': {},
                'messages': {}
            }

            # Export groups if group_manager has the necessary methods
            if hasattr(group_manager, 'groups'):
                export_data['groups'] = {gid: group.to_dict() for gid, group in group_manager.groups.items()}
                logger.debug(f"Exported {len(export_data['groups'])} groups")

            # Export messages if message_store has the necessary methods
            if hasattr(message_store, 'get_all_messages'):
                export_data['messages'] = message_store.get_all_messages()
                logger.debug(f"Exported messages")

            # Encrypt the complete export with password
            encrypted_export = crypto.encrypt_identity_file(export_data, password)

            # Save to file atomically
            temp_file = export_path + '.tmp'
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(encrypted_export, f, indent=2, ensure_ascii=False)

            os.replace(temp_file, export_path)
            logger.info(f"Complete account exported to: {export_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to export account: {e}", exc_info=True)
            return False
    
    def delete_identity(self, password: str) -> bool:
        """
        Delete identity file after verifying password.
        Returns True if successful, False if password is incorrect or file doesn't exist.
        """
        # Verify password first
        if not self.load_identity(password):
            logger.error("Delete failed: incorrect password")
            return False

        # Delete identity file
        if os.path.exists(self.identity_file):
            try:
                username = self.identity.username if self.identity else "unknown"
                os.remove(self.identity_file)
                self.identity = None
                logger.info(f"Identity deleted: {username}")
                return True
            except Exception as e:
                logger.error(f"Failed to delete identity file: {e}", exc_info=True)
                return False

        logger.warning("Identity file does not exist, nothing to delete")
        return False
