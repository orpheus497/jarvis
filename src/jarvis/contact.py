"""
Jarvis - Contact management system.

Created by orpheus497
"""

import json
import os
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pathlib import Path

import aiofiles

logger = logging.getLogger(__name__)


class Contact:
    """Represents a contact in the messenger."""
    
    def __init__(self, uid: str, username: str, public_key: str, 
                 host: str, port: int, fingerprint: str, 
                 verified: bool = False, notes: str = ""):
        self.uid = uid
        self.username = username
        self.public_key = public_key
        self.host = host
        self.port = port
        self.fingerprint = fingerprint
        self.verified = verified
        self.notes = notes
        self.last_seen: Optional[str] = None
        self.status: str = "offline"
        self.added_at = datetime.now(timezone.utc).isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert contact to dictionary for storage."""
        return {
            'uid': self.uid,
            'username': self.username,
            'public_key': self.public_key,
            'host': self.host,
            'port': self.port,
            'fingerprint': self.fingerprint,
            'verified': self.verified,
            'notes': self.notes,
            'last_seen': self.last_seen,
            'status': self.status,
            'added_at': self.added_at
        }
    
    @staticmethod
    def from_dict(data: Dict[str, Any]) -> 'Contact':
        """Create contact from dictionary."""
        contact = Contact(
            uid=data['uid'],
            username=data['username'],
            public_key=data['public_key'],
            host=data['host'],
            port=data['port'],
            fingerprint=data['fingerprint'],
            verified=data.get('verified', False),
            notes=data.get('notes', '')
        )
        contact.last_seen = data.get('last_seen')
        contact.status = data.get('status', 'offline')
        contact.added_at = data.get('added_at', contact.added_at)
        return contact
    
    def update_last_seen(self) -> None:
        """Update last seen timestamp."""
        self.last_seen = datetime.now(timezone.utc).isoformat()

    def mark_online(self) -> None:
        """Mark contact as online."""
        self.status = "online"
        self.update_last_seen()

    def mark_offline(self) -> None:
        """Mark contact as offline."""
        self.status = "offline"


class ContactManager:
    """Manages contacts and their persistent storage."""
    
    def __init__(self, contacts_file: str):
        self.contacts_file = contacts_file
        self.contacts: Dict[str, Contact] = {}  # uid -> Contact
        self._load_contacts()
    
    def _load_contacts(self) -> None:
        """Load contacts from file."""
        if os.path.exists(self.contacts_file):
            try:
                with open(self.contacts_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                for uid, contact_data in data.items():
                    self.contacts[uid] = Contact.from_dict(contact_data)
                logger.info(f"Loaded {len(self.contacts)} contacts from {self.contacts_file}")
            except (IOError, OSError) as e:
                logger.error(f"Failed to read contacts file: {e}")
                raise IOError(f"Cannot load contacts: {e}") from e
            except json.JSONDecodeError as e:
                logger.error(f"Corrupted contacts file: {e}")
                # Don't raise - start with empty contacts if file is corrupted
                logger.warning("Starting with empty contacts due to corrupted file")
            except Exception as e:
                logger.error(f"Unexpected error loading contacts: {e}")
                raise

    async def save_contacts_async(self) -> None:
        """Save contacts to file asynchronously."""
        try:
            data = {uid: contact.to_dict() for uid, contact in self.contacts.items()}
            json_data = json.dumps(data, indent=2, ensure_ascii=False)

            # Write to temporary file first
            temp_file = f"{self.contacts_file}.tmp"
            async with aiofiles.open(temp_file, 'w', encoding='utf-8') as f:
                await f.write(json_data)

            # Atomic rename
            os.replace(temp_file, self.contacts_file)
            logger.debug(f"Saved {len(self.contacts)} contacts to {self.contacts_file}")

        except (IOError, OSError) as e:
            logger.error(f"Failed to save contacts: {e}")
            raise IOError(f"Cannot save contacts: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error saving contacts: {e}")
            raise

    def save_contacts(self) -> None:
        """Save contacts to file synchronously (legacy support)."""
        try:
            data = {uid: contact.to_dict() for uid, contact in self.contacts.items()}
            json_data = json.dumps(data, indent=2, ensure_ascii=False)

            # Write to temporary file first for atomicity
            temp_file = f"{self.contacts_file}.tmp"
            with open(temp_file, 'w', encoding='utf-8') as f:
                f.write(json_data)

            # Atomic rename
            os.replace(temp_file, self.contacts_file)
            logger.debug(f"Saved {len(self.contacts)} contacts to {self.contacts_file}")

        except (IOError, OSError) as e:
            logger.error(f"Failed to save contacts: {e}")
            raise IOError(f"Cannot save contacts: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error saving contacts: {e}")
            raise
    
    def add_contact(self, contact: Contact) -> bool:
        """Add a contact. Returns True if added, False if already exists."""
        if contact.uid in self.contacts:
            return False
        self.contacts[contact.uid] = contact
        self.save_contacts()
        return True
    
    def remove_contact(self, uid: str) -> bool:
        """Remove a contact. Returns True if removed, False if not found."""
        if uid in self.contacts:
            del self.contacts[uid]
            self.save_contacts()
            return True
        return False
    
    def get_contact(self, uid: str) -> Optional[Contact]:
        """Get a contact by UID."""
        return self.contacts.get(uid)
    
    def get_contact_by_username(self, username: str) -> Optional[Contact]:
        """Get a contact by username."""
        for contact in self.contacts.values():
            if contact.username == username:
                return contact
        return None

    def get_contact_by_fingerprint(self, fingerprint: str) -> Optional[Contact]:
        """Get a contact by fingerprint."""
        for contact in self.contacts.values():
            if contact.fingerprint == fingerprint:
                return contact
        return None
    
    def update_contact(self, uid: str, **kwargs) -> bool:
        """Update contact fields. Returns True if updated."""
        contact = self.contacts.get(uid)
        if not contact:
            return False
        
        for key, value in kwargs.items():
            if hasattr(contact, key):
                setattr(contact, key, value)
        
        self.save_contacts()
        return True
    
    def get_all_contacts(self) -> List[Contact]:
        """Get all contacts sorted by username."""
        return sorted(self.contacts.values(), key=lambda c: c.username.lower())
    
    def mark_verified(self, uid: str) -> bool:
        """Mark a contact as verified."""
        return self.update_contact(uid, verified=True)

    def mark_online(self, uid: str) -> None:
        """Mark a contact as online."""
        contact = self.contacts.get(uid)
        if contact:
            contact.mark_online()
            self.save_contacts()

    def mark_offline(self, uid: str) -> None:
        """Mark a contact as offline."""
        contact = self.contacts.get(uid)
        if contact:
            contact.mark_offline()
            self.save_contacts()

    async def mark_online_async(self, uid: str) -> None:
        """Mark a contact as online (async version)."""
        contact = self.contacts.get(uid)
        if contact:
            contact.mark_online()
            await self.save_contacts_async()

    async def mark_offline_async(self, uid: str) -> None:
        """Mark a contact as offline (async version)."""
        contact = self.contacts.get(uid)
        if contact:
            contact.mark_offline()
            await self.save_contacts_async()
    
    def delete_all_contacts(self) -> bool:
        """
        Delete all contacts and the contacts file.
        Returns True if successful.
        """
        self.contacts.clear()
        if os.path.exists(self.contacts_file):
            try:
                os.remove(self.contacts_file)
                logger.info("Deleted all contacts and contacts file")
                return True
            except (IOError, OSError) as e:
                logger.error(f"Failed to delete contacts file: {e}")
                return False
        return True
