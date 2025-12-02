"""
Jarvis - Message storage and management.

Created by orpheus497
Version: 2.4.0

Handles message persistence, conversation history, and retrieval for both
direct messages and group chats.

Performance improvements:
- Write-behind caching with batching to reduce I/O operations
- Configurable batch size for message persistence
- Dirty flag tracking to avoid unnecessary saves
"""

import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiofiles

logger = logging.getLogger(__name__)

# Write-behind caching configuration
MESSAGE_SAVE_BATCH_SIZE = 10  # Save every N messages
MESSAGE_SAVE_INTERVAL = 5.0  # Or every N seconds (whichever comes first)

# Import search engine for SQLite support (optional)
try:
    from .search import MessageSearchEngine

    SEARCH_AVAILABLE = True
except ImportError:
    SEARCH_AVAILABLE = False
    MessageSearchEngine = None


class Message:
    """Represents a message in a conversation."""

    def __init__(
        self,
        contact_uid: str,
        content: str,
        sent_by_me: bool,
        timestamp: Optional[str] = None,
        message_id: Optional[str] = None,
        delivered: bool = False,
        read: bool = False,
        group_id: Optional[str] = None,
        sender_uid: Optional[str] = None,
    ):
        self.message_id = message_id or str(uuid.uuid4())
        self.contact_uid = contact_uid  # For direct messages
        self.content = content
        self.sent_by_me = sent_by_me
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.delivered = delivered
        self.read = read
        self.encrypted = True

        # Group chat specific fields
        self.group_id = group_id
        self.sender_uid = sender_uid  # UID of the actual sender in group chat

    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary for storage."""
        return {
            "message_id": self.message_id,
            "contact_uid": self.contact_uid,
            "content": self.content,
            "sent_by_me": self.sent_by_me,
            "timestamp": self.timestamp,
            "delivered": self.delivered,
            "read": self.read,
            "encrypted": self.encrypted,
            "group_id": self.group_id,
            "sender_uid": self.sender_uid,
        }

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "Message":
        """Create message from dictionary."""
        msg = Message(
            contact_uid=data["contact_uid"],
            content=data["content"],
            sent_by_me=data["sent_by_me"],
            timestamp=data["timestamp"],
            message_id=data["message_id"],
            delivered=data.get("delivered", False),
            read=data.get("read", False),
            group_id=data.get("group_id"),
            sender_uid=data.get("sender_uid"),
        )
        msg.encrypted = data.get("encrypted", True)
        return msg

    def mark_delivered(self) -> None:
        """Mark message as delivered."""
        self.delivered = True

    def mark_read(self) -> None:
        """Mark message as read."""
        self.read = True

    def is_group_message(self) -> bool:
        """Check if this is a group message."""
        return self.group_id is not None


class MessageStore:
    """Manages message storage and retrieval.

    Supports both JSON file storage (legacy) and SQLite storage (v2.0)
    with full-text search capabilities.
    """

    def __init__(self, messages_file: str, use_sqlite: bool = False):
        """Initialize message store.

        Args:
            messages_file: Path to messages file (JSON or SQLite)
            use_sqlite: Whether to use SQLite storage (enables search)
        """
        self.messages_file = messages_file
        self.messages: List[Message] = []
        self.use_sqlite = use_sqlite and SEARCH_AVAILABLE

        # Initialize search engine if using SQLite
        self.search_engine: Optional[MessageSearchEngine] = None
        if self.use_sqlite:
            db_path = Path(messages_file).parent / "messages.db"
            self.search_engine = MessageSearchEngine(db_path)

        # Write-behind caching state
        self._dirty = False  # Track if messages need to be saved
        self._unsaved_count = 0  # Number of unsaved messages
        self._last_save_time = time.time()  # Last save timestamp

        self._load_messages()

    def _load_messages(self) -> None:
        """Load messages from file."""
        if os.path.exists(self.messages_file):
            try:
                with open(self.messages_file, encoding="utf-8") as f:
                    data = json.load(f)
                self.messages = [Message.from_dict(msg_data) for msg_data in data]
                logger.info(f"Loaded {len(self.messages)} messages from {self.messages_file}")
            except OSError as e:
                logger.error(f"Failed to read messages file: {e}")
                raise OSError(f"Cannot load messages: {e}") from e
            except json.JSONDecodeError as e:
                logger.error(f"Corrupted messages file: {e}")
                # Don't raise - start with empty messages if file is corrupted
                logger.warning("Starting with empty messages due to corrupted file")
            except Exception as e:
                logger.error(f"Unexpected error loading messages: {e}")
                raise

    async def save_messages_async(self) -> None:
        """Save messages to file asynchronously and optionally to SQLite."""
        try:
            # Always save to JSON for backward compatibility
            data = [msg.to_dict() for msg in self.messages]
            json_data = json.dumps(data, indent=2, ensure_ascii=False)

            # Write to temporary file first
            temp_file = f"{self.messages_file}.tmp"
            async with aiofiles.open(temp_file, "w", encoding="utf-8") as f:
                await f.write(json_data)

            # Atomic rename
            os.replace(temp_file, self.messages_file)
            logger.debug(f"Saved {len(self.messages)} messages to {self.messages_file}")

            # Also save to SQLite if enabled
            if self.use_sqlite and self.search_engine:
                # Migrate all messages to SQLite
                for msg in self.messages:
                    self._index_message_in_search(msg)

        except OSError as e:
            logger.error(f"Failed to save messages: {e}")
            raise OSError(f"Cannot save messages: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error saving messages: {e}")
            raise

    def save_messages(self) -> None:
        """Save messages to file synchronously with write-behind caching state update."""
        try:
            # Always save to JSON for backward compatibility
            data = [msg.to_dict() for msg in self.messages]
            json_data = json.dumps(data, indent=2, ensure_ascii=False)

            # Write to temporary file first for atomicity
            temp_file = f"{self.messages_file}.tmp"
            with open(temp_file, "w", encoding="utf-8") as f:
                f.write(json_data)

            # Atomic rename
            os.replace(temp_file, self.messages_file)

            # Update caching state after successful save
            saved_count = self._unsaved_count
            self._dirty = False
            self._unsaved_count = 0
            self._last_save_time = time.time()

            logger.debug(
                f"Saved {saved_count} unsaved messages "
                f"(total: {len(self.messages)}) to {self.messages_file}"
            )

            # Also save to SQLite if enabled
            if self.use_sqlite and self.search_engine:
                # Migrate all messages to SQLite
                for msg in self.messages:
                    self._index_message_in_search(msg)

        except OSError as e:
            logger.error(f"Failed to save messages: {e}")
            raise OSError(f"Cannot save messages: {e}") from e
        except Exception as e:
            logger.error(f"Unexpected error saving messages: {e}")
            raise

    def add_message(
        self,
        sender_uid_or_message: any,
        receiver_uid: Optional[str] = None,
        content: Optional[str] = None,
        timestamp: Optional[str] = None,
        message_id: Optional[str] = None,
    ) -> None:
        """Add a message to the store with write-behind caching.

        Can be called in two ways:
        1. add_message(message_object) - Pass a Message object directly
        2. add_message(sender_uid, receiver_uid, content, timestamp, message_id) - Pass parameters

        Messages are batched and saved periodically to reduce I/O:
        - Every MESSAGE_SAVE_BATCH_SIZE messages
        - Every MESSAGE_SAVE_INTERVAL seconds
        - Or when flush() is called explicitly

        Args:
            sender_uid_or_message: Either a Message object or sender UID
            receiver_uid: Receiver UID (if using parameter mode)
            content: Message content (if using parameter mode)
            timestamp: ISO timestamp (if using parameter mode)
            message_id: Message ID (if using parameter mode)
        """
        # Check if first argument is a Message object
        if isinstance(sender_uid_or_message, Message):
            message = sender_uid_or_message
        else:
            # Create Message object from parameters
            # Note: For incoming messages, receiver_uid is used as contact_uid
            # to maintain consistency with existing message storage format
            message = Message(
                contact_uid=receiver_uid,
                content=content,
                sent_by_me=False,  # Incoming message
                timestamp=timestamp,
                message_id=message_id,
            )

        self.messages.append(message)
        self._dirty = True
        self._unsaved_count += 1

        logger.debug(
            f"Added message {message.message_id} from {message.contact_uid} "
            f"(unsaved: {self._unsaved_count})"
        )

        # Index in search engine immediately if enabled
        if self.use_sqlite and self.search_engine:
            self._index_message_in_search(message)

        # Check if we should save (batch reached or time interval exceeded)
        if self._should_save():
            self.save_messages()

    def add_group_message(
        self,
        group_id: str,
        sender_uid: str,
        content: str,
        timestamp: Optional[str] = None,
        message_id: Optional[str] = None,
    ) -> None:
        """Add a group message to the store.

        Args:
            group_id: Group ID
            sender_uid: Sender UID
            content: Message content
            timestamp: ISO timestamp
            message_id: Message ID
        """
        message = Message(
            contact_uid=sender_uid,  # For group messages, this is the sender
            content=content,
            sent_by_me=False,  # Incoming group message
            timestamp=timestamp,
            message_id=message_id,
            group_id=group_id,
            sender_uid=sender_uid,
        )
        self.add_message(message)

    def _should_save(self) -> bool:
        """Check if messages should be saved based on batching rules.

        Returns:
            True if save is needed (batch size or time interval reached)
        """
        if not self._dirty:
            return False

        # Save if batch size reached
        if self._unsaved_count >= MESSAGE_SAVE_BATCH_SIZE:
            logger.debug(f"Save triggered by batch size ({self._unsaved_count} messages)")
            return True

        # Save if time interval exceeded
        elapsed = time.time() - self._last_save_time
        if elapsed >= MESSAGE_SAVE_INTERVAL:
            logger.debug(f"Save triggered by time interval ({elapsed:.1f}s)")
            return True

        return False

    def flush(self) -> None:
        """Force immediate save of all unsaved messages.

        This should be called:
        - Before application shutdown
        - After critical operations
        - When explicit persistence is required
        """
        if self._dirty:
            logger.info(f"Flushing {self._unsaved_count} unsaved messages")
            self.save_messages()
        else:
            logger.debug("Flush called but no unsaved messages")

    def _index_message_in_search(self, message: Message) -> None:
        """Index a message in the search engine."""
        if not self.search_engine:
            return

        try:
            # Parse timestamp to Unix timestamp
            timestamp = datetime.fromisoformat(message.timestamp.replace("Z", "+00:00"))
            unix_timestamp = int(timestamp.timestamp())

            self.search_engine.index_message(
                message_id=message.message_id,
                sender=message.sender_uid or message.contact_uid,
                content=message.content,
                timestamp=unix_timestamp,
                recipient=message.contact_uid if not message.is_group_message() else None,
                group_id=message.group_id,
                message_type="text",
            )
            logger.debug(f"Indexed message {message.message_id} in search engine")
        except OSError as e:
            logger.error(f"Failed to index message in search: {e}")
            # Don't fail if indexing fails
        except Exception as e:
            logger.error(f"Unexpected error indexing message: {e}")
            # Don't fail if indexing fails

    def get_conversation(self, contact_uid: str, limit: Optional[int] = None) -> List[Message]:
        """
        Get all direct messages for a specific contact.
        Returns messages sorted by timestamp (oldest first).
        """
        conversation = [
            msg for msg in self.messages if msg.contact_uid == contact_uid and msg.group_id is None
        ]
        conversation.sort(key=lambda m: m.timestamp)
        if limit:
            return conversation[-limit:]
        return conversation

    def get_group_conversation(self, group_id: str, limit: Optional[int] = None) -> List[Message]:
        """
        Get all messages for a specific group.
        Returns messages sorted by timestamp (oldest first).
        """
        conversation = [msg for msg in self.messages if msg.group_id == group_id]
        conversation.sort(key=lambda m: m.timestamp)
        if limit:
            return conversation[-limit:]
        return conversation

    def get_recent_conversations(self, limit: int = 10) -> List[str]:
        """
        Get list of contact UIDs with recent direct conversations.
        Returns most recent conversations first.
        """
        conversations = {}
        for msg in self.messages:
            if msg.group_id is None:  # Only direct messages
                if msg.contact_uid not in conversations:
                    conversations[msg.contact_uid] = msg.timestamp
                else:
                    if msg.timestamp > conversations[msg.contact_uid]:
                        conversations[msg.contact_uid] = msg.timestamp

        sorted_contacts = sorted(conversations.items(), key=lambda x: x[1], reverse=True)
        return [contact for contact, _ in sorted_contacts[:limit]]

    def get_recent_group_conversations(self, limit: int = 10) -> List[str]:
        """
        Get list of group IDs with recent conversations.
        Returns most recent conversations first.
        """
        conversations = {}
        for msg in self.messages:
            if msg.group_id is not None:  # Only group messages
                if msg.group_id not in conversations:
                    conversations[msg.group_id] = msg.timestamp
                else:
                    if msg.timestamp > conversations[msg.group_id]:
                        conversations[msg.group_id] = msg.timestamp

        sorted_groups = sorted(conversations.items(), key=lambda x: x[1], reverse=True)
        return [group for group, _ in sorted_groups[:limit]]

    def mark_as_read(self, contact_uid: str) -> None:
        """Mark all direct messages from a contact as read."""
        modified = False
        for msg in self.messages:
            if (
                msg.contact_uid == contact_uid
                and msg.group_id is None
                and not msg.sent_by_me
                and not msg.read
            ):
                msg.mark_read()
                modified = True
        if modified:
            self.save_messages()
            logger.debug(f"Marked messages from {contact_uid} as read")

    def mark_conversation_read(self, contact_uid: str) -> None:
        """Alias for mark_as_read() for backward compatibility."""
        self.mark_as_read(contact_uid)

    def mark_group_as_read(self, group_id: str) -> None:
        """Mark all group messages as read."""
        modified = False
        for msg in self.messages:
            if msg.group_id == group_id and not msg.sent_by_me and not msg.read:
                msg.mark_read()
                modified = True
        if modified:
            self.save_messages()
            logger.debug(f"Marked messages in group {group_id} as read")

    def mark_group_conversation_read(self, group_id: str) -> None:
        """Alias for mark_group_as_read() for backward compatibility."""
        self.mark_group_as_read(group_id)

    def get_unread_count(self, contact_uid: str) -> int:
        """Get count of unread direct messages from a contact."""
        return sum(
            1
            for msg in self.messages
            if (
                msg.contact_uid == contact_uid
                and msg.group_id is None
                and not msg.sent_by_me
                and not msg.read
            )
        )

    def get_group_unread_count(self, group_id: str) -> int:
        """Get count of unread messages in a group."""
        return sum(
            1
            for msg in self.messages
            if msg.group_id == group_id and not msg.sent_by_me and not msg.read
        )

    def get_total_unread_count(self) -> int:
        """Get total count of unread messages from all contacts and groups."""
        return sum(1 for msg in self.messages if not msg.sent_by_me and not msg.read)

    def delete_conversation(self, contact_uid: str) -> None:
        """Delete all direct messages for a contact."""
        original_count = len(self.messages)
        self.messages = [
            msg
            for msg in self.messages
            if not (msg.contact_uid == contact_uid and msg.group_id is None)
        ]
        deleted_count = original_count - len(self.messages)
        self.save_messages()
        logger.info(f"Deleted {deleted_count} messages for contact {contact_uid}")

    def delete_group_conversation(self, group_id: str) -> None:
        """Delete all messages for a group."""
        original_count = len(self.messages)
        self.messages = [msg for msg in self.messages if msg.group_id != group_id]
        deleted_count = original_count - len(self.messages)
        self.save_messages()
        logger.info(f"Deleted {deleted_count} messages for group {group_id}")

    def search_messages(
        self,
        query: str,
        contact_uid: Optional[str] = None,
        group_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Message]:
        """
        Search messages by content.

        Uses SQLite FTS5 if enabled, otherwise falls back to simple search.
        Can filter by contact UID or group ID.

        Args:
            query: Search query
            contact_uid: Optional contact filter
            group_id: Optional group filter
            limit: Maximum results to return

        Returns:
            List of matching messages
        """
        # Use SQLite search if available
        if self.use_sqlite and self.search_engine:
            try:
                results = self.search_engine.search(
                    query=query, contact=contact_uid, group_id=group_id, limit=limit
                )

                # Convert search results back to Message objects
                messages = []
                for result in results:
                    # Find message in our in-memory list
                    for msg in self.messages:
                        if msg.message_id == result["message_id"]:
                            messages.append(msg)
                            break

                logger.debug(f"SQLite search for '{query}' found {len(messages)} results")
                return messages
            except OSError as e:
                logger.error(f"Search engine I/O error: {e}")
                # Fall back to simple search on error
            except Exception as e:
                logger.error(f"Search engine error: {e}")
                # Fall back to simple search on error

        # Fallback: simple in-memory search
        query_lower = query.lower()
        results = []
        for msg in self.messages:
            if query_lower in msg.content.lower():
                if contact_uid and msg.contact_uid != contact_uid:
                    continue
                if group_id and msg.group_id != group_id:
                    continue
                results.append(msg)

                if len(results) >= limit:
                    break

        logger.debug(f"In-memory search for '{query}' found {len(results)} results")
        return results

    def delete_all_messages(self) -> bool:
        """
        Delete all messages and the messages file.
        Returns True if successful.
        """
        self.messages.clear()
        if os.path.exists(self.messages_file):
            try:
                os.remove(self.messages_file)
                logger.info("Deleted all messages and messages file")
                return True
            except OSError as e:
                logger.error(f"Failed to delete messages file: {e}")
                return False
        return True
