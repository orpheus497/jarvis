"""
Jarvis - Message Queue for offline recipients.

Created by orpheus497
Version: 2.4.0

This module implements persistent message queuing for offline recipients.
Messages are queued when recipients are unreachable and delivered automatically
when they come online. Includes delivery receipts and retry logic.

Thread safety improvements:
- Added threading.Lock for all database operations
- Prevents concurrent access to SQLite connection
- Protects against database corruption in multi-threaded environment
"""

import json
import logging
import sqlite3
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from .constants import (
    MESSAGE_DELIVERY_RETRY_ATTEMPTS,
    MESSAGE_DELIVERY_RETRY_DELAY,
    MESSAGE_QUEUE_CLEANUP_INTERVAL,
    MESSAGE_QUEUE_MAX_AGE,
    MESSAGE_QUEUE_MAX_SIZE,
)

logger = logging.getLogger(__name__)


@dataclass
class QueuedMessage:
    """Represents a queued message."""

    queue_id: int
    recipient_uid: str
    sender_uid: str
    message_type: str
    message_data: str  # JSON encoded
    timestamp: float
    attempts: int
    last_attempt: Optional[float]
    next_retry: float
    expires_at: float

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    @classmethod
    def from_row(cls, row: tuple) -> "QueuedMessage":
        """Create from database row."""
        return cls(*row)


class MessageQueue:
    """
    Persistent message queue for offline recipients.

    Stores messages in SQLite database and handles automatic delivery
    when recipients come online. Includes retry logic and expiration.

    Thread Safety:
        All database operations are protected by a threading.Lock to prevent
        concurrent access and potential database corruption.
    """

    def __init__(self, db_path: Path):
        """
        Initialize message queue.

        Args:
            db_path: Path to SQLite database file
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self.conn: Optional[sqlite3.Connection] = None
        self.last_cleanup = time.time()

        # Thread safety: Lock for all database operations
        self._db_lock = threading.Lock()

        self._init_database()

    def _init_database(self):
        """Initialize database schema with thread-safe connection."""
        with self._db_lock:
            self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self.conn.row_factory = sqlite3.Row

            cursor = self.conn.cursor()

            # Create messages table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS queued_messages (
                    queue_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    recipient_uid TEXT NOT NULL,
                    sender_uid TEXT NOT NULL,
                    message_type TEXT NOT NULL,
                    message_data TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    attempts INTEGER DEFAULT 0,
                    last_attempt REAL,
                    next_retry REAL NOT NULL,
                    expires_at REAL NOT NULL
                )
            """
            )

            # Create indices separately (SQLite requires separate CREATE INDEX statements)
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_recipient ON queued_messages (recipient_uid)
            """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_expires ON queued_messages (expires_at)
            """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_next_retry ON queued_messages (next_retry)
            """
            )

            self.conn.commit()
            logger.info(f"Message queue database initialized: {self.db_path}")

    def enqueue(
        self, recipient_uid: str, sender_uid: str, message_type: str, message_data: Dict[str, Any]
    ) -> bool:
        """
        Add message to queue with thread-safe database access.

        Args:
            recipient_uid: Recipient's UID
            sender_uid: Sender's UID
            message_type: Type of message
            message_data: Message data dictionary

        Returns:
            True if queued successfully, False otherwise
        """
        try:
            # Check queue size for recipient
            count = self.get_pending_count(recipient_uid)
            if count >= MESSAGE_QUEUE_MAX_SIZE:
                logger.warning(f"Queue full for {recipient_uid}: {count} messages")
                return False

            # Calculate expiration
            now = time.time()
            expires_at = now + MESSAGE_QUEUE_MAX_AGE

            # Encode message data
            message_json = json.dumps(message_data)

            # Thread-safe database insert
            with self._db_lock:
                cursor = self.conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO queued_messages
                    (recipient_uid, sender_uid, message_type, message_data,
                     timestamp, next_retry, expires_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                    (recipient_uid, sender_uid, message_type, message_json, now, now, expires_at),
                )

                self.conn.commit()

            logger.info(
                f"Message queued for {recipient_uid} "
                f"(type: {message_type}, expires: {datetime.fromtimestamp(expires_at)})"
            )

            return True

        except Exception as e:
            logger.error(f"Failed to enqueue message: {e}", exc_info=True)
            return False

    def dequeue(self, recipient_uid: str, limit: int = 100) -> List[QueuedMessage]:
        """
        Get pending messages for recipient with thread-safe database access.

        Args:
            recipient_uid: Recipient's UID
            limit: Maximum messages to return

        Returns:
            List of queued messages ready for delivery
        """
        try:
            now = time.time()

            with self._db_lock:
                cursor = self.conn.cursor()
                cursor.execute(
                    """
                    SELECT * FROM queued_messages
                    WHERE recipient_uid = ?
                    AND next_retry <= ?
                    AND expires_at > ?
                    AND attempts < ?
                    ORDER BY timestamp ASC
                    LIMIT ?
                """,
                    (recipient_uid, now, now, MESSAGE_DELIVERY_RETRY_ATTEMPTS, limit),
                )

                messages = [QueuedMessage.from_row(row) for row in cursor.fetchall()]

            logger.debug(f"Dequeued {len(messages)} messages for {recipient_uid}")

            return messages

        except Exception as e:
            logger.error(f"Failed to dequeue messages: {e}", exc_info=True)
            return []

    def mark_delivered(self, queue_id: int) -> bool:
        """
        Mark message as successfully delivered and remove from queue with thread-safe database access.

        Args:
            queue_id: Queue ID of delivered message

        Returns:
            True if successful, False otherwise
        """
        try:
            with self._db_lock:
                cursor = self.conn.cursor()
                cursor.execute(
                    """
                    DELETE FROM queued_messages WHERE queue_id = ?
                """,
                    (queue_id,),
                )

                self.conn.commit()
                rowcount = cursor.rowcount

            if rowcount > 0:
                logger.info(f"Message {queue_id} marked as delivered and removed")
                return True
            else:
                logger.warning(f"Message {queue_id} not found in queue")
                return False

        except Exception as e:
            logger.error(f"Failed to mark message delivered: {e}", exc_info=True)
            return False

    def mark_failed(self, queue_id: int) -> bool:
        """
        Mark delivery attempt failed and schedule retry with thread-safe database access.

        Args:
            queue_id: Queue ID of failed message

        Returns:
            True if successful, False otherwise
        """
        try:
            now = time.time()

            with self._db_lock:
                cursor = self.conn.cursor()

                # Get current attempts
                cursor.execute(
                    """
                    SELECT attempts FROM queued_messages WHERE queue_id = ?
                """,
                    (queue_id,),
                )

                row = cursor.fetchone()
                if not row:
                    logger.warning(f"Message {queue_id} not found")
                    return False

                attempts = row[0] + 1

                # Calculate next retry with exponential backoff
                backoff = MESSAGE_DELIVERY_RETRY_DELAY * (2 ** (attempts - 1))
                next_retry = now + backoff

                # Update message
                cursor.execute(
                    """
                    UPDATE queued_messages
                    SET attempts = ?,
                        last_attempt = ?,
                        next_retry = ?
                    WHERE queue_id = ?
                """,
                    (attempts, now, next_retry, queue_id),
                )

                self.conn.commit()

            logger.info(
                f"Message {queue_id} delivery failed "
                f"(attempt {attempts}, next retry in {backoff}s)"
            )

            return True

        except Exception as e:
            logger.error(f"Failed to mark message failed: {e}", exc_info=True)
            return False

    def get_pending_count(self, recipient_uid: str) -> int:
        """
        Get count of pending messages for recipient with thread-safe database access.

        Args:
            recipient_uid: Recipient's UID

        Returns:
            Number of pending messages
        """
        try:
            now = time.time()

            with self._db_lock:
                cursor = self.conn.cursor()
                cursor.execute(
                    """
                    SELECT COUNT(*) FROM queued_messages
                    WHERE recipient_uid = ?
                    AND expires_at > ?
                """,
                    (recipient_uid, now),
                )

                count = cursor.fetchone()[0]

            return count

        except Exception as e:
            logger.error(f"Failed to get pending count: {e}", exc_info=True)
            return 0

    def get_all_recipients(self) -> List[str]:
        """
        Get list of all recipients with pending messages with thread-safe database access.

        Returns:
            List of recipient UIDs
        """
        try:
            now = time.time()

            with self._db_lock:
                cursor = self.conn.cursor()
                cursor.execute(
                    """
                    SELECT DISTINCT recipient_uid FROM queued_messages
                    WHERE expires_at > ?
                """,
                    (now,),
                )

                recipients = [row[0] for row in cursor.fetchall()]

            return recipients

        except Exception as e:
            logger.error(f"Failed to get recipients: {e}", exc_info=True)
            return []

    def cleanup_expired(self) -> int:
        """
        Remove expired messages from queue with thread-safe database access.

        Returns:
            Number of messages removed
        """
        try:
            now = time.time()

            with self._db_lock:
                cursor = self.conn.cursor()
                cursor.execute(
                    """
                    DELETE FROM queued_messages WHERE expires_at <= ?
                """,
                    (now,),
                )

                removed = cursor.rowcount
                self.conn.commit()

            if removed > 0:
                logger.info(f"Cleaned up {removed} expired messages")

            self.last_cleanup = now
            return removed

        except Exception as e:
            logger.error(f"Failed to cleanup expired messages: {e}", exc_info=True)
            return 0

    def cleanup_if_needed(self):
        """Perform cleanup if interval exceeded."""
        if time.time() - self.last_cleanup >= MESSAGE_QUEUE_CLEANUP_INTERVAL:
            self.cleanup_expired()

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get queue statistics with thread-safe database access.

        Returns:
            Dictionary with statistics
        """
        try:
            now = time.time()

            with self._db_lock:
                cursor = self.conn.cursor()

                # Total messages
                cursor.execute("SELECT COUNT(*) FROM queued_messages")
                total = cursor.fetchone()[0]

                # Expired messages
                cursor.execute(
                    """
                    SELECT COUNT(*) FROM queued_messages WHERE expires_at <= ?
                """,
                    (now,),
                )
                expired = cursor.fetchone()[0]

                # Messages by recipient
                cursor.execute(
                    """
                    SELECT recipient_uid, COUNT(*) as count
                    FROM queued_messages
                    WHERE expires_at > ?
                    GROUP BY recipient_uid
                    ORDER BY count DESC
                """,
                    (now,),
                )
                by_recipient = {row[0]: row[1] for row in cursor.fetchall()}

                # Failed messages (max attempts)
                cursor.execute(
                    """
                    SELECT COUNT(*) FROM queued_messages
                    WHERE attempts >= ?
                """,
                    (MESSAGE_DELIVERY_RETRY_ATTEMPTS,),
                )
                failed = cursor.fetchone()[0]

            return {
                "total_messages": total,
                "active_messages": total - expired,
                "expired_messages": expired,
                "failed_messages": failed,
                "recipients_with_pending": len(by_recipient),
                "by_recipient": by_recipient,
                "last_cleanup": self.last_cleanup,
            }

        except Exception as e:
            logger.error(f"Failed to get statistics: {e}", exc_info=True)
            return {}

    def close(self) -> None:
        """Close database connection with thread-safe access."""
        with self._db_lock:
            if self.conn:
                self.conn.close()
                self.conn = None
                logger.debug("Message queue database closed")

    def __enter__(self) -> "MessageQueue":
        """Enter context manager."""
        logger.debug("Message queue context manager entered")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        """Exit context manager and close database connection."""
        self.close()
        logger.debug("Message queue context manager exited")
        return False

    def __del__(self):
        """Cleanup on destruction."""
        self.close()

    # Async wrappers for use in async context (network.py)

    async def get_queued_for_recipient(self, recipient_uid: str, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Async wrapper to get queued messages for a recipient as dictionaries.

        Args:
            recipient_uid: Recipient's UID
            limit: Maximum messages to return

        Returns:
            List of message dictionaries with queue_id and message_data
        """
        messages = self.dequeue(recipient_uid, limit)
        result = []
        for msg in messages:
            try:
                result.append({
                    "queue_id": msg.queue_id,
                    "recipient_uid": msg.recipient_uid,
                    "sender_uid": msg.sender_uid,
                    "message_type": msg.message_type,
                    "message_data": json.loads(msg.message_data),
                    "timestamp": msg.timestamp,
                    "attempts": msg.attempts,
                })
            except json.JSONDecodeError:
                logger.error(f"Failed to decode message data for queue_id {msg.queue_id}")
        return result

    async def enqueue_async(
        self, recipient_uid: str, sender_uid: str, message_type: str, message_data: Dict[str, Any]
    ) -> bool:
        """Async wrapper for enqueue method."""
        return self.enqueue(recipient_uid, sender_uid, message_type, message_data)

    async def mark_delivered_async(self, queue_id: int) -> bool:
        """Async wrapper for mark_delivered method."""
        return self.mark_delivered(queue_id)

    async def mark_failed_async(self, queue_id: int) -> bool:
        """Async wrapper for mark_failed method."""
        return self.mark_failed(queue_id)

    async def cleanup_expired_async(self) -> int:
        """Async wrapper for cleanup_expired method."""
        return self.cleanup_expired()
