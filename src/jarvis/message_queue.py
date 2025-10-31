"""
Jarvis - Message Queue for offline recipients.

Created by orpheus497

This module implements persistent message queuing for offline recipients.
Messages are queued when recipients are unreachable and delivered automatically
when they come online. Includes delivery receipts and retry logic.
"""

import os
import json
import sqlite3
import logging
import time
from typing import List, Dict, Optional, Any
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict

from .constants import (
    MESSAGE_QUEUE_MAX_SIZE,
    MESSAGE_QUEUE_MAX_AGE,
    MESSAGE_QUEUE_CLEANUP_INTERVAL,
    MESSAGE_DELIVERY_RETRY_ATTEMPTS,
    MESSAGE_DELIVERY_RETRY_DELAY
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
    def from_row(cls, row: tuple) -> 'QueuedMessage':
        """Create from database row."""
        return cls(*row)


class MessageQueue:
    """
    Persistent message queue for offline recipients.
    
    Stores messages in SQLite database and handles automatic delivery
    when recipients come online. Includes retry logic and expiration.
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
        
        self._init_database()
    
    def _init_database(self):
        """Initialize database schema."""
        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        
        cursor = self.conn.cursor()
        
        # Create messages table
        cursor.execute('''
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
                expires_at REAL NOT NULL,
                INDEX idx_recipient (recipient_uid),
                INDEX idx_expires (expires_at),
                INDEX idx_next_retry (next_retry)
            )
        ''')
        
        self.conn.commit()
        logger.info(f"Message queue database initialized: {self.db_path}")
    
    def enqueue(self, recipient_uid: str, sender_uid: str, 
                message_type: str, message_data: Dict[str, Any]) -> bool:
        """
        Add message to queue.
        
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
                logger.warning(
                    f"Queue full for {recipient_uid}: {count} messages"
                )
                return False
            
            # Calculate expiration
            now = time.time()
            expires_at = now + MESSAGE_QUEUE_MAX_AGE
            
            # Encode message data
            message_json = json.dumps(message_data)
            
            # Insert into database
            cursor = self.conn.cursor()
            cursor.execute('''
                INSERT INTO queued_messages 
                (recipient_uid, sender_uid, message_type, message_data, 
                 timestamp, next_retry, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (recipient_uid, sender_uid, message_type, message_json,
                  now, now, expires_at))
            
            self.conn.commit()
            
            logger.info(
                f"Message queued for {recipient_uid} "
                f"(type: {message_type}, expires: {datetime.fromtimestamp(expires_at)})"
            )
            
            return True
        
        except Exception as e:
            logger.error(f"Failed to enqueue message: {e}")
            return False
    
    def dequeue(self, recipient_uid: str, limit: int = 100) -> List[QueuedMessage]:
        """
        Get pending messages for recipient.
        
        Args:
            recipient_uid: Recipient's UID
            limit: Maximum messages to return
        
        Returns:
            List of queued messages ready for delivery
        """
        try:
            now = time.time()
            
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT * FROM queued_messages
                WHERE recipient_uid = ?
                AND next_retry <= ?
                AND expires_at > ?
                AND attempts < ?
                ORDER BY timestamp ASC
                LIMIT ?
            ''', (recipient_uid, now, now, MESSAGE_DELIVERY_RETRY_ATTEMPTS, limit))
            
            messages = [QueuedMessage.from_row(row) for row in cursor.fetchall()]
            
            logger.debug(
                f"Dequeued {len(messages)} messages for {recipient_uid}"
            )
            
            return messages
        
        except Exception as e:
            logger.error(f"Failed to dequeue messages: {e}")
            return []
    
    def mark_delivered(self, queue_id: int) -> bool:
        """
        Mark message as successfully delivered and remove from queue.
        
        Args:
            queue_id: Queue ID of delivered message
        
        Returns:
            True if successful, False otherwise
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute('''
                DELETE FROM queued_messages WHERE queue_id = ?
            ''', (queue_id,))
            
            self.conn.commit()
            
            if cursor.rowcount > 0:
                logger.info(f"Message {queue_id} marked as delivered and removed")
                return True
            else:
                logger.warning(f"Message {queue_id} not found in queue")
                return False
        
        except Exception as e:
            logger.error(f"Failed to mark message delivered: {e}")
            return False
    
    def mark_failed(self, queue_id: int) -> bool:
        """
        Mark delivery attempt failed and schedule retry.
        
        Args:
            queue_id: Queue ID of failed message
        
        Returns:
            True if successful, False otherwise
        """
        try:
            now = time.time()
            
            cursor = self.conn.cursor()
            
            # Get current attempts
            cursor.execute('''
                SELECT attempts FROM queued_messages WHERE queue_id = ?
            ''', (queue_id,))
            
            row = cursor.fetchone()
            if not row:
                logger.warning(f"Message {queue_id} not found")
                return False
            
            attempts = row[0] + 1
            
            # Calculate next retry with exponential backoff
            backoff = MESSAGE_DELIVERY_RETRY_DELAY * (2 ** (attempts - 1))
            next_retry = now + backoff
            
            # Update message
            cursor.execute('''
                UPDATE queued_messages
                SET attempts = ?,
                    last_attempt = ?,
                    next_retry = ?
                WHERE queue_id = ?
            ''', (attempts, now, next_retry, queue_id))
            
            self.conn.commit()
            
            logger.info(
                f"Message {queue_id} delivery failed "
                f"(attempt {attempts}, next retry in {backoff}s)"
            )
            
            return True
        
        except Exception as e:
            logger.error(f"Failed to mark message failed: {e}")
            return False
    
    def get_pending_count(self, recipient_uid: str) -> int:
        """
        Get count of pending messages for recipient.
        
        Args:
            recipient_uid: Recipient's UID
        
        Returns:
            Number of pending messages
        """
        try:
            now = time.time()
            
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT COUNT(*) FROM queued_messages
                WHERE recipient_uid = ?
                AND expires_at > ?
            ''', (recipient_uid, now))
            
            count = cursor.fetchone()[0]
            return count
        
        except Exception as e:
            logger.error(f"Failed to get pending count: {e}")
            return 0
    
    def get_all_recipients(self) -> List[str]:
        """
        Get list of all recipients with pending messages.
        
        Returns:
            List of recipient UIDs
        """
        try:
            now = time.time()
            
            cursor = self.conn.cursor()
            cursor.execute('''
                SELECT DISTINCT recipient_uid FROM queued_messages
                WHERE expires_at > ?
            ''', (now,))
            
            recipients = [row[0] for row in cursor.fetchall()]
            return recipients
        
        except Exception as e:
            logger.error(f"Failed to get recipients: {e}")
            return []
    
    def cleanup_expired(self) -> int:
        """
        Remove expired messages from queue.
        
        Returns:
            Number of messages removed
        """
        try:
            now = time.time()
            
            cursor = self.conn.cursor()
            cursor.execute('''
                DELETE FROM queued_messages WHERE expires_at <= ?
            ''', (now,))
            
            removed = cursor.rowcount
            self.conn.commit()
            
            if removed > 0:
                logger.info(f"Cleaned up {removed} expired messages")
            
            self.last_cleanup = now
            return removed
        
        except Exception as e:
            logger.error(f"Failed to cleanup expired messages: {e}")
            return 0
    
    def cleanup_if_needed(self):
        """Perform cleanup if interval exceeded."""
        if time.time() - self.last_cleanup >= MESSAGE_QUEUE_CLEANUP_INTERVAL:
            self.cleanup_expired()
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get queue statistics.
        
        Returns:
            Dictionary with statistics
        """
        try:
            now = time.time()
            
            cursor = self.conn.cursor()
            
            # Total messages
            cursor.execute('SELECT COUNT(*) FROM queued_messages')
            total = cursor.fetchone()[0]
            
            # Expired messages
            cursor.execute('''
                SELECT COUNT(*) FROM queued_messages WHERE expires_at <= ?
            ''', (now,))
            expired = cursor.fetchone()[0]
            
            # Messages by recipient
            cursor.execute('''
                SELECT recipient_uid, COUNT(*) as count
                FROM queued_messages
                WHERE expires_at > ?
                GROUP BY recipient_uid
                ORDER BY count DESC
            ''', (now,))
            by_recipient = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Failed messages (max attempts)
            cursor.execute('''
                SELECT COUNT(*) FROM queued_messages
                WHERE attempts >= ?
            ''', (MESSAGE_DELIVERY_RETRY_ATTEMPTS,))
            failed = cursor.fetchone()[0]
            
            return {
                'total_messages': total,
                'active_messages': total - expired,
                'expired_messages': expired,
                'failed_messages': failed,
                'recipients_with_pending': len(by_recipient),
                'by_recipient': by_recipient,
                'last_cleanup': self.last_cleanup,
            }
        
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {}
    
    def close(self):
        """Close database connection."""
        if self.conn:
            self.conn.close()
            self.conn = None
            logger.debug("Message queue database closed")
    
    def __del__(self):
        """Cleanup on destruction."""
        self.close()
