"""
Jarvis - Message Search Engine

This module provides full-text search capabilities for messages using
SQLite FTS5 (Full-Text Search). Supports advanced search queries,
filtering, highlighting, and context retrieval with LRU caching.

Author: orpheus497
Version: 2.3.0
"""

import hashlib
import json
import logging
import sqlite3
import time
from collections import OrderedDict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from .constants import (
    SEARCH_CACHE_MAX_SIZE,
    SEARCH_CACHE_TTL,
    SEARCH_CONTEXT_LINES,
    SEARCH_MAX_RESULTS,
    SEARCH_RESULTS_PER_PAGE,
)
from .errors import ErrorCode, JarvisError

logger = logging.getLogger(__name__)


class SearchResultCache:
    """
    LRU cache for search results with TTL expiration.

    Implements least-recently-used eviction and time-to-live
    expiration for efficient search result caching.
    """

    def __init__(
        self, max_size: int = SEARCH_CACHE_MAX_SIZE, ttl: int = SEARCH_CACHE_TTL
    ):
        """
        Initialize search cache.

        Args:
            max_size: Maximum number of cached queries
            ttl: Cache entry time-to-live in seconds
        """
        self.max_size = max_size
        self.ttl = ttl
        self.cache: OrderedDict[str, Tuple[List[Dict], float]] = OrderedDict()
        self.hits = 0
        self.misses = 0
        logger.info(f"Search cache initialized: max_size={max_size}, ttl={ttl}s")

    def _make_key(
        self,
        query: str,
        contact: Optional[str] = None,
        group_id: Optional[str] = None,
        start_date: Optional[int] = None,
        end_date: Optional[int] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> str:
        """Generate cache key from query parameters."""
        key_data = f"{query}|{contact}|{group_id}|{start_date}|{end_date}|{limit}|{offset}"
        return hashlib.sha256(key_data.encode()).hexdigest()

    def get(
        self,
        query: str,
        contact: Optional[str] = None,
        group_id: Optional[str] = None,
        start_date: Optional[int] = None,
        end_date: Optional[int] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Optional[List[Dict]]:
        """
        Get cached search results.

        Returns:
            Cached results if found and not expired, None otherwise
        """
        key = self._make_key(query, contact, group_id, start_date, end_date, limit, offset)

        if key not in self.cache:
            self.misses += 1
            return None

        results, timestamp = self.cache[key]

        if time.time() - timestamp > self.ttl:
            del self.cache[key]
            self.misses += 1
            logger.debug(f"Cache expired: {query[:30]}...")
            return None

        self.cache.move_to_end(key)
        self.hits += 1
        logger.debug(f"Cache hit: {query[:30]}...")
        return results

    def put(
        self,
        query: str,
        results: List[Dict],
        contact: Optional[str] = None,
        group_id: Optional[str] = None,
        start_date: Optional[int] = None,
        end_date: Optional[int] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> None:
        """Cache search results."""
        key = self._make_key(query, contact, group_id, start_date, end_date, limit, offset)

        if key in self.cache:
            self.cache.move_to_end(key)

        self.cache[key] = (results, time.time())

        if len(self.cache) > self.max_size:
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
            logger.debug(f"Cache evicted oldest entry (size={len(self.cache)})")

        logger.debug(f"Cache stored: {query[:30]}... (size={len(self.cache)})")

    def clear(self) -> None:
        """Clear all cached results."""
        self.cache.clear()
        self.hits = 0
        self.misses = 0
        logger.info("Search cache cleared")

    def cleanup_expired(self) -> int:
        """
        Remove expired cache entries.

        Returns:
            Number of entries removed
        """
        now = time.time()
        expired_keys = [
            key for key, (_, timestamp) in self.cache.items() if now - timestamp > self.ttl
        ]

        for key in expired_keys:
            del self.cache[key]

        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")

        return len(expired_keys)

    def get_statistics(self) -> Dict[str, any]:
        """
        Get cache statistics.

        Returns:
            Dictionary with cache stats
        """
        total_requests = self.hits + self.misses
        hit_rate = self.hits / total_requests if total_requests > 0 else 0.0

        return {
            "size": len(self.cache),
            "max_size": self.max_size,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": hit_rate,
            "ttl": self.ttl,
        }


class MessageSearchEngine:
    """Full-text search engine for messages with caching.

    Uses SQLite FTS5 for efficient full-text search with support for
    filters, highlighting, pagination, and LRU caching of results.

    Attributes:
        db_path: Path to SQLite database
        conn: SQLite connection
        cache: Search result cache
    """

    def __init__(self, db_path: Path, enable_cache: bool = True):
        """Initialize search engine.

        Args:
            db_path: Path to SQLite database file
            enable_cache: Enable search result caching (default: True)

        Raises:
            JarvisError: If database initialization fails
        """
        self.db_path = Path(db_path)
        self.conn: Optional[sqlite3.Connection] = None
        self.cache: Optional[SearchResultCache] = None

        try:
            # Ensure database directory exists
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

            # Connect to database
            self.conn = sqlite3.connect(str(self.db_path))
            self.conn.row_factory = sqlite3.Row

            # Create tables if needed
            self._create_tables()

            # Initialize cache if enabled
            if enable_cache:
                self.cache = SearchResultCache()

            logger.info(f"Search engine initialized: {db_path} (cache={enable_cache})")

        except Exception as e:
            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR,
                f"Failed to initialize search engine: {e}",
                {"error": str(e)},
            )

    def _create_tables(self) -> None:
        """Create database tables including FTS5 index."""
        cursor = self.conn.cursor()

        # Create messages table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_id TEXT UNIQUE NOT NULL,
                sender TEXT NOT NULL,
                recipient TEXT,
                group_id TEXT,
                content TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                message_type TEXT NOT NULL,
                is_encrypted BOOLEAN DEFAULT 1
            )
        """
        )

        # Create FTS5 virtual table for full-text search
        cursor.execute(
            """
            CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
                content,
                sender,
                recipient,
                content='messages',
                content_rowid='id'
            )
        """
        )

        # Create triggers to keep FTS5 in sync
        cursor.execute(
            """
            CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
                INSERT INTO messages_fts(rowid, content, sender, recipient)
                VALUES (new.id, new.content, new.sender, new.recipient);
            END
        """
        )

        cursor.execute(
            """
            CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
                DELETE FROM messages_fts WHERE rowid = old.id;
            END
        """
        )

        cursor.execute(
            """
            CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
                UPDATE messages_fts SET
                    content = new.content,
                    sender = new.sender,
                    recipient = new.recipient
                WHERE rowid = new.id;
            END
        """
        )

        # Create indices for better query performance
        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_messages_timestamp
            ON messages(timestamp DESC)
        """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_messages_sender
            ON messages(sender)
        """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_messages_recipient
            ON messages(recipient)
        """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_messages_group
            ON messages(group_id)
        """
        )

        self.conn.commit()
        logger.debug("Database tables and indices created")

    def migrate_from_json(self, json_file: Path) -> int:
        """Migrate messages from JSON file to SQLite database.

        Args:
            json_file: Path to JSON messages file

        Returns:
            Number of messages migrated

        Raises:
            JarvisError: If migration fails
        """
        if not json_file.exists():
            logger.warning(f"JSON file not found: {json_file}")
            return 0

        try:
            with open(json_file) as f:
                data = json.load(f)

            count = 0
            cursor = self.conn.cursor()

            # Migrate direct messages
            for contact, messages in data.get("messages", {}).items():
                for msg in messages:
                    try:
                        cursor.execute(
                            """
                            INSERT OR IGNORE INTO messages
                            (message_id, sender, recipient, content, timestamp, message_type)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """,
                            (
                                msg.get("id", f"{msg['timestamp']}_{contact}"),
                                msg.get("sender", "unknown"),
                                contact,
                                msg.get("content", ""),
                                msg.get("timestamp", 0),
                                msg.get("type", "text"),
                            ),
                        )
                        count += 1
                    except Exception as e:
                        logger.warning(f"Failed to migrate message: {e}")

            # Migrate group messages
            for group_id, messages in data.get("group_messages", {}).items():
                for msg in messages:
                    try:
                        cursor.execute(
                            """
                            INSERT OR IGNORE INTO messages
                            (message_id, sender, group_id, content, timestamp, message_type)
                            VALUES (?, ?, ?, ?, ?, ?)
                        """,
                            (
                                msg.get("id", f"{msg['timestamp']}_{group_id}"),
                                msg.get("sender", "unknown"),
                                group_id,
                                msg.get("content", ""),
                                msg.get("timestamp", 0),
                                msg.get("type", "text"),
                            ),
                        )
                        count += 1
                    except Exception as e:
                        logger.warning(f"Failed to migrate group message: {e}")

            self.conn.commit()
            logger.info(f"Migrated {count} messages from JSON")

            return count

        except Exception as e:
            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR, f"Failed to migrate from JSON: {e}", {"error": str(e)}
            )

    def index_message(
        self,
        message_id: str,
        sender: str,
        content: str,
        timestamp: int,
        recipient: Optional[str] = None,
        group_id: Optional[str] = None,
        message_type: str = "text",
    ) -> None:
        """Index a single message for searching.

        Args:
            message_id: Unique message identifier
            sender: Message sender
            content: Message content
            timestamp: Unix timestamp
            recipient: Message recipient (for direct messages)
            group_id: Group ID (for group messages)
            message_type: Type of message (text, file, etc.)

        Raises:
            JarvisError: If indexing fails
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                INSERT OR REPLACE INTO messages
                (message_id, sender, recipient, group_id, content, timestamp, message_type)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (message_id, sender, recipient, group_id, content, timestamp, message_type),
            )

            self.conn.commit()
            logger.debug(f"Indexed message: {message_id}")

        except Exception as e:
            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR,
                f"Failed to index message: {e}",
                {"message_id": message_id, "error": str(e)},
            )

    def search(
        self,
        query: str,
        contact: Optional[str] = None,
        group_id: Optional[str] = None,
        start_date: Optional[int] = None,
        end_date: Optional[int] = None,
        limit: int = SEARCH_RESULTS_PER_PAGE,
        offset: int = 0,
    ) -> List[Dict]:
        """Search messages with filters and caching.

        Args:
            query: Search query (supports FTS5 syntax)
            contact: Filter by contact (sender or recipient)
            group_id: Filter by group
            start_date: Filter by start timestamp
            end_date: Filter by end timestamp
            limit: Maximum number of results
            offset: Result offset for pagination

        Returns:
            List of matching messages with highlighted snippets

        Raises:
            JarvisError: If search fails
        """
        try:
            # Limit results to prevent excessive queries
            limit = min(limit, SEARCH_MAX_RESULTS)

            # Check cache first
            if self.cache:
                cached_results = self.cache.get(
                    query, contact, group_id, start_date, end_date, limit, offset
                )
                if cached_results is not None:
                    return cached_results

            # Build query
            sql = """
                SELECT
                    m.id,
                    m.message_id,
                    m.sender,
                    m.recipient,
                    m.group_id,
                    m.content,
                    m.timestamp,
                    m.message_type,
                    snippet(messages_fts, -1, '<mark>', '</mark>', '...', 64) as snippet
                FROM messages m
                JOIN messages_fts ON m.id = messages_fts.rowid
                WHERE messages_fts MATCH ?
            """

            params = [query]

            # Add filters
            if contact:
                sql += " AND (m.sender = ? OR m.recipient = ?)"
                params.extend([contact, contact])

            if group_id:
                sql += " AND m.group_id = ?"
                params.append(group_id)

            if start_date:
                sql += " AND m.timestamp >= ?"
                params.append(start_date)

            if end_date:
                sql += " AND m.timestamp <= ?"
                params.append(end_date)

            # Order by relevance then timestamp
            sql += " ORDER BY rank, m.timestamp DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            cursor = self.conn.cursor()
            cursor.execute(sql, params)

            results = []
            for row in cursor.fetchall():
                results.append(
                    {
                        "message_id": row["message_id"],
                        "sender": row["sender"],
                        "recipient": row["recipient"],
                        "group_id": row["group_id"],
                        "content": row["content"],
                        "timestamp": row["timestamp"],
                        "message_type": row["message_type"],
                        "snippet": row["snippet"],
                    }
                )

            # Cache results
            if self.cache:
                self.cache.put(query, results, contact, group_id, start_date, end_date, limit, offset)

            logger.info(f"Search query '{query}' returned {len(results)} results")
            return results

        except Exception as e:
            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR,
                f"Search failed: {e}",
                {"query": query, "error": str(e)},
            )

    def get_cache_statistics(self) -> Optional[Dict[str, any]]:
        """
        Get search cache statistics.

        Returns:
            Cache statistics dict or None if caching disabled
        """
        if self.cache:
            return self.cache.get_statistics()
        return None

    def clear_cache(self) -> None:
        """Clear search result cache."""
        if self.cache:
            self.cache.clear()

    def search_by_contact(self, contact: str, limit: int = 100) -> List[Dict]:
        """Search all messages with a specific contact.

        Args:
            contact: Contact identifier
            limit: Maximum number of results

        Returns:
            List of messages
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                SELECT
                    message_id, sender, recipient, group_id,
                    content, timestamp, message_type
                FROM messages
                WHERE sender = ? OR recipient = ?
                ORDER BY timestamp DESC
                LIMIT ?
            """,
                (contact, contact, limit),
            )

            results = []
            for row in cursor.fetchall():
                results.append(dict(row))

            return results

        except Exception as e:
            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR,
                f"Contact search failed: {e}",
                {"contact": contact, "error": str(e)},
            )

    def search_by_date_range(self, start_date: int, end_date: int, limit: int = 100) -> List[Dict]:
        """Search messages within a date range.

        Args:
            start_date: Start timestamp (inclusive)
            end_date: End timestamp (inclusive)
            limit: Maximum number of results

        Returns:
            List of messages
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                """
                SELECT
                    message_id, sender, recipient, group_id,
                    content, timestamp, message_type
                FROM messages
                WHERE timestamp BETWEEN ? AND ?
                ORDER BY timestamp DESC
                LIMIT ?
            """,
                (start_date, end_date, limit),
            )

            results = []
            for row in cursor.fetchall():
                results.append(dict(row))

            return results

        except Exception as e:
            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR, f"Date range search failed: {e}", {"error": str(e)}
            )

    def get_message_context(
        self, message_id: str, context_lines: int = SEARCH_CONTEXT_LINES
    ) -> Dict:
        """Get messages before and after a specific message.

        Args:
            message_id: Target message ID
            context_lines: Number of messages before/after to retrieve

        Returns:
            Dictionary with before, target, and after messages
        """
        try:
            cursor = self.conn.cursor()

            # Get target message
            cursor.execute(
                """
                SELECT * FROM messages WHERE message_id = ?
            """,
                (message_id,),
            )
            target = cursor.fetchone()

            if not target:
                return {"before": [], "target": None, "after": []}

            target_dict = dict(target)
            timestamp = target["timestamp"]
            recipient = target["recipient"]
            group_id = target["group_id"]

            # Build context query
            if group_id:
                context_filter = "group_id = ?"
                filter_param = group_id
            else:
                context_filter = "(sender = ? OR recipient = ?)"
                filter_param = recipient

            # Get messages before
            if group_id:
                cursor.execute(
                    f"""
                    SELECT * FROM messages
                    WHERE {context_filter} AND timestamp < ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """,
                    (filter_param, timestamp, context_lines),
                )
            else:
                cursor.execute(
                    f"""
                    SELECT * FROM messages
                    WHERE {context_filter} AND timestamp < ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """,
                    (filter_param, filter_param, timestamp, context_lines),
                )

            before = [dict(row) for row in cursor.fetchall()]
            before.reverse()  # Chronological order

            # Get messages after
            if group_id:
                cursor.execute(
                    f"""
                    SELECT * FROM messages
                    WHERE {context_filter} AND timestamp > ?
                    ORDER BY timestamp ASC
                    LIMIT ?
                """,
                    (filter_param, timestamp, context_lines),
                )
            else:
                cursor.execute(
                    f"""
                    SELECT * FROM messages
                    WHERE {context_filter} AND timestamp > ?
                    ORDER BY timestamp ASC
                    LIMIT ?
                """,
                    (filter_param, filter_param, timestamp, context_lines),
                )

            after = [dict(row) for row in cursor.fetchall()]

            return {"before": before, "target": target_dict, "after": after}

        except Exception as e:
            raise JarvisError(
                ErrorCode.E001_UNKNOWN_ERROR,
                f"Failed to get message context: {e}",
                {"message_id": message_id, "error": str(e)},
            )

    def get_stats(self) -> Dict:
        """Get search engine statistics.

        Returns:
            Dictionary with statistics
        """
        try:
            cursor = self.conn.cursor()

            # Total messages
            cursor.execute("SELECT COUNT(*) as count FROM messages")
            total_messages = cursor.fetchone()["count"]

            # Messages by type
            cursor.execute(
                """
                SELECT message_type, COUNT(*) as count
                FROM messages
                GROUP BY message_type
            """
            )
            by_type = {row["message_type"]: row["count"] for row in cursor.fetchall()}

            # Database size
            db_size = self.db_path.stat().st_size if self.db_path.exists() else 0

            return {
                "total_messages": total_messages,
                "by_type": by_type,
                "database_size_bytes": db_size,
            }

        except Exception as e:
            logger.warning(f"Failed to get stats: {e}")
            return {}

    def close(self) -> None:
        """Close database connection."""
        if self.conn:
            self.conn.close()
            logger.debug("Search engine connection closed")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
