"""
Jarvis - Rate Limiting Implementation

This module implements rate limiting using the token bucket algorithm
to prevent abuse and ensure fair resource usage. Supports message rate
limiting, connection rate limiting, and temporary banning.

Author: orpheus497
Version: 2.3.0
"""

import logging
import time
from threading import Lock
from typing import Dict, Set

from .constants import (
    RATE_LIMIT_BAN_DURATION,
    RATE_LIMIT_CLEANUP_INTERVAL,
    RATE_LIMIT_CONNECTIONS_PER_MINUTE,
    RATE_LIMIT_MESSAGES_BURST,
    RATE_LIMIT_MESSAGES_PER_MINUTE,
)

logger = logging.getLogger(__name__)


class TokenBucket:
    """Token bucket implementation for rate limiting.

    The token bucket algorithm allows bursts of activity while
    maintaining a long-term rate limit. Tokens are added at a
    constant rate and consumed by operations.

    Attributes:
        capacity: Maximum number of tokens in bucket
        refill_rate: Tokens added per second
        tokens: Current number of tokens
        last_refill: Timestamp of last refill
        lock: Thread lock for synchronization
    """

    def __init__(self, capacity: int, refill_rate: float):
        """Initialize token bucket.

        Args:
            capacity: Maximum tokens (burst size)
            refill_rate: Tokens per second
        """
        self.capacity = capacity
        self.refill_rate = refill_rate
        self.tokens = float(capacity)
        self.last_refill = time.time()
        self.lock = Lock()

    def consume(self, tokens: int = 1) -> bool:
        """Attempt to consume tokens from the bucket.

        Args:
            tokens: Number of tokens to consume

        Returns:
            True if tokens were consumed, False if insufficient tokens
        """
        with self.lock:
            # Refill tokens based on time elapsed
            now = time.time()
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + (elapsed * self.refill_rate))
            self.last_refill = now

            # Check if we have enough tokens
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True

            return False

    def reset(self) -> None:
        """Reset the bucket to full capacity."""
        with self.lock:
            self.tokens = float(self.capacity)
            self.last_refill = time.time()


class RateLimiter:
    """Rate limiter for Jarvis network operations.

    Manages rate limiting for messages and connections per address.
    Supports temporary banning of abusive addresses and automatic
    cleanup of stale entries.

    Attributes:
        message_buckets: Token buckets for message rate limiting
        connection_buckets: Token buckets for connection rate limiting
        banned_addresses: Set of banned IP addresses
        ban_expiry: Expiry timestamps for banned addresses
        lock: Thread lock for synchronization
        last_cleanup: Timestamp of last cleanup
    """

    def __init__(
        self,
        messages_per_minute: int = RATE_LIMIT_MESSAGES_PER_MINUTE,
        messages_burst: int = RATE_LIMIT_MESSAGES_BURST,
        connections_per_minute: int = RATE_LIMIT_CONNECTIONS_PER_MINUTE,
    ):
        """Initialize rate limiter.

        Args:
            messages_per_minute: Maximum messages per minute per address
            messages_burst: Maximum burst size for messages
            connections_per_minute: Maximum connections per minute per address
        """
        self.messages_per_minute = messages_per_minute
        self.messages_burst = messages_burst
        self.connections_per_minute = connections_per_minute

        # Token buckets per address
        self.message_buckets: Dict[str, TokenBucket] = {}
        self.connection_buckets: Dict[str, TokenBucket] = {}

        # Banned addresses
        self.banned_addresses: Set[str] = set()
        self.ban_expiry: Dict[str, float] = {}

        # Thread synchronization
        self.lock = Lock()
        self.last_cleanup = time.time()

        logger.info(
            "Rate limiter initialized: "
            f"{messages_per_minute} msg/min, "
            f"{connections_per_minute} conn/min"
        )

    def check_message_rate(self, address: str) -> bool:
        """Check if message is allowed for the given address.

        Args:
            address: IP address to check

        Returns:
            True if message is allowed, False if rate limited
        """
        # Check if banned
        if self._is_banned(address):
            logger.warning(f"Message rejected from banned address: {address}")
            return False

        # Get or create token bucket for this address
        with self.lock:
            if address not in self.message_buckets:
                refill_rate = self.messages_per_minute / 60.0  # per second
                self.message_buckets[address] = TokenBucket(self.messages_burst, refill_rate)

            bucket = self.message_buckets[address]

        # Try to consume a token
        if bucket.consume():
            return True

        logger.warning(f"Message rate limit exceeded for: {address}")
        return False

    def check_connection_rate(self, address: str) -> bool:
        """Check if connection is allowed for the given address.

        Args:
            address: IP address to check

        Returns:
            True if connection is allowed, False if rate limited
        """
        # Check if banned
        if self._is_banned(address):
            logger.warning(f"Connection rejected from banned address: {address}")
            return False

        # Get or create token bucket for this address
        with self.lock:
            if address not in self.connection_buckets:
                refill_rate = self.connections_per_minute / 60.0  # per second
                self.connection_buckets[address] = TokenBucket(
                    self.connections_per_minute, refill_rate
                )

            bucket = self.connection_buckets[address]

        # Try to consume a token
        if bucket.consume():
            return True

        logger.warning(f"Connection rate limit exceeded for: {address}")
        return False

    def ban(self, address: str, duration: int = RATE_LIMIT_BAN_DURATION) -> None:
        """Temporarily ban an address.

        Args:
            address: IP address to ban
            duration: Ban duration in seconds
        """
        with self.lock:
            self.banned_addresses.add(address)
            self.ban_expiry[address] = time.time() + duration

        logger.warning(f"Banned address {address} for {duration} seconds")

    def unban(self, address: str) -> None:
        """Manually unban an address.

        Args:
            address: IP address to unban
        """
        with self.lock:
            self.banned_addresses.discard(address)
            self.ban_expiry.pop(address, None)

        logger.info(f"Unbanned address: {address}")

    def _is_banned(self, address: str) -> bool:
        """Check if an address is currently banned.

        Args:
            address: IP address to check

        Returns:
            True if banned, False otherwise
        """
        if address not in self.banned_addresses:
            return False

        # Check if ban has expired
        now = time.time()
        with self.lock:
            if address in self.ban_expiry and now >= self.ban_expiry[address]:
                # Ban expired, remove it
                self.banned_addresses.discard(address)
                self.ban_expiry.pop(address, None)
                logger.info(f"Ban expired for address: {address}")
                return False

        return True

    def cleanup(self) -> None:
        """Clean up expired bans and stale buckets.

        Should be called periodically to prevent memory leaks.
        """
        now = time.time()

        # Only cleanup if enough time has passed
        if now - self.last_cleanup < RATE_LIMIT_CLEANUP_INTERVAL:
            return

        with self.lock:
            # Remove expired bans
            expired_bans = [addr for addr, expiry in self.ban_expiry.items() if now >= expiry]
            for addr in expired_bans:
                self.banned_addresses.discard(addr)
                self.ban_expiry.pop(addr, None)

            if expired_bans:
                logger.info(f"Cleaned up {len(expired_bans)} expired bans")

            # Remove stale buckets (no activity for 1 hour)
            stale_timeout = 3600  # 1 hour

            stale_message_buckets = [
                addr
                for addr, bucket in self.message_buckets.items()
                if now - bucket.last_refill > stale_timeout
            ]
            for addr in stale_message_buckets:
                del self.message_buckets[addr]

            stale_connection_buckets = [
                addr
                for addr, bucket in self.connection_buckets.items()
                if now - bucket.last_refill > stale_timeout
            ]
            for addr in stale_connection_buckets:
                del self.connection_buckets[addr]

            if stale_message_buckets or stale_connection_buckets:
                logger.info(
                    f"Cleaned up {len(stale_message_buckets)} message buckets, "
                    f"{len(stale_connection_buckets)} connection buckets"
                )

            self.last_cleanup = now

    def get_stats(self) -> Dict[str, int]:
        """Get current rate limiter statistics.

        Returns:
            Dictionary with statistics
        """
        with self.lock:
            return {
                "message_buckets": len(self.message_buckets),
                "connection_buckets": len(self.connection_buckets),
                "banned_addresses": len(self.banned_addresses),
            }
