"""
Jarvis - Security Manager for enhanced internet security.

Created by orpheus497

This module implements security policies for internet exposure including
pre-authentication challenges, IP filtering, rate limiting, and abuse prevention.
"""

import asyncio
import hashlib
import hmac
import logging
import secrets
import time
from typing import Dict, Optional, Set, Tuple, Any
from dataclasses import dataclass
from collections import defaultdict

from .constants import (
    PREAUTH_CHALLENGE_TIMEOUT,
    IP_BAN_DURATION,
    IP_BAN_THRESHOLD,
    CONNECTION_LIMIT_PER_IP,
    RATE_LIMIT_INTERNET_MESSAGES_PER_MINUTE,
    RATE_LIMIT_INTERNET_CONNECTIONS_PER_MINUTE
)

logger = logging.getLogger(__name__)


@dataclass
class SecurityEvent:
    """Represents a security-related event."""
    timestamp: float
    ip_address: str
    event_type: str
    details: str


class SecurityManager:
    """
    Manages security policies for internet-facing connections.
    
    Provides pre-authentication challenges, IP whitelisting/blacklisting,
    connection limits, and abuse detection/prevention.
    """
    
    def __init__(self):
        """Initialize security manager."""
        self.whitelist: Set[str] = set()
        self.blacklist: Set[str] = set()
        self.temp_bans: Dict[str, float] = {}  # IP -> unban_time
        
        # Track connection attempts
        self.connection_attempts: Dict[str, list] = defaultdict(list)
        self.active_connections: Dict[str, int] = defaultdict(int)
        
        # Pre-auth challenges
        self.active_challenges: Dict[str, Tuple[bytes, float]] = {}  # IP -> (challenge, timestamp)
        
        # Security events
        self.events: list[SecurityEvent] = []
        self.max_events = 1000
        
        # Rate limiting
        self.message_counts: Dict[str, list] = defaultdict(list)
        
        # Locks
        self.lock = asyncio.Lock()
        
        logger.info("Security manager initialized")
    
    async def check_ip_allowed(self, ip_address: str) -> Tuple[bool, Optional[str]]:
        """
        Check if IP address is allowed to connect.
        
        Args:
            ip_address: IP address to check
        
        Returns:
            Tuple of (allowed, reason)
        """
        async with self.lock:
            # Check blacklist
            if ip_address in self.blacklist:
                reason = "IP is permanently blacklisted"
                self._log_event(ip_address, "BLOCKED_BLACKLIST", reason)
                return False, reason
            
            # Check temporary ban
            if ip_address in self.temp_bans:
                unban_time = self.temp_bans[ip_address]
                if time.time() < unban_time:
                    remaining = int(unban_time - time.time())
                    reason = f"IP temporarily banned (expires in {remaining}s)"
                    self._log_event(ip_address, "BLOCKED_TEMPBAN", reason)
                    return False, reason
                else:
                    # Ban expired
                    del self.temp_bans[ip_address]
            
            # Check if in whitelist (always allowed)
            if ip_address in self.whitelist:
                return True, None
            
            # Check connection attempts
            attempts = self._get_recent_attempts(ip_address, window=60)
            if len(attempts) >= IP_BAN_THRESHOLD:
                reason = f"Too many connection attempts ({len(attempts)})"
                await self.ban_ip(ip_address, duration=IP_BAN_DURATION)
                self._log_event(ip_address, "BANNED_ABUSE", reason)
                return False, reason
            
            # Check active connections limit
            active = self.active_connections.get(ip_address, 0)
            if active >= CONNECTION_LIMIT_PER_IP:
                reason = f"Too many active connections ({active})"
                self._log_event(ip_address, "BLOCKED_LIMIT", reason)
                return False, reason
            
            return True, None
    
    async def generate_challenge(self, ip_address: str) -> bytes:
        """
        Generate pre-authentication challenge for IP.
        
        Args:
            ip_address: IP address requesting connection
        
        Returns:
            Challenge bytes
        """
        async with self.lock:
            # Generate random challenge
            challenge = secrets.token_bytes(32)
            
            # Store with timestamp
            self.active_challenges[ip_address] = (challenge, time.time())
            
            logger.debug(f"Generated challenge for {ip_address}")
            return challenge
    
    async def verify_challenge_response(self, ip_address: str, 
                                       response: bytes, secret: bytes) -> bool:
        """
        Verify challenge response.
        
        Args:
            ip_address: IP address responding
            response: Response bytes
            secret: Shared secret for HMAC
        
        Returns:
            True if response is valid
        """
        async with self.lock:
            # Check if we have a challenge for this IP
            if ip_address not in self.active_challenges:
                logger.warning(f"No challenge found for {ip_address}")
                return False
            
            challenge, timestamp = self.active_challenges[ip_address]
            
            # Check timeout
            if time.time() - timestamp > PREAUTH_CHALLENGE_TIMEOUT:
                logger.warning(f"Challenge expired for {ip_address}")
                del self.active_challenges[ip_address]
                return False
            
            # Compute expected response
            expected = hmac.new(secret, challenge, hashlib.sha256).digest()
            
            # Verify response
            valid = hmac.compare_digest(response, expected)
            
            # Remove challenge (one-time use)
            del self.active_challenges[ip_address]
            
            if valid:
                logger.info(f"Challenge verified for {ip_address}")
                self._log_event(ip_address, "CHALLENGE_SUCCESS", "Pre-auth successful")
            else:
                logger.warning(f"Challenge verification failed for {ip_address}")
                self._log_event(ip_address, "CHALLENGE_FAILED", "Invalid response")
                await self._record_failed_attempt(ip_address)
            
            return valid
    
    async def record_connection_attempt(self, ip_address: str, success: bool = True):
        """
        Record connection attempt.
        
        Args:
            ip_address: IP address attempting connection
            success: Whether attempt was successful
        """
        async with self.lock:
            now = time.time()
            self.connection_attempts[ip_address].append(now)
            
            # Trim old attempts
            window = 60  # Keep last 60 seconds
            self.connection_attempts[ip_address] = [
                t for t in self.connection_attempts[ip_address]
                if now - t < window
            ]
            
            if success:
                self.active_connections[ip_address] = \
                    self.active_connections.get(ip_address, 0) + 1
                self._log_event(ip_address, "CONNECTION_SUCCESS", "Connection established")
            else:
                await self._record_failed_attempt(ip_address)
    
    async def record_disconnection(self, ip_address: str):
        """
        Record disconnection.
        
        Args:
            ip_address: IP address disconnecting
        """
        async with self.lock:
            if ip_address in self.active_connections:
                self.active_connections[ip_address] -= 1
                if self.active_connections[ip_address] <= 0:
                    del self.active_connections[ip_address]
                
                self._log_event(ip_address, "DISCONNECTION", "Connection closed")
    
    async def _record_failed_attempt(self, ip_address: str):
        """Record failed connection attempt."""
        attempts = self._get_recent_attempts(ip_address, window=60)
        
        if len(attempts) >= IP_BAN_THRESHOLD:
            await self.ban_ip(ip_address, duration=IP_BAN_DURATION)
            self._log_event(
                ip_address,
                "AUTO_BANNED",
                f"Banned after {len(attempts)} failed attempts"
            )
    
    async def check_rate_limit(self, ip_address: str, limit_type: str = 'message') -> bool:
        """
        Check if IP is within rate limits.
        
        Args:
            ip_address: IP address to check
            limit_type: Type of rate limit ('message' or 'connection')
        
        Returns:
            True if within limits
        """
        async with self.lock:
            now = time.time()
            window = 60  # 1 minute window
            
            # Get appropriate limit
            if limit_type == 'message':
                limit = RATE_LIMIT_INTERNET_MESSAGES_PER_MINUTE
                counts = self.message_counts[ip_address]
            else:
                limit = RATE_LIMIT_INTERNET_CONNECTIONS_PER_MINUTE
                counts = self.connection_attempts[ip_address]
            
            # Count recent actions
            recent = [t for t in counts if now - t < window]
            
            if len(recent) >= limit:
                logger.warning(
                    f"Rate limit exceeded for {ip_address}: "
                    f"{len(recent)}/{limit} {limit_type}s per minute"
                )
                self._log_event(
                    ip_address,
                    "RATE_LIMIT_EXCEEDED",
                    f"{limit_type}: {len(recent)}/{limit}"
                )
                return False
            
            # Record this action
            if limit_type == 'message':
                self.message_counts[ip_address].append(now)
            
            return True
    
    async def ban_ip(self, ip_address: str, duration: int = IP_BAN_DURATION):
        """
        Temporarily ban IP address.
        
        Args:
            ip_address: IP to ban
            duration: Ban duration in seconds
        """
        async with self.lock:
            unban_time = time.time() + duration
            self.temp_bans[ip_address] = unban_time
            
            logger.warning(
                f"IP banned: {ip_address} for {duration}s "
                f"(until {time.ctime(unban_time)})"
            )
            self._log_event(
                ip_address,
                "BANNED",
                f"Temporary ban for {duration}s"
            )
    
    async def unban_ip(self, ip_address: str):
        """
        Remove temporary ban from IP.
        
        Args:
            ip_address: IP to unban
        """
        async with self.lock:
            if ip_address in self.temp_bans:
                del self.temp_bans[ip_address]
                logger.info(f"IP unbanned: {ip_address}")
                self._log_event(ip_address, "UNBANNED", "Manual unban")
    
    async def add_to_whitelist(self, ip_address: str):
        """Add IP to whitelist (always allowed)."""
        async with self.lock:
            self.whitelist.add(ip_address)
            logger.info(f"IP whitelisted: {ip_address}")
            self._log_event(ip_address, "WHITELISTED", "Added to whitelist")
    
    async def remove_from_whitelist(self, ip_address: str):
        """Remove IP from whitelist."""
        async with self.lock:
            self.whitelist.discard(ip_address)
            logger.info(f"IP removed from whitelist: {ip_address}")
    
    async def add_to_blacklist(self, ip_address: str):
        """Add IP to blacklist (permanently blocked)."""
        async with self.lock:
            self.blacklist.add(ip_address)
            logger.warning(f"IP blacklisted: {ip_address}")
            self._log_event(ip_address, "BLACKLISTED", "Added to blacklist")
    
    async def remove_from_blacklist(self, ip_address: str):
        """Remove IP from blacklist."""
        async with self.lock:
            self.blacklist.discard(ip_address)
            logger.info(f"IP removed from blacklist: {ip_address}")
    
    def _get_recent_attempts(self, ip_address: str, window: int = 60) -> list:
        """Get recent connection attempts within window."""
        now = time.time()
        attempts = self.connection_attempts.get(ip_address, [])
        return [t for t in attempts if now - t < window]
    
    def _log_event(self, ip_address: str, event_type: str, details: str):
        """Log security event."""
        event = SecurityEvent(
            timestamp=time.time(),
            ip_address=ip_address,
            event_type=event_type,
            details=details
        )
        
        self.events.append(event)
        
        # Trim old events
        if len(self.events) > self.max_events:
            self.events = self.events[-self.max_events:]
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get security statistics."""
        now = time.time()
        
        # Count active bans
        active_bans = sum(
            1 for unban_time in self.temp_bans.values()
            if unban_time > now
        )
        
        # Count recent events by type
        recent_window = 3600  # Last hour
        recent_events = [
            e for e in self.events
            if now - e.timestamp < recent_window
        ]
        
        event_counts = defaultdict(int)
        for event in recent_events:
            event_counts[event.event_type] += 1
        
        # Get top IPs by connection attempts
        top_ips = sorted(
            self.connection_attempts.items(),
            key=lambda x: len(x[1]),
            reverse=True
        )[:10]
        
        return {
            'whitelist_size': len(self.whitelist),
            'blacklist_size': len(self.blacklist),
            'active_bans': active_bans,
            'active_connections': sum(self.active_connections.values()),
            'active_challenges': len(self.active_challenges),
            'total_events': len(self.events),
            'recent_events': len(recent_events),
            'event_counts': dict(event_counts),
            'top_connection_ips': [
                {'ip': ip, 'attempts': len(attempts)}
                for ip, attempts in top_ips
            ],
        }
    
    async def get_recent_events(self, count: int = 50, 
                               event_type: Optional[str] = None) -> list[SecurityEvent]:
        """
        Get recent security events.
        
        Args:
            count: Maximum number of events to return
            event_type: Filter by event type (None = all)
        
        Returns:
            List of security events
        """
        async with self.lock:
            events = self.events
            
            # Filter by type if specified
            if event_type:
                events = [e for e in events if e.event_type == event_type]
            
            # Return most recent
            return events[-count:]
    
    async def cleanup_expired(self):
        """Clean up expired bans and old data."""
        async with self.lock:
            now = time.time()
            
            # Remove expired bans
            expired_bans = [
                ip for ip, unban_time in self.temp_bans.items()
                if unban_time <= now
            ]
            for ip in expired_bans:
                del self.temp_bans[ip]
                logger.info(f"Ban expired for {ip}")
            
            # Remove old connection attempts (keep last hour)
            window = 3600
            for ip in list(self.connection_attempts.keys()):
                self.connection_attempts[ip] = [
                    t for t in self.connection_attempts[ip]
                    if now - t < window
                ]
                if not self.connection_attempts[ip]:
                    del self.connection_attempts[ip]
            
            # Remove old message counts
            for ip in list(self.message_counts.keys()):
                self.message_counts[ip] = [
                    t for t in self.message_counts[ip]
                    if now - t < window
                ]
                if not self.message_counts[ip]:
                    del self.message_counts[ip]
            
            # Remove expired challenges
            expired_challenges = [
                ip for ip, (_, timestamp) in self.active_challenges.items()
                if now - timestamp > PREAUTH_CHALLENGE_TIMEOUT
            ]
            for ip in expired_challenges:
                del self.active_challenges[ip]
