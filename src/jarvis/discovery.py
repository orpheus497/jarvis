"""
Jarvis - Peer Discovery Service for automatic peer finding.

Created by orpheus497

This module implements peer discovery via mDNS (local network) and a simple DHT
(internet). Enables users to find each other without manual IP address exchange.
"""

import asyncio
import hashlib
import json
import logging
import socket
import time
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, asdict

from .constants import (
    MDNS_SERVICE_TYPE,
    MDNS_ANNOUNCEMENT_INTERVAL,
    DHT_REPLICATION_FACTOR,
    DHT_REFRESH_INTERVAL,
    DISCOVERY_CACHE_TTL
)

logger = logging.getLogger(__name__)

try:
    from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf, ServiceStateChange
    ZEROCONF_AVAILABLE = True
except ImportError:
    logger.warning("zeroconf not available, mDNS discovery disabled")
    ZEROCONF_AVAILABLE = False


@dataclass
class DiscoveredPeer:
    """Represents a discovered peer."""
    uid: str
    username: str
    public_key: str
    fingerprint: str
    addresses: List[Tuple[str, int]]  # List of (host, port)
    discovery_method: str  # 'mdns', 'dht', 'manual'
    discovered_at: float
    last_seen: float
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)
    
    def is_fresh(self, ttl: int = DISCOVERY_CACHE_TTL) -> bool:
        """Check if discovery is still fresh."""
        return (time.time() - self.last_seen) < ttl


class DiscoveryService:
    """
    Peer discovery service using mDNS for local network.
    
    Broadcasts presence on local network and discovers other peers
    automatically without requiring manual IP address exchange.
    """
    
    def __init__(self, uid: str, username: str, public_key: str, fingerprint: str):
        """
        Initialize discovery service.
        
        Args:
            uid: User's unique ID
            username: User's display name
            public_key: User's public key (base64)
            fingerprint: User's public key fingerprint
        """
        self.uid = uid
        self.username = username
        self.public_key = public_key
        self.fingerprint = fingerprint
        
        self.zeroconf: Optional[Zeroconf] = None
        self.service_info: Optional[ServiceInfo] = None
        self.browser: Optional[ServiceBrowser] = None
        
        self.discovered_peers: Dict[str, DiscoveredPeer] = {}
        self.cache_lock = asyncio.Lock()
        
        self.running = False
        self.announcement_task: Optional[asyncio.Task] = None
        
        # Callbacks
        self.on_peer_discovered: Optional[callable] = None
        self.on_peer_lost: Optional[callable] = None
    
    async def start(self, port: int, host: str = "0.0.0.0") -> bool:
        """
        Start discovery service.
        
        Args:
            port: Port to advertise
            host: Host to advertise (default: all interfaces)
        
        Returns:
            True if started successfully
        """
        if not ZEROCONF_AVAILABLE:
            logger.warning("Zeroconf not available, discovery service disabled")
            return False
        
        try:
            self.running = True
            
            # Initialize Zeroconf
            self.zeroconf = Zeroconf()
            
            # Get local IP addresses
            addresses = self._get_local_addresses()
            if not addresses:
                logger.warning("No local addresses found")
                return False
            
            # Create service info
            service_name = f"{self.username}-{self.uid[:8]}.{MDNS_SERVICE_TYPE}"
            
            # Properties to advertise
            properties = {
                'uid': self.uid,
                'username': self.username,
                'public_key': self.public_key,
                'fingerprint': self.fingerprint,
                'version': '2.1.0',
            }
            
            # Register service
            self.service_info = ServiceInfo(
                MDNS_SERVICE_TYPE,
                service_name,
                addresses=addresses,
                port=port,
                properties=properties,
                server=f"{self.username}.local."
            )
            
            self.zeroconf.register_service(self.service_info)
            logger.info(f"mDNS service registered: {service_name} on port {port}")
            
            # Start browser to discover other peers
            self.browser = ServiceBrowser(
                self.zeroconf,
                MDNS_SERVICE_TYPE,
                handlers=[self._on_service_state_change]
            )
            logger.info("mDNS browser started")
            
            # Start periodic announcement
            self.announcement_task = asyncio.create_task(self._announcement_loop())
            
            return True
        
        except Exception as e:
            logger.error(f"Failed to start discovery service: {e}", exc_info=True)
            return False
    
    async def stop(self):
        """Stop discovery service."""
        logger.info("Stopping discovery service...")
        self.running = False
        
        # Stop announcement task
        if self.announcement_task:
            self.announcement_task.cancel()
            try:
                await self.announcement_task
            except asyncio.CancelledError:
                pass
        
        # Unregister service
        if self.zeroconf and self.service_info:
            try:
                self.zeroconf.unregister_service(self.service_info)
                logger.info("mDNS service unregistered")
            except Exception as e:
                logger.warning(f"Error unregistering service: {e}")
        
        # Close browser
        if self.browser:
            try:
                self.browser.cancel()
            except Exception as e:
                logger.warning(f"Error closing browser: {e}")
        
        # Close Zeroconf
        if self.zeroconf:
            try:
                self.zeroconf.close()
            except Exception as e:
                logger.warning(f"Error closing zeroconf: {e}")
        
        logger.info("Discovery service stopped")
    
    def _on_service_state_change(self, zeroconf: Zeroconf, service_type: str,
                                  name: str, state_change: ServiceStateChange):
        """Handle service state changes from mDNS browser."""
        if state_change is ServiceStateChange.Added:
            asyncio.create_task(self._handle_service_added(zeroconf, service_type, name))
        elif state_change is ServiceStateChange.Removed:
            asyncio.create_task(self._handle_service_removed(name))
    
    async def _handle_service_added(self, zeroconf: Zeroconf, service_type: str, name: str):
        """Handle discovered service."""
        try:
            info = zeroconf.get_service_info(service_type, name)
            if not info:
                return
            
            # Extract properties
            props = {}
            if info.properties:
                for key, value in info.properties.items():
                    if isinstance(key, bytes):
                        key = key.decode('utf-8')
                    if isinstance(value, bytes):
                        value = value.decode('utf-8')
                    props[key] = value
            
            # Check if it's us
            peer_uid = props.get('uid')
            if peer_uid == self.uid:
                return  # Ignore our own service
            
            # Extract peer info
            username = props.get('username', 'Unknown')
            public_key = props.get('public_key', '')
            fingerprint = props.get('fingerprint', '')
            
            # Get addresses
            addresses = []
            if info.addresses:
                for addr in info.addresses:
                    if len(addr) == 4:  # IPv4
                        ip = socket.inet_ntoa(addr)
                        addresses.append((ip, info.port))
            
            if not addresses:
                logger.warning(f"No addresses for peer {username}")
                return
            
            # Create discovered peer
            peer = DiscoveredPeer(
                uid=peer_uid,
                username=username,
                public_key=public_key,
                fingerprint=fingerprint,
                addresses=addresses,
                discovery_method='mdns',
                discovered_at=time.time(),
                last_seen=time.time()
            )
            
            # Add to cache
            async with self.cache_lock:
                self.discovered_peers[peer_uid] = peer
            
            logger.info(
                f"Discovered peer via mDNS: {username} ({peer_uid[:8]}) "
                f"at {addresses[0][0]}:{addresses[0][1]}"
            )
            
            # Call callback
            if self.on_peer_discovered:
                try:
                    await self.on_peer_discovered(peer)
                except Exception as e:
                    logger.error(f"Error in peer discovered callback: {e}")
        
        except Exception as e:
            logger.error(f"Error handling service added: {e}", exc_info=True)
    
    async def _handle_service_removed(self, name: str):
        """Handle service removal."""
        try:
            # Extract UID from name (format: username-uid.service_type)
            parts = name.split('-')
            if len(parts) >= 2:
                uid_part = parts[1].split('.')[0]
                
                # Find and remove peer
                async with self.cache_lock:
                    peer_to_remove = None
                    for uid, peer in self.discovered_peers.items():
                        if uid.startswith(uid_part):
                            peer_to_remove = uid
                            break
                    
                    if peer_to_remove:
                        peer = self.discovered_peers.pop(peer_to_remove)
                        logger.info(f"Peer left: {peer.username} ({peer_to_remove[:8]})")
                        
                        # Call callback
                        if self.on_peer_lost:
                            try:
                                await self.on_peer_lost(peer)
                            except Exception as e:
                                logger.error(f"Error in peer lost callback: {e}")
        
        except Exception as e:
            logger.error(f"Error handling service removed: {e}")
    
    async def _announcement_loop(self):
        """Periodically refresh service announcement."""
        while self.running:
            try:
                await asyncio.sleep(MDNS_ANNOUNCEMENT_INTERVAL)
                
                # Update service info to keep it fresh
                if self.zeroconf and self.service_info:
                    try:
                        self.zeroconf.update_service(self.service_info)
                        logger.debug("mDNS service announcement refreshed")
                    except Exception as e:
                        logger.warning(f"Failed to refresh announcement: {e}")
                
                # Clean up stale entries
                await self._cleanup_stale_peers()
            
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in announcement loop: {e}")
    
    async def _cleanup_stale_peers(self):
        """Remove peers not seen recently."""
        async with self.cache_lock:
            stale_peers = [
                uid for uid, peer in self.discovered_peers.items()
                if not peer.is_fresh()
            ]
            
            for uid in stale_peers:
                peer = self.discovered_peers.pop(uid)
                logger.info(f"Removed stale peer: {peer.username} ({uid[:8]})")
    
    def _get_local_addresses(self) -> List[bytes]:
        """Get local IP addresses."""
        addresses = []
        try:
            # Get hostname
            hostname = socket.gethostname()
            
            # Get all addresses for hostname
            for addr_info in socket.getaddrinfo(hostname, None):
                family, _, _, _, sockaddr = addr_info
                if family == socket.AF_INET:  # IPv4
                    ip = sockaddr[0]
                    # Skip localhost
                    if not ip.startswith('127.'):
                        addresses.append(socket.inet_aton(ip))
        except Exception as e:
            logger.warning(f"Error getting local addresses: {e}")
        
        return addresses
    
    async def get_discovered_peers(self) -> List[DiscoveredPeer]:
        """Get list of discovered peers."""
        async with self.cache_lock:
            return [
                peer for peer in self.discovered_peers.values()
                if peer.is_fresh()
            ]
    
    async def get_peer(self, uid: str) -> Optional[DiscoveredPeer]:
        """Get specific peer by UID."""
        async with self.cache_lock:
            peer = self.discovered_peers.get(uid)
            if peer and peer.is_fresh():
                return peer
        return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get discovery statistics."""
        return {
            'running': self.running,
            'total_discovered': len(self.discovered_peers),
            'fresh_peers': sum(
                1 for p in self.discovered_peers.values() if p.is_fresh()
            ),
            'mdns_available': ZEROCONF_AVAILABLE,
            'service_registered': self.service_info is not None,
        }


class SimpleDHT:
    """
    Simple DHT implementation for internet peer discovery.
    
    This is a basic distributed hash table for announcing and discovering
    peers over the internet without requiring a central server.
    
    Note: This is a simplified implementation. Production use would benefit
    from a mature DHT library (e.g., based on Kademlia).
    """
    
    def __init__(self, uid: str, username: str, public_key: str, fingerprint: str):
        """
        Initialize DHT node.
        
        Args:
            uid: User's unique ID
            username: User's display name
            public_key: User's public key (base64)
            fingerprint: User's public key fingerprint
        """
        self.uid = uid
        self.username = username
        self.public_key = public_key
        self.fingerprint = fingerprint
        
        self.node_id = self._generate_node_id(uid)
        self.routing_table: Dict[str, Dict[str, Any]] = {}
        self.storage: Dict[str, Dict[str, Any]] = {}
        
        self.bootstrap_nodes: List[Tuple[str, int]] = []
        self.running = False
        
        logger.info(f"DHT node initialized with ID: {self.node_id[:16]}...")
    
    def _generate_node_id(self, uid: str) -> str:
        """Generate consistent node ID from UID."""
        return hashlib.sha256(uid.encode()).hexdigest()
    
    async def start(self, bootstrap_nodes: Optional[List[Tuple[str, int]]] = None):
        """
        Start DHT node.
        
        Args:
            bootstrap_nodes: List of (host, port) tuples for bootstrap
        """
        self.running = True
        self.bootstrap_nodes = bootstrap_nodes or []
        
        logger.info("DHT node started")
        
        # In a full implementation, we would:
        # 1. Connect to bootstrap nodes
        # 2. Build routing table
        # 3. Start periodic maintenance
        # 4. Announce our presence
        
        # For now, this is a placeholder for future enhancement
        logger.info(
            "DHT is a placeholder - full implementation requires "
            "connecting to bootstrap nodes and building routing table"
        )
    
    async def stop(self):
        """Stop DHT node."""
        self.running = False
        logger.info("DHT node stopped")
    
    async def announce(self, port: int) -> bool:
        """
        Announce presence in DHT.
        
        Args:
            port: Port we're listening on
        
        Returns:
            True if announced successfully
        """
        # Placeholder for DHT announcement
        logger.debug(f"DHT announce: {self.username} on port {port}")
        return True
    
    async def find_peer(self, uid: str) -> Optional[Dict[str, Any]]:
        """
        Find peer in DHT.
        
        Args:
            uid: UID to search for
        
        Returns:
            Peer information if found
        """
        # Placeholder for DHT lookup
        logger.debug(f"DHT lookup: {uid}")
        return None
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get DHT statistics."""
        return {
            'running': self.running,
            'node_id': self.node_id[:16] + '...',
            'routing_table_size': len(self.routing_table),
            'storage_size': len(self.storage),
            'bootstrap_nodes': len(self.bootstrap_nodes),
        }
