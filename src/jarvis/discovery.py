"""
Jarvis - Peer Discovery Service for automatic peer finding.

Created by orpheus497

This module implements peer discovery via mDNS (local network) and a simple DHT
(internet). Enables users to find each other without manual IP address exchange.
"""

import asyncio
import contextlib
import hashlib
import json
import logging
import socket
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

from .constants import (
    DISCOVERY_CACHE_TTL,
    MDNS_ANNOUNCEMENT_INTERVAL,
    MDNS_SERVICE_TYPE,
)

logger = logging.getLogger(__name__)

try:
    from zeroconf import ServiceBrowser, ServiceInfo, ServiceStateChange, Zeroconf

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
                "uid": self.uid,
                "username": self.username,
                "public_key": self.public_key,
                "fingerprint": self.fingerprint,
                "version": "2.1.0",
            }

            # Register service
            self.service_info = ServiceInfo(
                MDNS_SERVICE_TYPE,
                service_name,
                addresses=addresses,
                port=port,
                properties=properties,
                server=f"{self.username}.local.",
            )

            self.zeroconf.register_service(self.service_info)
            logger.info(f"mDNS service registered: {service_name} on port {port}")

            # Start browser to discover other peers
            self.browser = ServiceBrowser(
                self.zeroconf, MDNS_SERVICE_TYPE, handlers=[self._on_service_state_change]
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
            with contextlib.suppress(asyncio.CancelledError):
                await self.announcement_task

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

    def _on_service_state_change(
        self, zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange
    ):
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
                        key = key.decode("utf-8")
                    if isinstance(value, bytes):
                        value = value.decode("utf-8")
                    props[key] = value

            # Check if it's us
            peer_uid = props.get("uid")
            if peer_uid == self.uid:
                return  # Ignore our own service

            # Extract peer info
            username = props.get("username", "Unknown")
            public_key = props.get("public_key", "")
            fingerprint = props.get("fingerprint", "")

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
                discovery_method="mdns",
                discovered_at=time.time(),
                last_seen=time.time(),
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
            parts = name.split("-")
            if len(parts) >= 2:
                uid_part = parts[1].split(".")[0]

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
                uid for uid, peer in self.discovered_peers.items() if not peer.is_fresh()
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
                    if not ip.startswith("127."):
                        addresses.append(socket.inet_aton(ip))
        except Exception as e:
            logger.warning(f"Error getting local addresses: {e}")

        return addresses

    async def get_discovered_peers(self) -> List[DiscoveredPeer]:
        """Get list of discovered peers."""
        async with self.cache_lock:
            return [peer for peer in self.discovered_peers.values() if peer.is_fresh()]

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
            "running": self.running,
            "total_discovered": len(self.discovered_peers),
            "fresh_peers": sum(1 for p in self.discovered_peers.values() if p.is_fresh()),
            "mdns_available": ZEROCONF_AVAILABLE,
            "service_registered": self.service_info is not None,
        }


class KBucket:
    """
    K-bucket for Kademlia routing table.

    Stores up to K contacts sorted by last seen time.
    """

    def __init__(self, k: int = 20):
        """
        Initialize K-bucket.

        Args:
            k: Maximum number of contacts (typically 20 in Kademlia)
        """
        self.k = k
        self.contacts: List[Dict[str, Any]] = []
        self.last_updated = time.time()

    def add_contact(self, node_id: str, address: str, port: int, uid: str) -> bool:
        """
        Add or update contact in bucket.

        Args:
            node_id: DHT node ID (SHA-256 hash)
            address: IP address
            port: Port number
            uid: User UID

        Returns:
            True if contact was added or updated
        """
        # Check if contact already exists
        for contact in self.contacts:
            if contact["node_id"] == node_id:
                # Move to end (most recently seen)
                self.contacts.remove(contact)
                contact["last_seen"] = time.time()
                contact["address"] = address
                contact["port"] = port
                self.contacts.append(contact)
                self.last_updated = time.time()
                return True

        # Add new contact if space available
        if len(self.contacts) < self.k:
            self.contacts.append(
                {
                    "node_id": node_id,
                    "address": address,
                    "port": port,
                    "uid": uid,
                    "last_seen": time.time(),
                }
            )
            self.last_updated = time.time()
            return True

        # Bucket full - could implement ping/eviction logic here
        logger.debug(f"K-bucket full ({self.k} contacts), contact not added")
        return False

    def get_contacts(self) -> List[Dict[str, Any]]:
        """Get all contacts in bucket."""
        return self.contacts.copy()

    def remove_contact(self, node_id: str) -> bool:
        """Remove contact from bucket."""
        for contact in self.contacts:
            if contact["node_id"] == node_id:
                self.contacts.remove(contact)
                self.last_updated = time.time()
                return True
        return False


class SimpleDHT:
    """
    Kademlia-based DHT implementation for internet peer discovery.

    Implements a distributed hash table for announcing and discovering
    peers over the internet without requiring a central server.

    Based on Kademlia DHT protocol with 160-bit ID space, k-buckets,
    and iterative lookups.
    """

    # Kademlia constants
    K = 20  # Bucket size (max contacts per bucket)
    ALPHA = 3  # Concurrency parameter for lookups
    ID_BITS = 160  # ID space size (SHA-1 compatible)
    REPUBLISH_INTERVAL = 3600  # Republish stored values every hour
    EXPIRE_TIME = 86400  # Expire stored values after 24 hours
    PING_TIMEOUT = 5  # Timeout for ping requests

    def __init__(self, uid: str, username: str, public_key: str, fingerprint: str):
        """
        Initialize Kademlia DHT node.

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

        # Generate 160-bit node ID from UID
        self.node_id = self._generate_node_id(uid)

        # Initialize routing table (160 k-buckets, one for each bit)
        self.routing_table: List[KBucket] = [KBucket(self.K) for _ in range(self.ID_BITS)]

        # Local storage for key-value pairs
        self.storage: Dict[str, Dict[str, Any]] = {}

        # Bootstrap nodes
        self.bootstrap_nodes: List[Tuple[str, int]] = []

        # Running state
        self.running = False
        self.maintenance_task: Optional[asyncio.Task] = None
        self.server_task: Optional[asyncio.Task] = None
        self.server: Optional[asyncio.Server] = None
        self.listen_port: Optional[int] = None

        # RPC statistics
        self.rpc_stats = {
            "ping_sent": 0,
            "ping_received": 0,
            "store_sent": 0,
            "store_received": 0,
            "find_node_sent": 0,
            "find_node_received": 0,
            "find_value_sent": 0,
            "find_value_received": 0,
        }

        logger.info(f"Kademlia DHT node initialized with ID: {self.node_id[:16]}...")

    def _generate_node_id(self, uid: str) -> str:
        """
        Generate 160-bit node ID from UID.

        Uses SHA-256 truncated to 160 bits (40 hex characters) for compatibility
        with Kademlia's 160-bit ID space while avoiding SHA-1's cryptographic weaknesses.

        Args:
            uid: User identifier string

        Returns:
            160-bit node ID as 40-character hex string
        """
        # Use SHA-256 for security
        full_hash = hashlib.sha256(uid.encode('utf-8')).hexdigest()

        # Truncate to 160 bits (40 hex chars) for Kademlia compatibility
        node_id = full_hash[:40]

        return node_id

    def _xor_distance(self, id1: str, id2: str) -> int:
        """
        Calculate XOR distance between two node IDs.

        Args:
            id1: First node ID (hex string)
            id2: Second node ID (hex string)

        Returns:
            XOR distance as integer
        """
        return int(id1, 16) ^ int(id2, 16)

    def _bucket_index(self, node_id: str) -> int:
        """
        Determine which k-bucket a node belongs to.

        Args:
            node_id: Node ID to find bucket for

        Returns:
            Bucket index (0-159)
        """
        distance = self._xor_distance(self.node_id, node_id)
        if distance == 0:
            return 0
        return self.ID_BITS - 1 - distance.bit_length()

    def add_node(self, node_id: str, address: str, port: int, uid: str) -> bool:
        """
        Add node to routing table.

        Args:
            node_id: DHT node ID
            address: IP address
            port: Port number
            uid: User UID

        Returns:
            True if node was added
        """
        if node_id == self.node_id:
            return False  # Don't add ourselves

        bucket_index = self._bucket_index(node_id)
        bucket = self.routing_table[bucket_index]

        added = bucket.add_contact(node_id, address, port, uid)
        if added:
            logger.debug(
                f"Added node {node_id[:8]}... to bucket {bucket_index} "
                f"({len(bucket.contacts)}/{self.K})"
            )
        return added

    def find_closest_nodes(self, target_id: str, count: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Find the closest nodes to a target ID.

        Args:
            target_id: Target node ID
            count: Number of nodes to return (default: K)

        Returns:
            List of closest nodes sorted by distance
        """
        if count is None:
            count = self.K

        # Collect all known nodes
        all_nodes = []
        for bucket in self.routing_table:
            all_nodes.extend(bucket.get_contacts())

        # Sort by XOR distance to target
        all_nodes.sort(key=lambda n: self._xor_distance(n["node_id"], target_id))

        return all_nodes[:count]

    def store_value(self, key: str, value: Dict[str, Any]) -> None:
        """
        Store key-value pair locally.

        Args:
            key: Storage key (typically a UID)
            value: Value to store (peer information)
        """
        self.storage[key] = {
            "value": value,
            "stored_at": time.time(),
            "expires_at": time.time() + self.EXPIRE_TIME,
        }
        logger.debug(f"Stored value for key {key[:8]}...")

    def get_value(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve value from local storage.

        Args:
            key: Storage key

        Returns:
            Stored value or None if not found/expired
        """
        if key not in self.storage:
            return None

        entry = self.storage[key]
        if time.time() > entry["expires_at"]:
            # Value expired
            del self.storage[key]
            logger.debug(f"Value for key {key[:8]}... expired")
            return None

        return entry["value"]

    async def start(
        self, bootstrap_nodes: Optional[List[Tuple[str, int]]] = None, listen_port: int = 6881
    ):
        """
        Start Kademlia DHT node with RPC server.

        Args:
            bootstrap_nodes: List of (host, port) tuples for bootstrap
            listen_port: Port to listen on for DHT RPCs (default: 6881)
        """
        self.running = True
        self.bootstrap_nodes = bootstrap_nodes or []
        self.listen_port = listen_port

        # Start RPC server
        try:
            self.server = await asyncio.start_server(
                self._handle_rpc_connection, "0.0.0.0", listen_port
            )
            logger.info(f"DHT RPC server listening on port {listen_port}")
        except Exception as e:
            logger.error(f"Failed to start DHT RPC server: {e}")
            self.running = False
            return

        logger.info("Kademlia DHT node started")

        # Connect to bootstrap nodes if provided
        if self.bootstrap_nodes:
            await self._bootstrap()

        # Start periodic maintenance task
        self.maintenance_task = asyncio.create_task(self._maintenance_loop())

        logger.info(
            f"DHT operational with {len(self.bootstrap_nodes)} bootstrap nodes, "
            f"{sum(len(b.contacts) for b in self.routing_table)} known peers"
        )

    async def _bootstrap(self):
        """Bootstrap by connecting to known nodes."""
        logger.info(f"Bootstrapping with {len(self.bootstrap_nodes)} nodes...")

        for host, port in self.bootstrap_nodes:
            try:
                # Ping bootstrap node to verify it's alive
                logger.debug(f"Pinging bootstrap node {host}:{port}")
                response = await self._send_ping(host, port)

                if response and "node_id" in response:
                    # Add bootstrap node to routing table
                    boot_node_id = response["node_id"]
                    self.add_node(boot_node_id, host, port, response.get("uid", ""))

                    # Find nodes close to ourselves
                    logger.debug(f"Finding nodes close to our ID from {host}:{port}")
                    find_response = await self._send_find_node(host, port, self.node_id)

                    if find_response and "nodes" in find_response:
                        # Add discovered nodes to routing table
                        for node in find_response["nodes"]:
                            self.add_node(
                                node["node_id"], node["host"], node["port"], node.get("uid", "")
                            )
                        logger.info(
                            f"Discovered {len(find_response['nodes'])} nodes from bootstrap"
                        )
            except Exception as e:
                logger.warning(f"Bootstrap from {host}:{port} failed: {e}")

    async def _maintenance_loop(self):
        """Periodic maintenance task."""
        while self.running:
            try:
                await asyncio.sleep(self.REPUBLISH_INTERVAL)

                # Clean expired storage entries
                expired_keys = [
                    key
                    for key, entry in self.storage.items()
                    if time.time() > entry["expires_at"]
                ]

                for key in expired_keys:
                    del self.storage[key]

                if expired_keys:
                    logger.debug(f"Cleaned {len(expired_keys)} expired DHT entries")

                # Log statistics
                total_contacts = sum(len(b.contacts) for b in self.routing_table)
                logger.debug(
                    f"DHT maintenance: {total_contacts} contacts, "
                    f"{len(self.storage)} stored values"
                )

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"DHT maintenance error: {e}")

    async def stop(self):
        """Stop Kademlia DHT node."""
        self.running = False

        # Stop RPC server
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("DHT RPC server stopped")

        # Cancel maintenance task
        if self.maintenance_task:
            self.maintenance_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.maintenance_task

        logger.info("Kademlia DHT node stopped")

    async def announce(self, port: int) -> bool:
        """
        Announce presence in DHT.

        Stores our contact information in the DHT at our UID key.

        Args:
            port: Port we're listening on

        Returns:
            True if announced successfully
        """
        # Create peer information
        peer_info = {
            "uid": self.uid,
            "username": self.username,
            "public_key": self.public_key,
            "fingerprint": self.fingerprint,
            "port": port,
            "announced_at": time.time(),
        }

        # Store locally
        key = self._generate_node_id(self.uid)
        self.store_value(key, peer_info)

        # Find K closest nodes to our UID
        closest_nodes = self.find_closest_nodes(key, self.K)

        # Send STORE RPC to each closest node
        store_count = 0
        for node in closest_nodes:
            try:
                success = await self._send_store(node["address"], node["port"], key, peer_info)
                if success:
                    store_count += 1
            except Exception as e:
                logger.debug(f"Failed to store at {node['address']}:{node['port']}: {e}")

        logger.info(
            f"Announced presence in DHT: {self.username} on port {port} "
            f"(stored at {store_count}/{len(closest_nodes)} nodes)"
        )
        return store_count > 0 or len(closest_nodes) == 0

    async def find_peer(self, uid: str) -> Optional[Dict[str, Any]]:
        """
        Find peer in DHT using iterative lookup.

        Args:
            uid: UID to search for

        Returns:
            Peer information if found, None otherwise
        """
        # Generate key from UID
        key = self._generate_node_id(uid)

        # Check local storage first
        local_value = self.get_value(key)
        if local_value:
            logger.debug(f"Found peer {uid[:8]}... in local storage")
            return local_value

        # Perform iterative lookup
        closest_nodes = self.find_closest_nodes(key, self.K)
        queried_nodes = set()
        found_value = None

        # Query nodes in batches of ALPHA
        while closest_nodes and not found_value:
            # Select next ALPHA nodes to query
            to_query = []
            for node in closest_nodes:
                node_id = node["node_id"]
                if node_id not in queried_nodes:
                    to_query.append(node)
                    queried_nodes.add(node_id)
                if len(to_query) >= self.ALPHA:
                    break

            if not to_query:
                break

            # Query nodes concurrently
            tasks = []
            for node in to_query:
                task = self._send_find_value(node["address"], node["port"], key)
                tasks.append(task)

            responses = await asyncio.gather(*tasks, return_exceptions=True)

            # Process responses
            for response in responses:
                if isinstance(response, dict):
                    if "value" in response:
                        # Found the value!
                        found_value = response["value"]
                        logger.info(f"Found peer {uid[:8]}... in DHT via iterative lookup")
                        break
                    elif "nodes" in response:
                        # Add new nodes to search space
                        for new_node in response["nodes"]:
                            if new_node["node_id"] not in queried_nodes:
                                self.add_node(
                                    new_node["node_id"],
                                    new_node["host"],
                                    new_node["port"],
                                    new_node.get("uid", ""),
                                )

            if not found_value:
                # Update closest nodes for next iteration
                closest_nodes = self.find_closest_nodes(key, self.K)

        if not found_value:
            logger.debug(f"Peer {uid[:8]}... not found in DHT after querying {len(queried_nodes)} nodes")

        return found_value

    async def _handle_rpc_connection(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        """Handle incoming RPC connection."""
        addr = writer.get_extra_info("peername")
        try:
            # Read request (4-byte length prefix + JSON)
            length_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=5.0)
            length = int.from_bytes(length_bytes, "big")

            if length > 65536:  # 64KB max
                logger.warning(f"RPC request too large from {addr}: {length} bytes")
                writer.close()
                await writer.wait_closed()
                return

            data = await asyncio.wait_for(reader.readexactly(length), timeout=5.0)
            request = json.loads(data.decode("utf-8"))

            # Process request
            response = await self._process_rpc(request, addr)

            # Send response
            response_json = json.dumps(response).encode("utf-8")
            response_length = len(response_json).to_bytes(4, "big")
            writer.write(response_length + response_json)
            await writer.drain()

        except Exception as e:
            logger.debug(f"RPC error from {addr}: {e}")
        finally:
            writer.close()
            await writer.wait_closed()

    async def _process_rpc(self, request: Dict[str, Any], addr: Tuple) -> Dict[str, Any]:
        """Process RPC request and return response."""
        rpc_type = request.get("type")

        if rpc_type == "ping":
            self.rpc_stats["ping_received"] += 1
            return {
                "type": "pong",
                "node_id": self.node_id,
                "uid": self.uid,
                "username": self.username,
            }

        elif rpc_type == "store":
            self.rpc_stats["store_received"] += 1
            key = request.get("key")
            value = request.get("value")
            if key and value:
                self.store_value(key, value)
                return {"type": "store_response", "success": True}
            return {"type": "store_response", "success": False}

        elif rpc_type == "find_node":
            self.rpc_stats["find_node_received"] += 1
            target_id = request.get("target_id")
            if target_id:
                closest = self.find_closest_nodes(target_id, self.K)
                return {
                    "type": "find_node_response",
                    "nodes": [
                        {
                            "node_id": n["node_id"],
                            "host": n["address"],
                            "port": n["port"],
                            "uid": n.get("uid", ""),
                        }
                        for n in closest
                    ],
                }
            return {"type": "find_node_response", "nodes": []}

        elif rpc_type == "find_value":
            self.rpc_stats["find_value_received"] += 1
            key = request.get("key")
            if key:
                value = self.get_value(key)
                if value:
                    return {"type": "find_value_response", "value": value}
                else:
                    # Return closest nodes instead
                    closest = self.find_closest_nodes(key, self.K)
                    return {
                        "type": "find_value_response",
                        "nodes": [
                            {
                                "node_id": n["node_id"],
                                "host": n["address"],
                                "port": n["port"],
                                "uid": n.get("uid", ""),
                            }
                            for n in closest
                        ],
                    }
            return {"type": "find_value_response"}

        return {"type": "error", "message": "Unknown RPC type"}

    async def _send_ping(self, host: str, port: int) -> Optional[Dict[str, Any]]:
        """Send PING RPC to node."""
        self.rpc_stats["ping_sent"] += 1
        return await self._send_rpc(host, port, {"type": "ping"})

    async def _send_store(
        self, host: str, port: int, key: str, value: Dict[str, Any]
    ) -> bool:
        """Send STORE RPC to node."""
        self.rpc_stats["store_sent"] += 1
        response = await self._send_rpc(host, port, {"type": "store", "key": key, "value": value})
        return response and response.get("success", False)

    async def _send_find_node(
        self, host: str, port: int, target_id: str
    ) -> Optional[Dict[str, Any]]:
        """Send FIND_NODE RPC to node."""
        self.rpc_stats["find_node_sent"] += 1
        return await self._send_rpc(host, port, {"type": "find_node", "target_id": target_id})

    async def _send_find_value(
        self, host: str, port: int, key: str
    ) -> Optional[Dict[str, Any]]:
        """Send FIND_VALUE RPC to node."""
        self.rpc_stats["find_value_sent"] += 1
        return await self._send_rpc(host, port, {"type": "find_value", "key": key})

    async def _send_rpc(
        self, host: str, port: int, request: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Send RPC request and get response."""
        try:
            # Connect to node
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.PING_TIMEOUT
            )

            # Send request
            request_json = json.dumps(request).encode("utf-8")
            request_length = len(request_json).to_bytes(4, "big")
            writer.write(request_length + request_json)
            await writer.drain()

            # Read response
            length_bytes = await asyncio.wait_for(reader.readexactly(4), timeout=self.PING_TIMEOUT)
            length = int.from_bytes(length_bytes, "big")

            if length > 65536:  # 64KB max
                writer.close()
                await writer.wait_closed()
                return None

            data = await asyncio.wait_for(reader.readexactly(length), timeout=self.PING_TIMEOUT)
            response = json.loads(data.decode("utf-8"))

            writer.close()
            await writer.wait_closed()

            return response

        except Exception as e:
            logger.debug(f"RPC to {host}:{port} failed: {e}")
            return None

    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive DHT statistics."""
        total_contacts = sum(len(b.contacts) for b in self.routing_table)
        non_empty_buckets = sum(1 for b in self.routing_table if len(b.contacts) > 0)

        return {
            "running": self.running,
            "node_id": self.node_id[:16] + "...",
            "total_contacts": total_contacts,
            "non_empty_buckets": non_empty_buckets,
            "total_buckets": self.ID_BITS,
            "storage_size": len(self.storage),
            "bootstrap_nodes": len(self.bootstrap_nodes),
            "k_parameter": self.K,
            "alpha_parameter": self.ALPHA,
            "listen_port": self.listen_port,
            "rpc_stats": self.rpc_stats.copy(),
        }
