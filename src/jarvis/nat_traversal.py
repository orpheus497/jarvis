"""
Jarvis - NAT Traversal for internet connectivity.

Created by orpheus497

This module implements automatic NAT traversal to enable peer-to-peer connections
over the internet without manual port forwarding. Uses UPnP/NAT-PMP for automatic
port mapping and STUN for public IP discovery.
"""

import builtins
import contextlib
import logging
import socket
from enum import Enum
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

try:
    import miniupnpc

    UPNP_AVAILABLE = True
except ImportError:
    logger.warning("miniupnpc not available, UPnP port mapping disabled")
    UPNP_AVAILABLE = False

try:
    import stun

    STUN_AVAILABLE = True
except ImportError:
    logger.warning("pystun3 not available, STUN discovery disabled")
    STUN_AVAILABLE = False


class NATType(Enum):
    """NAT type classifications."""

    UNKNOWN = "unknown"
    OPEN_INTERNET = "open"
    FULL_CONE = "full_cone"
    RESTRICTED_CONE = "restricted_cone"
    PORT_RESTRICTED_CONE = "port_restricted_cone"
    SYMMETRIC = "symmetric"
    SYMMETRIC_UDP_FIREWALL = "symmetric_udp_firewall"
    BLOCKED = "blocked"


class ConnectionStrategy(Enum):
    """Connection strategies based on NAT type."""

    DIRECT = "direct"  # No NAT, direct connection
    UPNP = "upnp"  # UPnP port mapping
    STUN = "stun"  # STUN-discovered public address
    HOLE_PUNCH = "hole_punch"  # UDP hole punching
    RELAY = "relay"  # Relay server (future)
    MANUAL = "manual"  # Manual port forwarding required


class NATTraversal:
    """
    Handles NAT traversal for peer-to-peer connections.

    Provides automatic port mapping via UPnP/NAT-PMP and public IP discovery
    via STUN. Determines optimal connection strategy based on NAT type.
    """

    # Public STUN servers
    STUN_SERVERS = [
        ("stun.l.google.com", 19302),
        ("stun1.l.google.com", 19302),
        ("stun2.l.google.com", 19302),
        ("stun3.l.google.com", 19302),
        ("stun4.l.google.com", 19302),
        ("stun.stunprotocol.org", 3478),
        ("stun.voip.blackberry.com", 3478),
    ]

    def __init__(self):
        """Initialize NAT traversal manager."""
        self.upnp = None
        self.nat_type = NATType.UNKNOWN
        self.public_ip = None
        self.public_port = None
        self.local_ip = None
        self.local_port = None
        self.mapped_ports = {}  # Track UPnP mappings

        # Initialize UPnP if available
        if UPNP_AVAILABLE:
            try:
                self.upnp = miniupnpc.UPnP()
                self.upnp.discoverdelay = 200  # milliseconds
            except Exception as e:
                logger.warning(f"Failed to initialize UPnP: {e}")
                self.upnp = None

    def detect_nat_type(self, local_port: int = 0) -> NATType:
        """
        Detect NAT type using STUN protocol.

        Args:
            local_port: Local port to bind for STUN test (0 = random)

        Returns:
            NATType enum value
        """
        if not STUN_AVAILABLE:
            logger.warning("STUN not available, cannot detect NAT type")
            self.nat_type = NATType.UNKNOWN
            return self.nat_type

        try:
            # Try multiple STUN servers
            for stun_host, stun_port in self.STUN_SERVERS:
                try:
                    nat_type, external_ip, external_port = stun.get_nat_type(
                        source_port=local_port, stun_host=stun_host, stun_port=stun_port
                    )

                    # Map pystun3 response to our enum
                    nat_mapping = {
                        stun.OpenInternet: NATType.OPEN_INTERNET,
                        stun.FullCone: NATType.FULL_CONE,
                        stun.RestrictedCone: NATType.RESTRICTED_CONE,
                        stun.PortRestrictedCone: NATType.PORT_RESTRICTED_CONE,
                        stun.Symmetric: NATType.SYMMETRIC,
                        stun.SymmetricUDPFirewall: NATType.SYMMETRIC_UDP_FIREWALL,
                        stun.Blocked: NATType.BLOCKED,
                    }

                    self.nat_type = nat_mapping.get(nat_type, NATType.UNKNOWN)

                    if external_ip and external_port:
                        self.public_ip = external_ip
                        self.public_port = external_port
                        logger.info(f"NAT type detected: {self.nat_type.value}")
                        logger.info(f"Public address: {external_ip}:{external_port}")
                        return self.nat_type

                except Exception as e:
                    logger.debug(f"STUN server {stun_host} failed: {e}")
                    continue

            logger.warning("All STUN servers failed")
            self.nat_type = NATType.UNKNOWN
            return self.nat_type

        except Exception as e:
            logger.error(f"NAT type detection failed: {e}")
            self.nat_type = NATType.UNKNOWN
            return self.nat_type

    def get_public_address(self, local_port: int = 0) -> Optional[Tuple[str, int]]:
        """
        Discover public IP and port using STUN.

        Args:
            local_port: Local port to bind for STUN test (0 = random)

        Returns:
            Tuple of (public_ip, public_port) or None if failed
        """
        if not STUN_AVAILABLE:
            logger.warning("STUN not available, cannot discover public address")
            return None

        try:
            # Try each STUN server
            for stun_host, stun_port in self.STUN_SERVERS:
                try:
                    _nat_type, external_ip, external_port = stun.get_nat_type(
                        source_port=local_port, stun_host=stun_host, stun_port=stun_port
                    )

                    if external_ip and external_port:
                        self.public_ip = external_ip
                        self.public_port = external_port
                        logger.info(f"Public address: {external_ip}:{external_port}")
                        return (external_ip, external_port)

                except Exception as e:
                    logger.debug(f"STUN server {stun_host} failed: {e}")
                    continue

            logger.warning("Failed to discover public address")
            return None

        except Exception as e:
            logger.error(f"Public address discovery failed: {e}")
            return None

    def setup_upnp_mapping(
        self,
        local_port: int,
        external_port: Optional[int] = None,
        protocol: str = "TCP",
        description: str = "Jarvis P2P",
        duration: int = 3600,
    ) -> Optional[Tuple[str, int]]:
        """
        Setup UPnP port mapping for automatic port forwarding.

        Args:
            local_port: Local port to map
            external_port: Desired external port (None = same as local)
            protocol: Protocol type ('TCP' or 'UDP')
            description: Mapping description
            duration: Lease duration in seconds (0 = permanent)

        Returns:
            Tuple of (external_ip, external_port) or None if failed
        """
        if not UPNP_AVAILABLE or not self.upnp:
            logger.warning("UPnP not available")
            return None

        if external_port is None:
            external_port = local_port

        try:
            # Discover UPnP devices
            logger.info("Discovering UPnP devices...")
            devices_found = self.upnp.discover()

            if devices_found == 0:
                logger.warning("No UPnP devices found")
                return None

            logger.info(f"Found {devices_found} UPnP device(s)")

            # Select IGD (Internet Gateway Device)
            self.upnp.selectigd()

            # Get external IP
            external_ip = self.upnp.externalipaddress()
            logger.info(f"External IP from UPnP: {external_ip}")

            # Get local IP
            local_ip = self.upnp.lanaddr
            logger.info(f"Local IP: {local_ip}")

            # Try to add port mapping
            logger.info(
                f"Adding UPnP port mapping: {external_port} -> {local_ip}:{local_port} ({protocol})"
            )

            success = self.upnp.addportmapping(
                external_port,  # External port
                protocol,  # Protocol (TCP/UDP)
                local_ip,  # Internal IP
                local_port,  # Internal port
                description,  # Description
                "",  # Remote host ('' = any)
            )

            if success:
                logger.info(f"UPnP port mapping successful: {external_ip}:{external_port}")

                # Store mapping for cleanup
                mapping_key = f"{protocol}:{external_port}"
                self.mapped_ports[mapping_key] = {
                    "external_port": external_port,
                    "protocol": protocol,
                    "local_ip": local_ip,
                    "local_port": local_port,
                }

                self.public_ip = external_ip
                self.public_port = external_port
                self.local_ip = local_ip
                self.local_port = local_port

                return (external_ip, external_port)
            else:
                logger.warning("UPnP port mapping failed")
                return None

        except Exception as e:
            logger.error(f"UPnP port mapping error: {e}")
            return None

    def remove_upnp_mapping(self, external_port: int, protocol: str = "TCP") -> bool:
        """
        Remove UPnP port mapping.

        Args:
            external_port: External port to unmap
            protocol: Protocol type ('TCP' or 'UDP')

        Returns:
            True if successful, False otherwise
        """
        if not UPNP_AVAILABLE or not self.upnp:
            return False

        try:
            logger.info(f"Removing UPnP port mapping: {external_port} ({protocol})")

            success = self.upnp.deleteportmapping(external_port, protocol)

            if success:
                logger.info(f"UPnP port mapping removed: {external_port}")

                # Remove from tracking
                mapping_key = f"{protocol}:{external_port}"
                if mapping_key in self.mapped_ports:
                    del self.mapped_ports[mapping_key]

                return True
            else:
                logger.warning(f"Failed to remove UPnP mapping: {external_port}")
                return False

        except Exception as e:
            logger.error(f"Error removing UPnP mapping: {e}")
            return False

    def cleanup_mappings(self):
        """Remove all UPnP port mappings created by this instance."""
        if not self.mapped_ports:
            return

        logger.info("Cleaning up UPnP port mappings...")

        for _mapping_key, mapping_info in list(self.mapped_ports.items()):
            self.remove_upnp_mapping(mapping_info["external_port"], mapping_info["protocol"])

    def get_connection_strategy(
        self, target_nat_type: Optional[NATType] = None
    ) -> ConnectionStrategy:
        """
        Determine best connection strategy based on NAT types.

        Args:
            target_nat_type: Target peer's NAT type (if known)

        Returns:
            ConnectionStrategy enum value
        """
        # If we don't know our NAT type, detect it
        if self.nat_type == NATType.UNKNOWN:
            self.detect_nat_type()

        # Open internet - direct connection
        if self.nat_type == NATType.OPEN_INTERNET:
            return ConnectionStrategy.DIRECT

        # If UPnP is available and working, prefer it
        if UPNP_AVAILABLE and self.upnp:
            return ConnectionStrategy.UPNP

        # For cone NATs, STUN + hole punching works
        if self.nat_type in [
            NATType.FULL_CONE,
            NATType.RESTRICTED_CONE,
            NATType.PORT_RESTRICTED_CONE,
        ]:
            if target_nat_type in [
                NATType.FULL_CONE,
                NATType.RESTRICTED_CONE,
                NATType.PORT_RESTRICTED_CONE,
            ]:
                return ConnectionStrategy.HOLE_PUNCH
            else:
                return ConnectionStrategy.STUN

        # Symmetric NAT is difficult
        if self.nat_type == NATType.SYMMETRIC:
            if target_nat_type == NATType.OPEN_INTERNET:
                return ConnectionStrategy.STUN
            else:
                # Would need relay server
                return ConnectionStrategy.RELAY

        # Blocked or firewall
        if self.nat_type in [NATType.BLOCKED, NATType.SYMMETRIC_UDP_FIREWALL]:
            return ConnectionStrategy.RELAY

        # Default to manual configuration
        return ConnectionStrategy.MANUAL

    def get_local_ip(self) -> Optional[str]:
        """
        Get local IP address by connecting to external server.

        Returns:
            Local IP address or None
        """
        try:
            # Create a socket and connect to an external server
            # This doesn't actually send data, just determines routing
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except Exception as e:
            logger.debug(f"Failed to get local IP: {e}")
            return None

    def test_connectivity(self, host: str, port: int, timeout: float = 5.0) -> bool:
        """
        Test if we can connect to a remote host:port.

        Args:
            host: Remote host to test
            port: Remote port to test
            timeout: Connection timeout in seconds

        Returns:
            True if connection successful, False otherwise
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception as e:
            logger.debug(f"Connectivity test failed: {e}")
            return False

    def get_status(self) -> Dict[str, Any]:
        """
        Get comprehensive NAT traversal status.

        Returns:
            Dictionary with status information
        """
        return {
            "nat_type": self.nat_type.value,
            "public_ip": self.public_ip,
            "public_port": self.public_port,
            "local_ip": self.local_ip or self.get_local_ip(),
            "local_port": self.local_port,
            "upnp_available": UPNP_AVAILABLE and self.upnp is not None,
            "stun_available": STUN_AVAILABLE,
            "mapped_ports": len(self.mapped_ports),
            "strategy": self.get_connection_strategy().value,
        }

    def __del__(self):
        """Cleanup on destruction."""
        with contextlib.suppress(builtins.BaseException):
            self.cleanup_mappings()
