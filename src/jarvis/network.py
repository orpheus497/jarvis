"""
Jarvis - Asynchronous peer-to-peer networking layer with group chat support.

Created by orpheus497

This module implements:
- Direct P2P TCP connections using asyncio
- Multi-layer encrypted data transmission
- Group chat message routing
- Automatic reconnection handling
- Connection pooling and management
- Unified asynchronous architecture
- NAT traversal for internet connectivity
- Connection state machine for reliability
- Peer discovery via mDNS
- Security manager for connection protection
"""

import asyncio
import struct
import logging
from typing import Optional, Callable, Dict, Tuple, List, Set
from datetime import datetime, timezone
from pathlib import Path

from . import crypto
from . import protocol
from .contact import Contact
from .protocol import MessageType, Protocol
from .rate_limiter import RateLimiter
from .metrics import ConnectionMetrics
from .errors import NetworkError, ErrorCode

from .nat_traversal import NATTraversal, ConnectionStrategy
from .connection_fsm import ConnectionStateMachine, ConnectionState as FSMState, ConnectionEvent
from .discovery import DiscoveryService
from .security_manager import SecurityManager
from .message_queue import MessageQueue

# Configure logging for connection diagnostics
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class SecurityError(Exception):
    """Raised when a security violation is detected."""
    pass


class ConnectionState:
    """Connection state enumeration."""
    DISCONNECTED = 0
    CONNECTING = 1
    CONNECTED = 2
    AUTHENTICATED = 3
    ERROR = 4


class ConnectionStatus:
    """
    Connection status indicators for UI display.
    
    GREEN: All connections active (server online, all peers connected)
    AMBER: Partial connections (server online, some peers connected)
    RED: No connections (server online, no peers connected)
    GREY: Server offline (cannot send or receive)
    """
    GREEN = "green"   # All members online and connected
    AMBER = "amber"   # Some members online, connection active
    RED = "red"       # No connections active, but server running
    GREY = "grey"     # Server offline completely


class P2PConnection:
    """Represents an asynchronous P2P connection with another user."""

    # Connection timeouts and retry configuration
    CONNECT_TIMEOUT = 10  # Seconds to wait for initial connection
    HANDSHAKE_TIMEOUT = 15  # Seconds to wait for handshake completion
    OPERATION_TIMEOUT = 60  # Seconds for read operations during normal operation
    PING_INTERVAL = 30  # Seconds between keepalive pings
    PONG_TIMEOUT = 90  # Seconds before considering connection dead

    # Resource limits
    SEND_QUEUE_MAX_SIZE = 1000  # Maximum queued outgoing messages
    RECEIVE_BUFFER_MAX_SIZE = 1024 * 1024  # 1MB max receive buffer
    
    def __init__(self, contact: Contact, identity: crypto.IdentityKeyPair,
                 my_uid: str, my_username: str,
                 rate_limiter: Optional[RateLimiter] = None,
                 metrics: Optional[ConnectionMetrics] = None):
        self.contact = contact
        self.identity = identity
        self.my_uid = my_uid
        self.my_username = my_username

        self.session_keys: Optional[Tuple[bytes, bytes, bytes, bytes, bytes]] = None
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.state = ConnectionState.DISCONNECTED
        
        # Connection state machine
        self.fsm = ConnectionStateMachine()
        self.fsm.on_state_change = self._on_fsm_state_change
        self.fsm.on_connected = self._on_fsm_connected
        self.fsm.on_disconnected = self._on_fsm_disconnected

        self.receive_task: Optional[asyncio.Task] = None
        self.send_queue = asyncio.Queue(maxsize=self.SEND_QUEUE_MAX_SIZE)
        self.send_task: Optional[asyncio.Task] = None
        self.keepalive_task: Optional[asyncio.Task] = None

        self.buffer = b''
        self.last_ping = asyncio.get_event_loop().time()
        self.last_pong = asyncio.get_event_loop().time()

        # Rate limiting and metrics
        self.rate_limiter = rate_limiter
        self.metrics = metrics or ConnectionMetrics(contact.address or 'unknown')

        # Connection statistics for diagnostics
        self.connection_attempts = 0
        self.last_error = None
        self.bytes_sent = 0
        self.bytes_received = 0

        # Callbacks
        self.on_message_callback: Optional[Callable] = None
        self.on_group_message_callback: Optional[Callable] = None
        self.on_state_change_callback: Optional[Callable] = None
        
        self._lock = asyncio.Lock()
    
    def _on_fsm_state_change(self, old_state: FSMState, new_state: FSMState):
        """Handle FSM state changes."""
        logger.debug(f"Connection FSM: {old_state.name} -> {new_state.name} for {self.contact.username}")
        
        # Update legacy state for compatibility
        if new_state == FSMState.CONNECTED:
            self._set_state(ConnectionState.AUTHENTICATED)
        elif new_state in [FSMState.CONNECTING, FSMState.AUTHENTICATING]:
            self._set_state(ConnectionState.CONNECTING)
        elif new_state == FSMState.DISCONNECTED:
            self._set_state(ConnectionState.DISCONNECTED)
        elif new_state == FSMState.ERROR:
            self._set_state(ConnectionState.ERROR)
    
    def _on_fsm_connected(self):
        """Called when FSM reaches CONNECTED state."""
        logger.info(f"FSM confirms connection to {self.contact.username}")
    
    def _on_fsm_disconnected(self):
        """Called when FSM reaches DISCONNECTED state."""
        logger.info(f"FSM confirms disconnection from {self.contact.username}")
    
    async def connect(self) -> bool:
        """
        Establish connection to peer.
        
        Connection flow:
        1. TCP socket connection
        2. Exchange public keys
        3. Verify fingerprint
        4. Derive session keys
        5. Send handshake
        6. Receive handshake response
        7. Start send/receive tasks
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            self.connection_attempts += 1
            
            # FSM: Start connection process
            self.fsm.transition(ConnectionEvent.CONNECT_REQUESTED)
            
            self._set_state(ConnectionState.CONNECTING)
            logger.info(f"Attempting connection to {self.contact.username} ({self.contact.host}:{self.contact.port}) - Attempt #{self.connection_attempts}")
            
            # Create connection with timeout
            try:
                self.reader, self.writer = await asyncio.wait_for(
                    asyncio.open_connection(self.contact.host, self.contact.port),
                    timeout=self.CONNECT_TIMEOUT
                )
                logger.debug(f"TCP connection established to {self.contact.username}")
                
                # FSM: TCP connected
                self.fsm.transition(ConnectionEvent.TCP_CONNECTED)
            except asyncio.TimeoutError:
                logger.warning(f"Connection timeout to {self.contact.username} after {self.CONNECT_TIMEOUT}s")
                self.fsm.transition(ConnectionEvent.TCP_FAILED)
                raise ConnectionError("Connection timeout")
            except OSError as e:
                logger.warning(f"Connection failed to {self.contact.username}: {e}")
                self.fsm.transition(ConnectionEvent.TCP_FAILED)
                raise
            
            # FSM: Start authentication
            self.fsm.transition(ConnectionEvent.AUTH_STARTED)
            
            # Send our public key
            our_public_key = self.identity.get_public_key_bytes()
            self.writer.write(struct.pack('!I', len(our_public_key)))
            self.writer.write(our_public_key)
            await self.writer.drain()
            logger.debug(f"Sent public key to {self.contact.username}")
            
            # Receive peer's public key with timeout
            try:
                key_len_data = await asyncio.wait_for(
                    self.reader.readexactly(4),
                    timeout=self.HANDSHAKE_TIMEOUT
                )
                key_len = struct.unpack('!I', key_len_data)[0]
                if key_len != 32:
                    logger.error(f"Invalid public key length from {self.contact.username}: {key_len}")
                    self.fsm.transition(ConnectionEvent.AUTH_FAILED)
                    raise ValueError(f"Invalid public key length: {key_len}")
                
                peer_public_key_bytes = await asyncio.wait_for(
                    self.reader.readexactly(key_len),
                    timeout=self.HANDSHAKE_TIMEOUT
                )
                peer_public_key = crypto.IdentityKeyPair.from_public_bytes(peer_public_key_bytes)
                logger.debug(f"Received public key from {self.contact.username}")
            except asyncio.TimeoutError:
                logger.error(f"Handshake timeout with {self.contact.username}")
                self.fsm.transition(ConnectionEvent.AUTH_FAILED)
                raise ConnectionError("Handshake timeout")
            
            # Verify fingerprint
            received_fingerprint = crypto.generate_fingerprint(peer_public_key_bytes)
            if received_fingerprint != self.contact.fingerprint:
                logger.error(f"Fingerprint mismatch for {self.contact.username}! Possible MITM attack!")
                logger.error(f"Expected: {self.contact.fingerprint}")
                logger.error(f"Received: {received_fingerprint}")
                raise SecurityError("Fingerprint mismatch - possible MITM attack!")
            logger.debug(f"Fingerprint verified for {self.contact.username}")
            
            # Derive session keys using X25519 key exchange
            self.session_keys = crypto.perform_key_exchange(
                self.identity.private_key,
                peer_public_key
            )
            logger.debug(f"Session keys derived for {self.contact.username}")
            
            self._set_state(ConnectionState.CONNECTED)
            
            # Send handshake
            handshake = Protocol.create_handshake(
                self.my_uid,
                self.my_username,
                crypto.generate_fingerprint(self.identity.get_public_key_bytes())
            )
            self.writer.write(handshake)
            await self.writer.drain()
            logger.debug(f"Sent handshake to {self.contact.username}")
            
            # Wait for handshake response
            try:
                header_data = await asyncio.wait_for(
                    self.reader.readexactly(Protocol.HEADER_SIZE),
                    timeout=self.HANDSHAKE_TIMEOUT
                )
                version, msg_type_int, payload_length = struct.unpack('!BHI', header_data)
                
                # Receive the full payload
                payload_data = await asyncio.wait_for(
                    self.reader.readexactly(payload_length),
                    timeout=self.HANDSHAKE_TIMEOUT
                )
                full_message = header_data + payload_data
            except asyncio.TimeoutError:
                logger.error(f"Timeout waiting for handshake response from {self.contact.username}")
                raise ConnectionError("Handshake response timeout")
            
            # Unpack and verify handshake response
            msg_type, response_payload, _ = Protocol.unpack_message(full_message)
            if msg_type != MessageType.HANDSHAKE_RESPONSE:
                logger.error(f"Expected HANDSHAKE_RESPONSE from {self.contact.username}, got {msg_type}")
                raise ValueError(f"Expected HANDSHAKE_RESPONSE, got {msg_type}")
            
            if not response_payload.get('accepted', False):
                logger.warning(f"Handshake rejected by {self.contact.username}")
                raise ConnectionRefusedError("Handshake rejected by peer")
            
            logger.debug(f"Handshake accepted by {self.contact.username}")
            
            # FSM: Authentication complete
            self.fsm.transition(ConnectionEvent.AUTH_COMPLETE)
            
            # Mark as authenticated
            self._set_state(ConnectionState.AUTHENTICATED)
            
            # Start tasks
            self.receive_task = asyncio.create_task(self._receive_loop())
            self.send_task = asyncio.create_task(self._send_loop())
            self.keepalive_task = asyncio.create_task(self._keepalive_loop())
            
            logger.info(f"Successfully connected to {self.contact.username}")
            self.last_error = None
            return True
            
        except asyncio.TimeoutError as e:
            self.last_error = f"Timeout: {e}"
            logger.warning(f"Connection to {self.contact.username} timed out: {e}")
            self._set_state(ConnectionState.ERROR)
            await self.disconnect()
            return False
        except OSError as e:
            self.last_error = f"OS error: {e}"
            logger.warning(f"OS error connecting to {self.contact.username}: {e}")
            self._set_state(ConnectionState.ERROR)
            await self.disconnect()
            return False
        except Exception as e:
            self.last_error = f"Error: {e}"
            logger.error(f"Unexpected error connecting to {self.contact.username}: {e}", exc_info=True)
            self._set_state(ConnectionState.ERROR)
            await self.disconnect()
            return False
    
    async def send_message(self, plaintext: str, message_id: str, timestamp: str) -> bool:
        """
        Send encrypted message to peer.
        
        Returns:
            True if message queued successfully, False otherwise
        """
        if self.state != ConnectionState.AUTHENTICATED or not self.session_keys:
            logger.warning(f"Cannot send message to {self.contact.username}: Not authenticated (state={self.state})")
            return False
        
        try:
            # Encrypt message with five-layer encryption
            encrypted = crypto.encrypt_message_five_layer(plaintext, self.session_keys)
            
            # Create protocol message
            message = Protocol.create_text_message(message_id, plaintext, timestamp, encrypted)

            # Add to send queue with timeout to prevent blocking
            try:
                await asyncio.wait_for(self.send_queue.put(message), timeout=5.0)
                logger.debug(f"Message queued for {self.contact.username} (ID: {message_id})")
                return True
            except asyncio.TimeoutError:
                logger.error(f"Send queue full for {self.contact.username}, message dropped")
                return False
            
        except crypto.CryptoError as e:
            logger.error(f"Encryption failed for message to {self.contact.username}: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to queue message to {self.contact.username}: {e}", exc_info=True)
            return False
    
    async def send_group_message(self, group_id: str, message_id: str, 
                                  plaintext: str, timestamp: str) -> bool:
        """Send encrypted group message to peer."""
        if self.state != ConnectionState.AUTHENTICATED or not self.session_keys:
            logger.warning(f"Cannot send group message to {self.contact.username}: Not authenticated (state={self.state})")
            return False
        
        try:
            encrypted = crypto.encrypt_message_five_layer(plaintext, self.session_keys)
            
            message = Protocol.create_group_message(
                group_id, message_id, self.my_uid,
                plaintext, timestamp, encrypted
            )

            # Add to send queue with timeout to prevent blocking
            try:
                await asyncio.wait_for(self.send_queue.put(message), timeout=5.0)
                logger.debug(f"Group message queued for {self.contact.username} (Group: {group_id[:8]}, ID: {message_id})")
                return True
            except asyncio.TimeoutError:
                logger.error(f"Send queue full for {self.contact.username}, group message dropped")
                return False
            
        except crypto.CryptoError as e:
            logger.error(f"Encryption failed for group message to {self.contact.username}: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to queue group message to {self.contact.username}: {e}", exc_info=True)
            return False
    
    async def _receive_loop(self):
        """Background task for receiving messages."""
        logger.debug(f"Receive loop started for {self.contact.username}")
        
        try:
            while self.state in (ConnectionState.CONNECTED, ConnectionState.AUTHENTICATED):
                try:
                    # Receive data with timeout
                    data = await asyncio.wait_for(
                        self.reader.read(4096),
                        timeout=self.OPERATION_TIMEOUT
                    )
                    
                    if not data:
                        logger.warning(f"Connection closed by {self.contact.username}")
                        break

                    # Track metrics for received data
                    self.bytes_received += len(data)
                    self.metrics.record_packet_received(len(data))
                    self.buffer += data

                    # Check buffer size to prevent memory exhaustion
                    if len(self.buffer) > self.RECEIVE_BUFFER_MAX_SIZE:
                        logger.error(
                            f"Receive buffer overflow for {self.contact.username} "
                            f"({len(self.buffer)} bytes), disconnecting"
                        )
                        await self.disconnect()
                        return

                    # Process all complete messages in buffer
                    while len(self.buffer) >= Protocol.HEADER_SIZE:
                        result = Protocol.unpack_message(self.buffer)
                        if not result:
                            break

                        msg_type, payload, consumed = result
                        self.buffer = self.buffer[consumed:]

                        # Check rate limiting if enabled
                        if self.rate_limiter:
                            address = self.contact.address or 'unknown'
                            if not self.rate_limiter.check_message_rate(address):
                                logger.warning(
                                    f"Rate limit exceeded for {self.contact.username}, "
                                    f"dropping message"
                                )
                                continue

                        # Handle message
                        try:
                            await self._handle_message(msg_type, payload)
                        except Exception as e:
                            logger.error(f"Error handling message from {self.contact.username}: {e}", exc_info=True)
                
                except asyncio.TimeoutError:
                    # Timeout is normal, just continue
                    continue
                except asyncio.CancelledError:
                    logger.debug(f"Receive loop cancelled for {self.contact.username}")
                    break
                except Exception as e:
                    logger.error(f"Unexpected error in receive loop for {self.contact.username}: {e}", exc_info=True)
                    break
        finally:
            logger.debug(f"Receive loop ended for {self.contact.username}")
            await self.disconnect()
    
    async def _send_loop(self):
        """Background task for sending messages."""
        logger.debug(f"Send loop started for {self.contact.username}")
        
        try:
            while self.state in (ConnectionState.CONNECTED, ConnectionState.AUTHENTICATED):
                try:
                    # Get message from queue with timeout
                    message = await asyncio.wait_for(
                        self.send_queue.get(),
                        timeout=1.0
                    )
                    
                    # Send message
                    self.writer.write(message)
                    await self.writer.drain()
                    self.bytes_sent += len(message)

                    # Track metrics for sent data
                    self.metrics.record_packet_sent(len(message))
                    
                except asyncio.TimeoutError:
                    continue
                except asyncio.CancelledError:
                    logger.debug(f"Send loop cancelled for {self.contact.username}")
                    break
                except Exception as e:
                    logger.error(f"Error in send loop for {self.contact.username}: {e}", exc_info=True)
                    break
        finally:
            logger.debug(f"Send loop ended for {self.contact.username}")
    
    async def _keepalive_loop(self):
        """Background task for keepalive pings."""
        logger.debug(f"Keepalive loop started for {self.contact.username}")
        
        try:
            while self.state in (ConnectionState.CONNECTED, ConnectionState.AUTHENTICATED):
                await asyncio.sleep(self.PING_INTERVAL)
                
                if self.state != ConnectionState.AUTHENTICATED:
                    continue
                
                # Send ping
                try:
                    ping = Protocol.create_ping()
                    # Use timeout to prevent blocking if queue is full
                    try:
                        await asyncio.wait_for(self.send_queue.put(ping), timeout=1.0)
                        self.last_ping = asyncio.get_event_loop().time()

                        # Record ping time for latency measurement
                        self.metrics.record_ping()
                    except asyncio.TimeoutError:
                        logger.warning(f"Send queue full, skipping ping for {self.contact.username}")

                    # Check if we've received a pong recently
                    if asyncio.get_event_loop().time() - self.last_pong > self.PONG_TIMEOUT:
                        logger.warning(f"No pong from {self.contact.username} in {self.PONG_TIMEOUT}s")
                        await self.disconnect()
                        break
                except Exception as e:
                    logger.error(f"Error in keepalive for {self.contact.username}: {e}")
                    break
        except asyncio.CancelledError:
            logger.debug(f"Keepalive loop cancelled for {self.contact.username}")
        finally:
            logger.debug(f"Keepalive loop ended for {self.contact.username}")
    
    async def _handle_message(self, msg_type: MessageType, payload: Dict):
        """Handle received message based on type."""
        
        if msg_type == MessageType.HANDSHAKE_RESPONSE:
            # Handshake response is handled during connection establishment
            pass
        
        elif msg_type == MessageType.TEXT_MESSAGE:
            # Decrypt and deliver text message
            if self.session_keys and self.on_message_callback:
                try:
                    encrypted_data = payload.get('encrypted', {})
                    plaintext = crypto.decrypt_message_five_layer(encrypted_data, self.session_keys)
                    
                    # Call callback (may be sync or async)
                    if asyncio.iscoroutinefunction(self.on_message_callback):
                        await self.on_message_callback(
                            self.contact.uid,
                            plaintext,
                            payload.get('message_id'),
                            payload.get('timestamp')
                        )
                    else:
                        self.on_message_callback(
                            self.contact.uid,
                            plaintext,
                            payload.get('message_id'),
                            payload.get('timestamp')
                        )
                except crypto.CryptoError as e:
                    logger.error(f"Decryption failed for message from {self.contact.username}: {e}")
        
        elif msg_type == MessageType.GROUP_MESSAGE:
            # Decrypt and deliver group message
            if self.session_keys and self.on_group_message_callback:
                try:
                    encrypted_data = payload.get('encrypted', {})
                    plaintext = crypto.decrypt_message_five_layer(encrypted_data, self.session_keys)
                    
                    # Call callback (may be sync or async)
                    if asyncio.iscoroutinefunction(self.on_group_message_callback):
                        await self.on_group_message_callback(
                            payload.get('group_id'),
                            payload.get('sender_uid'),
                            plaintext,
                            payload.get('message_id'),
                            payload.get('timestamp')
                        )
                    else:
                        self.on_group_message_callback(
                            payload.get('group_id'),
                            payload.get('sender_uid'),
                            plaintext,
                            payload.get('message_id'),
                            payload.get('timestamp')
                        )
                except crypto.CryptoError as e:
                    logger.error(f"Decryption failed for group message from {self.contact.username}: {e}")
        
        elif msg_type == MessageType.PING:
            # Respond to ping with pong
            pong = Protocol.create_pong()
            try:
                await asyncio.wait_for(self.send_queue.put(pong), timeout=1.0)
            except asyncio.TimeoutError:
                logger.warning(f"Send queue full, dropping pong for {self.contact.username}")
        
        elif msg_type == MessageType.PONG:
            # Update last pong time
            self.last_pong = asyncio.get_event_loop().time()

            # Record pong time for latency measurement
            latency = self.metrics.record_pong()
            if latency:
                logger.debug(f"Latency to {self.contact.username}: {latency:.2f}ms")
        
        elif msg_type == MessageType.DISCONNECT:
            # Peer initiated disconnect
            await self.disconnect()
    
    async def disconnect(self):
        """Close connection and cleanup."""
        async with self._lock:
            if self.state == ConnectionState.DISCONNECTED:
                return
            
            logger.info(f"Disconnecting from {self.contact.username}")
            self._set_state(ConnectionState.DISCONNECTED)
            
            # Cancel tasks
            if self.receive_task and not self.receive_task.done():
                self.receive_task.cancel()
            if self.send_task and not self.send_task.done():
                self.send_task.cancel()
            if self.keepalive_task and not self.keepalive_task.done():
                self.keepalive_task.cancel()
            
            # Close writer
            if self.writer:
                try:
                    self.writer.close()
                    await self.writer.wait_closed()
                except Exception as e:
                    logger.debug(f"Error closing writer for {self.contact.username}: {e}")
                self.writer = None
            
            self.reader = None
            self.session_keys = None
            self.buffer = b''
    
    def _set_state(self, state: ConnectionState):
        """Update connection state and notify callback."""
        self.state = state
        if self.on_state_change_callback:
            # Call callback (may be sync or async)
            if asyncio.iscoroutinefunction(self.on_state_change_callback):
                asyncio.create_task(self.on_state_change_callback(self.contact.uid, state))
            else:
                self.on_state_change_callback(self.contact.uid, state)


class P2PServer:
    """Listens for incoming P2P connections using asyncio."""
    
    def __init__(self, port: int, identity: crypto.IdentityKeyPair, 
                 my_uid: str, my_username: str):
        self.port = port
        self.identity = identity
        self.my_uid = my_uid
        self.my_username = my_username
        
        self.server: Optional[asyncio.Server] = None
        self.running = False
        
        # Callbacks
        self.on_connection_callback: Optional[Callable] = None
    
    async def start(self) -> bool:
        """Start listening for connections."""
        try:
            self.server = await asyncio.start_server(
                self._handle_client,
                '0.0.0.0',
                self.port
            )
            self.running = True
            logger.info(f"P2P server listening on port {self.port}")
            return True
        except Exception as e:
            logger.error(f"Failed to start P2P server on port {self.port}: {e}")
            return False
    
    async def stop(self):
        """Stop listening for connections."""
        self.running = False
        if self.server:
            self.server.close()
            await self.server.wait_closed()
            logger.info("P2P server stopped")
    
    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle incoming client connection."""
        address = writer.get_extra_info('peername')
        logger.debug(f"Incoming connection from {address}")
        
        try:
            # Receive peer's public key
            key_len_data = await asyncio.wait_for(reader.readexactly(4), timeout=10)
            key_len = struct.unpack('!I', key_len_data)[0]
            if key_len != 32:
                raise ValueError(f"Invalid public key length: {key_len}")
            
            peer_public_key_bytes = await asyncio.wait_for(reader.readexactly(key_len), timeout=10)
            
            # Send our public key
            our_public_key = self.identity.get_public_key_bytes()
            writer.write(struct.pack('!I', len(our_public_key)))
            writer.write(our_public_key)
            await writer.drain()
            
            # Derive session keys
            peer_public_key = crypto.IdentityKeyPair.from_public_bytes(peer_public_key_bytes)
            session_keys = crypto.perform_key_exchange(
                self.identity.private_key,
                peer_public_key
            )
            
            # Generate fingerprint
            fingerprint = crypto.generate_fingerprint(peer_public_key_bytes)
            
            # Receive the client's handshake message
            header_data = await asyncio.wait_for(reader.readexactly(Protocol.HEADER_SIZE), timeout=15)
            
            # Parse header to get payload length
            version, msg_type_int, payload_length = struct.unpack('!BHI', header_data)
            
            # Receive the full payload
            payload_data = await asyncio.wait_for(reader.readexactly(payload_length), timeout=15)
            
            # Combine header and payload for unpacking
            full_message = header_data + payload_data
            
            # Verify it's a handshake
            msg_type, handshake_payload, _ = Protocol.unpack_message(full_message)
            if msg_type != MessageType.HANDSHAKE:
                raise ValueError("Expected HANDSHAKE message")
            
            logger.debug(f"Received handshake from {handshake_payload.get('username')} (fingerprint: {fingerprint[:16]}...)")
            
            # Notify callback with established connection and handshake info
            if self.on_connection_callback:
                if asyncio.iscoroutinefunction(self.on_connection_callback):
                    await self.on_connection_callback(
                        reader,
                        writer,
                        session_keys,
                        fingerprint,
                        address,
                        handshake_payload
                    )
                else:
                    self.on_connection_callback(
                        reader,
                        writer,
                        session_keys,
                        fingerprint,
                        address,
                        handshake_payload
                    )
                
        except asyncio.TimeoutError:
            logger.warning(f"Timeout handling connection from {address}")
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass
        except Exception as e:
            logger.error(f"Error handling connection from {address}: {e}")
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass


class NetworkManager:
    """Manages all P2P connections and group chat routing with automatic reconnection using asyncio."""
    
    # Configuration constants
    RECONNECT_INTERVAL = 60  # Reconnection attempt interval in seconds
    MANAGER_LOOP_INTERVAL = 10  # Connection manager check interval in seconds
    
    def __init__(self, identity: crypto.IdentityKeyPair, my_uid: str, 
                 my_username: str, listen_port: int, contact_manager,
                 data_dir: Optional[Path] = None):
        self.identity = identity
        self.my_uid = my_uid
        self.my_username = my_username
        self.listen_port = listen_port
        self.contact_manager = contact_manager
        self.data_dir = Path(data_dir) if data_dir else Path.home() / '.jarvis'
        
        self.connections: Dict[str, P2PConnection] = {}  # uid -> connection
        self.server = P2PServer(listen_port, identity, my_uid, my_username)
        
        # Group membership tracking
        self.group_members: Dict[str, Set[str]] = {}  # group_id -> set of member UIDs
        
        # Callbacks
        self.on_message_callback: Optional[Callable] = None
        self.on_group_message_callback: Optional[Callable] = None
        self.on_connection_state_callback: Optional[Callable] = None
        
        # Background connection management
        self.auto_reconnect_enabled = True
        self.connection_manager_task: Optional[asyncio.Task] = None
        self.running = False
        
        # New managers
        self.nat_traversal: Optional[NATTraversal] = None
        self.discovery: Optional[DiscoveryService] = None
        self.security: Optional[SecurityManager] = None
        self.message_queue = None
        
        # Public address info (from NAT traversal)
        self.public_ip: Optional[str] = None
        self.public_port: Optional[int] = None
        
        self._lock = asyncio.Lock()
    
    async def start_server(self) -> bool:
        """Start listening for incoming connections and background connection manager."""
        try:
            # Initialize NAT traversal
            logger.info("Initializing NAT traversal...")
            self.nat_traversal = NATTraversal()
            
            # Detect NAT type
            nat_type = self.nat_traversal.detect_nat_type(self.listen_port)
            logger.info(f"NAT type detected: {nat_type.value}")
            
            # Try UPnP port mapping
            upnp_result = self.nat_traversal.setup_upnp_mapping(
                self.listen_port,
                protocol='TCP',
                description='Jarvis P2P Messenger'
            )
            
            if upnp_result:
                self.public_ip, self.public_port = upnp_result
                logger.info(f"UPnP port mapping successful: {self.public_ip}:{self.public_port}")
            else:
                logger.warning("UPnP port mapping failed, trying STUN...")
                # Try STUN for public address discovery
                stun_result = self.nat_traversal.get_public_address(self.listen_port)
                if stun_result:
                    self.public_ip, self.public_port = stun_result
                    logger.info(f"STUN discovery successful: {self.public_ip}:{self.public_port}")
                else:
                    logger.warning("NAT traversal unsuccessful, connections limited to LAN")
            
            # Initialize security manager
            logger.info("Initializing security manager...")
            self.security = SecurityManager()
            
            # Initialize message queue
            logger.info("Initializing message queue...")
            self.message_queue = MessageQueue(self.data_dir / 'message_queue.db')
            
            # Initialize discovery service
            logger.info("Initializing peer discovery...")
            public_key_b64 = self.identity.get_public_key_base64()
            fingerprint = crypto.generate_fingerprint(self.identity.get_public_key_bytes())
            
            self.discovery = DiscoveryService(
                self.my_uid,
                self.my_username,
                public_key_b64,
                fingerprint
            )
            self.discovery.on_peer_discovered = self._handle_peer_discovered
            self.discovery.on_peer_lost = self._handle_peer_lost
            
            # Start discovery service
            discovery_started = await self.discovery.start(
                self.public_port or self.listen_port
            )
            if discovery_started:
                logger.info("Peer discovery service started")
            else:
                logger.warning("Peer discovery service failed to start")
            
            # Start P2P server
            self.server.on_connection_callback = self._handle_incoming_connection
            success = await self.server.start()
            
            if success:
                # Start background connection manager
                self.running = True
                self.connection_manager_task = asyncio.create_task(self._connection_manager_loop())
                logger.info("Network manager started successfully")
            
            return success
        
        except Exception as e:
            logger.error(f"Failed to start network manager: {e}", exc_info=True)
            return False
    
    async def stop_server(self):
        """Stop listening for connections and background tasks."""
        logger.info("Stopping network manager...")
        self.running = False
        
        # Stop discovery service
        if self.discovery:
            try:
                await self.discovery.stop()
                logger.info("Discovery service stopped")
            except Exception as e:
                logger.warning(f"Error stopping discovery: {e}")
        
        # Cleanup NAT traversal
        if self.nat_traversal:
            try:
                self.nat_traversal.cleanup_mappings()
                logger.info("NAT traversal cleaned up")
            except Exception as e:
                logger.warning(f"Error cleaning up NAT traversal: {e}")
        
        # Cleanup message queue
        if self.message_queue:
            try:
                await self.message_queue.cleanup_expired()
                logger.info("Message queue cleaned up")
            except Exception as e:
                logger.warning(f"Error cleaning up message queue: {e}")
        
        # Stop P2P server
        await self.server.stop()
        
        # Stop connection manager
        if self.connection_manager_task and not self.connection_manager_task.done():
            self.connection_manager_task.cancel()
            try:
                await self.connection_manager_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Network manager stopped")
    
    async def _connection_manager_loop(self):
        """
        Background task that manages connections.
        - Monitors connection health
        - Attempts automatic reconnection to offline contacts
        - Handles stale connections
        """
        logger.debug("Connection manager loop started")
        last_reconnect_attempt = asyncio.get_event_loop().time()
        
        try:
            while self.running:
                await asyncio.sleep(self.MANAGER_LOOP_INTERVAL)
                
                if not self.auto_reconnect_enabled:
                    continue
                
                # Check if it's time to attempt reconnections
                if asyncio.get_event_loop().time() - last_reconnect_attempt < self.RECONNECT_INTERVAL:
                    continue
                
                last_reconnect_attempt = asyncio.get_event_loop().time()
                
                # Get all contacts
                contacts = self.contact_manager.get_all_contacts()
                
                for contact in contacts:
                    # Skip if already connected
                    if self.is_connected(contact.uid):
                        continue
                    
                    # Attempt to connect in background
                    # Silently fail - connection issues are expected and will retry later
                    try:
                        await self.connect_to_peer(contact)
                    except (ConnectionError, OSError, asyncio.TimeoutError):
                        pass  # Expected network errors during reconnection attempts
                    except Exception:
                        pass  # Catch-all for any unexpected errors
                
                # Clean up disconnected connections
                async with self._lock:
                    disconnected = [
                        uid for uid, conn in self.connections.items()
                        if conn.state == ConnectionState.DISCONNECTED or conn.state == ConnectionState.ERROR
                    ]
                    
                    for uid in disconnected:
                        del self.connections[uid]
        except asyncio.CancelledError:
            logger.debug("Connection manager loop cancelled")
        finally:
            logger.debug("Connection manager loop ended")
    
    async def connect_to_peer(self, contact: Contact) -> bool:
        """Establish connection to a peer."""
        async with self._lock:
            if contact.uid in self.connections:
                return True  # Already connected
            
            connection = P2PConnection(contact, self.identity, self.my_uid, self.my_username)
            connection.on_message_callback = self._handle_message
            connection.on_group_message_callback = self._handle_group_message
            connection.on_state_change_callback = self._handle_state_change
            
            if await connection.connect():
                self.connections[contact.uid] = connection
                return True
            return False
    
    async def connect_all_contacts(self) -> Dict[str, bool]:
        """
        Establish connections to all contacts on login.
        
        Returns dictionary mapping contact UIDs to connection success status.
        """
        results = {}
        contacts = self.contact_manager.get_all_contacts()
        
        # Create connection tasks for all contacts
        tasks = []
        for contact in contacts:
            task = asyncio.create_task(self._connect_with_result(contact, results))
            tasks.append(task)
        
        # Wait for all connections to complete
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        
        return results
    
    async def _connect_with_result(self, contact: Contact, results: Dict):
        """Helper to connect and store result."""
        try:
            success = await self.connect_to_peer(contact)
            results[contact.uid] = success
        except Exception:
            results[contact.uid] = False
    
    async def disconnect_from_peer(self, uid: str):
        """Disconnect from a peer."""
        async with self._lock:
            if uid in self.connections:
                await self.connections[uid].disconnect()
                del self.connections[uid]
    
    async def send_message(self, uid: str, message: str, message_id: str, timestamp: str) -> bool:
        """Send direct message to a peer, queue if offline."""
        connection = self.connections.get(uid)
        
        if connection and connection.state == ConnectionState.AUTHENTICATED:
            # Peer is online, send directly
            success = await connection.send_message(message, message_id, timestamp)
            
            if success:
                # Try to deliver any queued messages for this peer
                if self.message_queue:
                    asyncio.create_task(self._deliver_queued_messages(uid))
            
            return success
        else:
            # Peer is offline, queue message
            if self.message_queue:
                logger.info(f"Peer {uid[:8]} is offline, queueing message {message_id[:8]}")
                await self.message_queue.enqueue(
                    recipient_uid=uid,
                    sender_uid=self.my_uid,
                    message_type='text',
                    message_data={'content': message, 'message_id': message_id, 'timestamp': timestamp}
                )
                return True  # Queued successfully
            else:
                logger.warning(f"Message queue not initialized, cannot queue message for {uid[:8]}")
                return False
    
    async def send_group_message(self, group_id: str, message: str, 
                                  message_id: str, timestamp: str) -> int:
        """
        Send message to all members of a group.
        
        Returns number of successful sends.
        """
        if group_id not in self.group_members:
            return 0
        
        success_count = 0
        tasks = []
        
        for member_uid in self.group_members[group_id]:
            if member_uid == self.my_uid:
                continue  # Don't send to ourselves
            
            connection = self.connections.get(member_uid)
            if connection and connection.state == ConnectionState.AUTHENTICATED:
                task = connection.send_group_message(group_id, message_id, message, timestamp)
                tasks.append(task)
        
        # Send to all members concurrently
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            success_count = sum(1 for r in results if r is True)
        
        return success_count
    
    def add_group_member(self, group_id: str, uid: str):
        """Add a member to a group."""
        if group_id not in self.group_members:
            self.group_members[group_id] = set()
        self.group_members[group_id].add(uid)
    
    def remove_group_member(self, group_id: str, uid: str):
        """Remove a member from a group."""
        if group_id in self.group_members:
            self.group_members[group_id].discard(uid)
            if not self.group_members[group_id]:
                del self.group_members[group_id]
    
    def is_connected(self, uid: str) -> bool:
        """Check if connected to a peer."""
        connection = self.connections.get(uid)
        return connection is not None and connection.state == ConnectionState.AUTHENTICATED
    
    def get_connection_state(self, uid: str) -> ConnectionState:
        """Get connection state for a peer."""
        connection = self.connections.get(uid)
        return connection.state if connection else ConnectionState.DISCONNECTED
    
    def get_connection_status(self, uid: str) -> str:
        """
        Get connection status for a single contact.
        
        Returns:
            ConnectionStatus.GREEN: Contact online and connected
            ConnectionStatus.RED: Contact offline or not connected (but server running)
            ConnectionStatus.GREY: Our server is offline
        """
        if not self.running:
            return ConnectionStatus.GREY
        
        if self.is_connected(uid):
            return ConnectionStatus.GREEN
        else:
            return ConnectionStatus.RED
    
    def get_group_connection_status(self, group_id: str) -> str:
        """
        Get connection status for a group.
        
        Returns:
            ConnectionStatus.GREEN: All members online and connected
            ConnectionStatus.AMBER: Some members online, can send/receive
            ConnectionStatus.RED: No members connected (but server running)
            ConnectionStatus.GREY: Our server is offline
        """
        if not self.running:
            return ConnectionStatus.GREY
        
        if group_id not in self.group_members:
            return ConnectionStatus.RED
        
        members = self.group_members[group_id]
        if not members:
            return ConnectionStatus.RED
        
        # Exclude ourselves from the count
        other_members = [uid for uid in members if uid != self.my_uid]
        if not other_members:
            return ConnectionStatus.GREEN  # Solo group
        
        connected_count = sum(1 for uid in other_members if self.is_connected(uid))
        
        if connected_count == len(other_members):
            return ConnectionStatus.GREEN  # All members connected
        elif connected_count > 0:
            return ConnectionStatus.AMBER  # Some members connected
        else:
            return ConnectionStatus.RED  # No members connected
    
    def _handle_message(self, sender_uid: str, content: str, message_id: str, timestamp: str):
        """Handle received direct message."""
        if self.on_message_callback:
            if asyncio.iscoroutinefunction(self.on_message_callback):
                asyncio.create_task(self.on_message_callback(sender_uid, content, message_id, timestamp))
            else:
                self.on_message_callback(sender_uid, content, message_id, timestamp)
    
    def _handle_group_message(self, group_id: str, sender_uid: str, 
                              content: str, message_id: str, timestamp: str):
        """Handle received group message."""
        if self.on_group_message_callback:
            if asyncio.iscoroutinefunction(self.on_group_message_callback):
                asyncio.create_task(self.on_group_message_callback(group_id, sender_uid, content, message_id, timestamp))
            else:
                self.on_group_message_callback(group_id, sender_uid, content, message_id, timestamp)
    
    def _handle_state_change(self, uid: str, state: ConnectionState):
        """Handle connection state change."""
        if self.on_connection_state_callback:
            if asyncio.iscoroutinefunction(self.on_connection_state_callback):
                asyncio.create_task(self.on_connection_state_callback(uid, state))
            else:
                self.on_connection_state_callback(uid, state)
    
    async def _handle_incoming_connection(self, reader: asyncio.StreamReader, 
                                           writer: asyncio.StreamWriter,
                                           session_keys: Tuple, fingerprint: str, 
                                           address: Tuple[str, int], handshake_payload: Dict):
        """Handle incoming connection from a peer."""
        ip_address = address[0]
        
        # Security check: verify IP is allowed
        if self.security:
            allowed, reason = await self.security.check_ip_allowed(ip_address)
            if not allowed:
                logger.warning(f"Connection rejected from {ip_address}: {reason}")
                writer.close()
                await writer.wait_closed()
                return
            
            # Record connection attempt
            await self.security.record_connection_attempt(ip_address, success=True)
        
        async with self._lock:
            # Check if we already have a connection with this fingerprint
            for conn in self.connections.values():
                if conn.contact.fingerprint == fingerprint:
                    # Already connected, close the new connection
                    writer.close()
                    await writer.wait_closed()
                    return

            # Find the contact by fingerprint
            contact = self.contact_manager.get_contact_by_fingerprint(fingerprint)
            if not contact:
                # Unknown contact, close the connection
                writer.close()
                await writer.wait_closed()
                logger.warning(f"Rejected connection from unknown fingerprint: {fingerprint[:16]}...")
                
                # Record failed connection attempt
                if self.security:
                    await self.security.record_connection_attempt(ip_address, success=False)
                
                return

            # Create a new connection object
            connection = P2PConnection(contact, self.identity, self.my_uid, self.my_username)
            connection.reader = reader
            connection.writer = writer
            connection.session_keys = session_keys
            connection.on_message_callback = self._handle_message
            connection.on_group_message_callback = self._handle_group_message
            connection.on_state_change_callback = self._handle_state_change
            
            # Set state to AUTHENTICATED before starting tasks
            connection._set_state(ConnectionState.AUTHENTICATED)

            # Send handshake response
            handshake_response = protocol.Protocol.create_handshake_response(
                self.my_uid,
                self.my_username,
                crypto.generate_fingerprint(self.identity.get_public_key_bytes()),
                accepted=True
            )
            writer.write(handshake_response)
            await writer.drain()
            
            logger.info(f"Accepted incoming connection from {contact.username}")

            # Start tasks
            connection.receive_task = asyncio.create_task(connection._receive_loop())
            connection.send_task = asyncio.create_task(connection._send_loop())
            connection.keepalive_task = asyncio.create_task(connection._keepalive_loop())

            # Add to connections
            self.connections[contact.uid] = connection
    
    async def _handle_peer_discovered(self, peer):
        """Handle newly discovered peer via mDNS."""
        logger.info(f"Peer discovered: {peer.username} ({peer.uid[:8]})")
        
        # Check if this is a known contact
        contact = self.contact_manager.get_contact_by_fingerprint(peer.fingerprint)
        
        if contact:
            # Known contact, update address if needed
            if peer.addresses:
                host, port = peer.addresses[0]
                if contact.host != host or contact.port != port:
                    logger.info(f"Updating address for {peer.username}: {host}:{port}")
                    contact.host = host
                    contact.port = port
                    self.contact_manager.update_contact(contact)
                
                # Try to connect if not already connected
                if contact.uid not in self.connections:
                    logger.info(f"Auto-connecting to discovered peer: {peer.username}")
                    asyncio.create_task(self.connect(contact.uid))
        else:
            logger.info(f"Discovered unknown peer: {peer.username} (fingerprint: {peer.fingerprint[:16]}...)")
            # Could notify UI to allow adding as contact
    
    async def _handle_peer_lost(self, peer):
        """Handle peer that left the network."""
        logger.info(f"Peer lost: {peer.username} ({peer.uid[:8]})")
    
    async def _deliver_queued_messages(self, uid: str):
        """Deliver queued messages to a newly connected peer."""
        if not self.message_queue:
            return
        
        connection = self.connections.get(uid)
        if not connection or connection.state != ConnectionState.AUTHENTICATED:
            return
        
        logger.info(f"Attempting to deliver queued messages to {uid[:8]}")
        
        # Get all queued messages for this recipient
        queued = await self.message_queue.get_queued_for_recipient(uid)
        
        for msg in queued:
            try:
                # Try to send the message
                message_data = msg['message_data']
                success = await connection.send_message(
                    message_data['content'],
                    message_data['message_id'],
                    message_data['timestamp']
                )
                
                if success:
                    # Mark as delivered
                    await self.message_queue.mark_delivered(msg['queue_id'])
                    logger.info(f"Delivered queued message {msg['queue_id']} to {uid[:8]}")
                else:
                    # Mark as failed, will retry later
                    await self.message_queue.mark_failed(msg['queue_id'])
                    logger.warning(f"Failed to deliver queued message {msg['queue_id']} to {uid[:8]}")
                    
            except Exception as e:
                logger.error(f"Error delivering queued message to {uid[:8]}: {e}")
                await self.message_queue.mark_failed(msg['queue_id'])
    
    async def disconnect_all(self):
        """Disconnect from all peers."""
        async with self._lock:
            tasks = [conn.disconnect() for conn in list(self.connections.values())]
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            self.connections.clear()
