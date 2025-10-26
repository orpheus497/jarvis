"""
Jarvis - Peer-to-peer networking layer with group chat support.

Created by orpheus497

This module implements:
- Direct P2P TCP connections
- Multi-layer encrypted data transmission
- Group chat message routing
- Automatic reconnection handling
- Connection pooling and management
- NAT traversal support (UPnP/NAT-PMP)
"""

import socket
import threading
import time
import queue
import struct
from typing import Optional, Callable, Dict, Tuple, List, Set
from datetime import datetime, timezone

from . import crypto
from . import protocol
from .contact import Contact
from .protocol import MessageType, Protocol


class ConnectionState:
    """Connection state enumeration."""
    DISCONNECTED = 0
    CONNECTING = 1
    CONNECTED = 2
    AUTHENTICATED = 3
    ERROR = 4


class P2PConnection:
    """Represents a P2P connection with another user."""
    
    def __init__(self, contact: Contact, identity: crypto.IdentityKeyPair, 
                 my_uid: str, my_username: str):
        self.contact = contact
        self.identity = identity
        self.my_uid = my_uid
        self.my_username = my_username
        
        self.session_keys: Optional[Tuple[bytes, bytes, bytes, bytes, bytes]] = None
        self.socket: Optional[socket.socket] = None
        self.state = ConnectionState.DISCONNECTED
        
        self.receive_thread: Optional[threading.Thread] = None
        self.send_queue = queue.Queue()
        self.send_thread: Optional[threading.Thread] = None
        
        self.buffer = b''
        self.last_ping = time.time()
        self.last_pong = time.time()
        
        # Callbacks
        self.on_message_callback: Optional[Callable] = None
        self.on_group_message_callback: Optional[Callable] = None
        self.on_state_change_callback: Optional[Callable] = None
        
        self.lock = threading.Lock()
    
    def connect(self) -> bool:
        """
        Establish connection to peer.
        
        Connection flow:
        1. TCP socket connection
        2. Exchange public keys
        3. Verify fingerprint
        4. Derive session keys
        5. Send handshake
        6. Receive handshake response
        7. Start send/receive threads
        """
        try:
            self._set_state(ConnectionState.CONNECTING)
            
            # Create and connect socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            self.socket.connect((self.contact.host, self.contact.port))
            
            # Send our public key
            our_public_key = self.identity.get_public_key_bytes()
            self.socket.sendall(struct.pack('!I', len(our_public_key)))
            self.socket.sendall(our_public_key)
            
            # Receive peer's public key
            key_len = struct.unpack('!I', self._recv_exact(4))[0]
            if key_len != 32:
                raise Exception(f"Invalid public key length: {key_len}")
            
            peer_public_key_bytes = self._recv_exact(key_len)
            peer_public_key = crypto.IdentityKeyPair.from_public_bytes(peer_public_key_bytes)
            
            # Verify fingerprint
            received_fingerprint = crypto.generate_fingerprint(peer_public_key_bytes)
            if received_fingerprint != self.contact.fingerprint:
                raise Exception("Fingerprint mismatch - possible MITM attack!")
            
            # Derive session keys using X25519 key exchange
            self.session_keys = crypto.perform_key_exchange(
                self.identity.private_key,
                peer_public_key
            )
            
            self._set_state(ConnectionState.CONNECTED)
            
            # Send handshake
            handshake = Protocol.create_handshake(
                self.my_uid,
                self.my_username,
                crypto.generate_fingerprint(self.identity.get_public_key_bytes())
            )
            self.socket.sendall(handshake)
            
            # Start threads
            self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
            self.receive_thread.start()
            
            self.send_thread = threading.Thread(target=self._send_loop, daemon=True)
            self.send_thread.start()
            
            # Start keepalive thread
            keepalive_thread = threading.Thread(target=self._keepalive_loop, daemon=True)
            keepalive_thread.start()
            
            return True
            
        except Exception as e:
            self._set_state(ConnectionState.ERROR)
            self.disconnect()
            return False
    
    def send_message(self, plaintext: str, message_id: str, timestamp: str) -> bool:
        """
        Send encrypted message to peer.
        
        Message flow:
        1. Encrypt plaintext with five-layer encryption
        2. Create protocol message
        3. Add to send queue
        """
        if self.state != ConnectionState.AUTHENTICATED or not self.session_keys:
            return False
        
        try:
            # Encrypt message with five-layer encryption
            encrypted = crypto.encrypt_message_five_layer(plaintext, self.session_keys)
            
            # Create protocol message
            message = Protocol.create_text_message(message_id, plaintext, timestamp, encrypted)
            
            # Add to send queue
            self.send_queue.put(message)
            return True
        except Exception as e:
            return False
    
    def send_group_message(self, group_id: str, message_id: str, 
                          plaintext: str, timestamp: str) -> bool:
        """Send encrypted group message to peer."""
        if self.state != ConnectionState.AUTHENTICATED or not self.session_keys:
            return False
        
        try:
            encrypted = crypto.encrypt_message_five_layer(plaintext, self.session_keys)
            
            message = Protocol.create_group_message(
                group_id, message_id, self.my_uid,
                plaintext, timestamp, encrypted
            )
            
            self.send_queue.put(message)
            return True
        except Exception as e:
            return False
    
    def _receive_loop(self):
        """Background thread for receiving messages."""
        self.socket.settimeout(1.0)
        
        while self.state in (ConnectionState.CONNECTED, ConnectionState.AUTHENTICATED):
            try:
                # Receive data
                data = self.socket.recv(4096)
                if not data:
                    break
                
                self.buffer += data
                
                # Process all complete messages in buffer
                while len(self.buffer) >= Protocol.HEADER_SIZE:
                    result = Protocol.unpack_message(self.buffer)
                    if not result:
                        break
                    
                    msg_type, payload, consumed = result
                    self.buffer = self.buffer[consumed:]
                    
                    # Handle message
                    self._handle_message(msg_type, payload)
                    
            except socket.timeout:
                continue
            except Exception as e:
                break
        
        self.disconnect()
    
    def _send_loop(self):
        """Background thread for sending messages."""
        while self.state in (ConnectionState.CONNECTED, ConnectionState.AUTHENTICATED):
            try:
                # Get message from queue with timeout
                message = self.send_queue.get(timeout=1.0)
                
                # Send message
                self.socket.sendall(message)
                
            except queue.Empty:
                continue
            except Exception as e:
                break
    
    def _keepalive_loop(self):
        """Background thread for keepalive pings."""
        while self.state in (ConnectionState.CONNECTED, ConnectionState.AUTHENTICATED):
            time.sleep(30)  # Send ping every 30 seconds
            
            if self.state != ConnectionState.AUTHENTICATED:
                continue
            
            # Send ping
            try:
                ping = Protocol.create_ping()
                self.send_queue.put(ping)
                self.last_ping = time.time()
                
                # Check if we've received a pong recently
                if time.time() - self.last_pong > 90:  # No pong in 90 seconds
                    self.disconnect()
                    break
            except:
                break
    
    def _handle_message(self, msg_type: MessageType, payload: Dict):
        """Handle received message based on type."""
        
        if msg_type == MessageType.HANDSHAKE_RESPONSE:
            # Handshake accepted, mark as authenticated
            if payload.get('accepted', False):
                self._set_state(ConnectionState.AUTHENTICATED)
        
        elif msg_type == MessageType.TEXT_MESSAGE:
            # Decrypt and deliver text message
            if self.session_keys and self.on_message_callback:
                try:
                    encrypted_data = payload.get('encrypted', {})
                    plaintext = crypto.decrypt_message_five_layer(encrypted_data, self.session_keys)
                    
                    self.on_message_callback(
                        self.contact.uid,
                        plaintext,
                        payload.get('message_id'),
                        payload.get('timestamp')
                    )
                except crypto.CryptoError:
                    pass
        
        elif msg_type == MessageType.GROUP_MESSAGE:
            # Decrypt and deliver group message
            if self.session_keys and self.on_group_message_callback:
                try:
                    encrypted_data = payload.get('encrypted', {})
                    plaintext = crypto.decrypt_message_five_layer(encrypted_data, self.session_keys)
                    
                    self.on_group_message_callback(
                        payload.get('group_id'),
                        payload.get('sender_uid'),
                        plaintext,
                        payload.get('message_id'),
                        payload.get('timestamp')
                    )
                except crypto.CryptoError:
                    pass
        
        elif msg_type == MessageType.PING:
            # Respond to ping with pong
            pong = Protocol.create_pong()
            self.send_queue.put(pong)
        
        elif msg_type == MessageType.PONG:
            # Update last pong time
            self.last_pong = time.time()
        
        elif msg_type == MessageType.DISCONNECT:
            # Peer initiated disconnect
            self.disconnect()
    
    def disconnect(self):
        """Close connection and cleanup."""
        with self.lock:
            if self.state == ConnectionState.DISCONNECTED:
                return
            
            self._set_state(ConnectionState.DISCONNECTED)
            
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
                self.socket = None
            
            self.session_keys = None
            self.buffer = b''
    
    def _recv_exact(self, n: int) -> bytes:
        """Receive exactly n bytes from socket."""
        data = b''
        while len(data) < n:
            packet = self.socket.recv(n - len(data))
            if not packet:
                raise Exception("Connection closed")
            data += packet
        return data
    
    def _set_state(self, state: ConnectionState):
        """Update connection state and notify callback."""
        self.state = state
        if self.on_state_change_callback:
            self.on_state_change_callback(self.contact.uid, state)


class P2PServer:
    """Listens for incoming P2P connections."""
    
    def __init__(self, port: int, identity: crypto.IdentityKeyPair, 
                 my_uid: str, my_username: str):
        self.port = port
        self.identity = identity
        self.my_uid = my_uid
        self.my_username = my_username
        
        self.server_socket: Optional[socket.socket] = None
        self.running = False
        self.server_thread: Optional[threading.Thread] = None
        
        # Callbacks
        self.on_connection_callback: Optional[Callable] = None
    
    def start(self) -> bool:
        """Start listening for connections."""
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(10)
            self.running = True
            
            self.server_thread = threading.Thread(target=self._accept_loop, daemon=True)
            self.server_thread.start()
            
            return True
        except Exception as e:
            return False
    
    def stop(self):
        """Stop listening for connections."""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            self.server_socket = None
    
    def _accept_loop(self):
        """Accept incoming connections."""
        self.server_socket.settimeout(1.0)
        
        while self.running:
            try:
                client_socket, address = self.server_socket.accept()
                
                # Handle client in separate thread
                threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, address),
                    daemon=True
                ).start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    time.sleep(0.1)
    
    def _handle_client(self, client_socket: socket.socket, address: Tuple[str, int]):
        """Handle incoming client connection."""
        try:
            client_socket.settimeout(10)
            
            # Receive peer's public key
            key_len = struct.unpack('!I', self._recv_exact_from_socket(client_socket, 4))[0]
            if key_len != 32:
                raise Exception(f"Invalid public key length: {key_len}")
            
            peer_public_key_bytes = self._recv_exact_from_socket(client_socket, key_len)
            
            # Send our public key
            our_public_key = self.identity.get_public_key_bytes()
            client_socket.sendall(struct.pack('!I', len(our_public_key)))
            client_socket.sendall(our_public_key)
            
            # Derive session keys
            peer_public_key = crypto.IdentityKeyPair.from_public_bytes(peer_public_key_bytes)
            session_keys = crypto.perform_key_exchange(
                self.identity.private_key,
                peer_public_key
            )
            
            # Generate fingerprint
            fingerprint = crypto.generate_fingerprint(peer_public_key_bytes)
            
            # Notify callback with established connection
            if self.on_connection_callback:
                self.on_connection_callback(
                    client_socket,
                    session_keys,
                    fingerprint,
                    address
                )
                
        except Exception as e:
            try:
                client_socket.close()
            except:
                pass
    
    def _recv_exact_from_socket(self, sock: socket.socket, n: int) -> bytes:
        """Receive exactly n bytes from socket."""
        data = b''
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                raise Exception("Connection closed")
            data += packet
        return data


class NetworkManager:
    """Manages all P2P connections and group chat routing with automatic reconnection."""
    
    def __init__(self, identity: crypto.IdentityKeyPair, my_uid: str, 
                 my_username: str, listen_port: int, contact_manager):
        self.identity = identity
        self.my_uid = my_uid
        self.my_username = my_username
        self.listen_port = listen_port
        self.contact_manager = contact_manager
        
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
        self.connection_manager_thread: Optional[threading.Thread] = None
        self.running = False
        
        self.lock = threading.Lock()
    
    def start_server(self) -> bool:
        """Start listening for incoming connections and background connection manager."""
        self.server.on_connection_callback = self._handle_incoming_connection
        success = self.server.start()
        
        if success:
            # Start background connection manager
            self.running = True
            self.connection_manager_thread = threading.Thread(
                target=self._connection_manager_loop, 
                daemon=True
            )
            self.connection_manager_thread.start()
        
        return success
    
    def stop_server(self):
        """Stop listening for connections and background threads."""
        self.running = False
        self.server.stop()
        
        if self.connection_manager_thread:
            self.connection_manager_thread.join(timeout=2.0)
    
    def _connection_manager_loop(self):
        """
        Background thread that manages connections.
        - Monitors connection health
        - Attempts automatic reconnection to offline contacts
        - Handles stale connections
        """
        reconnect_interval = 60  # Try to reconnect every 60 seconds
        last_reconnect_attempt = time.time()
        
        while self.running:
            time.sleep(10)  # Check every 10 seconds
            
            if not self.auto_reconnect_enabled:
                continue
            
            # Check if it's time to attempt reconnections
            if time.time() - last_reconnect_attempt < reconnect_interval:
                continue
            
            last_reconnect_attempt = time.time()
            
            # Get all contacts
            contacts = self.contact_manager.get_all_contacts()
            
            for contact in contacts:
                # Skip if already connected
                if self.is_connected(contact.uid):
                    continue
                
                # Attempt to connect in background
                try:
                    self.connect_to_peer(contact)
                except Exception:
                    pass  # Silently fail, will try again later
            
            # Clean up disconnected connections
            with self.lock:
                disconnected = [
                    uid for uid, conn in self.connections.items()
                    if conn.state == ConnectionState.DISCONNECTED or conn.state == ConnectionState.ERROR
                ]
                
                for uid in disconnected:
                    del self.connections[uid]
    
    def connect_to_peer(self, contact: Contact) -> bool:
        """Establish connection to a peer."""
        with self.lock:
            if contact.uid in self.connections:
                return True  # Already connected
            
            connection = P2PConnection(contact, self.identity, self.my_uid, self.my_username)
            connection.on_message_callback = self._handle_message
            connection.on_group_message_callback = self._handle_group_message
            connection.on_state_change_callback = self._handle_state_change
            
            if connection.connect():
                self.connections[contact.uid] = connection
                return True
            return False
    
    def disconnect_from_peer(self, uid: str):
        """Disconnect from a peer."""
        with self.lock:
            if uid in self.connections:
                self.connections[uid].disconnect()
                del self.connections[uid]
    
    def send_message(self, uid: str, message: str, message_id: str, timestamp: str) -> bool:
        """Send direct message to a peer."""
        connection = self.connections.get(uid)
        if connection and connection.state == ConnectionState.AUTHENTICATED:
            return connection.send_message(message, message_id, timestamp)
        return False
    
    def send_group_message(self, group_id: str, message: str, 
                          message_id: str, timestamp: str) -> int:
        """
        Send message to all members of a group.
        
        Returns number of successful sends.
        """
        if group_id not in self.group_members:
            return 0
        
        success_count = 0
        for member_uid in self.group_members[group_id]:
            if member_uid == self.my_uid:
                continue  # Don't send to ourselves
            
            connection = self.connections.get(member_uid)
            if connection and connection.state == ConnectionState.AUTHENTICATED:
                if connection.send_group_message(group_id, message_id, message, timestamp):
                    success_count += 1
        
        return success_count
    
    def add_group_member(self, group_id: str, uid: str):
        """Add a member to a group."""
        with self.lock:
            if group_id not in self.group_members:
                self.group_members[group_id] = set()
            self.group_members[group_id].add(uid)
    
    def remove_group_member(self, group_id: str, uid: str):
        """Remove a member from a group."""
        with self.lock:
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
    
    def _handle_message(self, sender_uid: str, content: str, message_id: str, timestamp: str):
        """Handle received direct message."""
        if self.on_message_callback:
            self.on_message_callback(sender_uid, content, message_id, timestamp)
    
    def _handle_group_message(self, group_id: str, sender_uid: str, 
                             content: str, message_id: str, timestamp: str):
        """Handle received group message."""
        if self.on_group_message_callback:
            self.on_group_message_callback(group_id, sender_uid, content, message_id, timestamp)
    
    def _handle_state_change(self, uid: str, state: ConnectionState):
        """Handle connection state change."""
        if self.on_connection_state_callback:
            self.on_connection_state_callback(uid, state)
    
    def _handle_incoming_connection(self, client_socket: socket.socket, 
                                    session_keys: Tuple, fingerprint: str, 
                                    address: Tuple[str, int]):
        """Handle incoming connection from a peer."""
        # 1. Create a P2PConnection from the accepted socket
        # 2. Completing the handshake
        # 3. Adding to connections dict
        with self.lock:
            # Check if we already have a connection with this fingerprint
            for conn in self.connections.values():
                if conn.contact.fingerprint == fingerprint:
                    # Already connected, close the new connection
                    client_socket.close()
                    return

            # Find the contact by fingerprint
            contact = self.contact_manager.get_contact_by_fingerprint(fingerprint)
            if not contact:
                # Unknown contact, close the connection
                client_socket.close()
                return

            # Create a new connection object
            connection = P2PConnection(contact, self.identity, self.my_uid, self.my_username)
            connection.socket = client_socket
            connection.session_keys = session_keys
            connection.on_message_callback = self._handle_message
            connection.on_group_message_callback = self._handle_group_message
            connection.on_state_change_callback = self._handle_state_change

            # Send handshake response
            handshake_response = protocol.Protocol.create_handshake_response(
                self.my_uid,
                self.my_username,
                crypto.generate_fingerprint(self.identity.get_public_key_bytes()),
                accepted=True
            )
            connection.send_queue.put(handshake_response)

            # Start threads
            connection.receive_thread = threading.Thread(target=connection._receive_loop, daemon=True)
            connection.receive_thread.start()

            connection.send_thread = threading.Thread(target=connection._send_loop, daemon=True)
            connection.send_thread.start()

            # Start keepalive thread
            keepalive_thread = threading.Thread(target=connection._keepalive_loop, daemon=True)
            keepalive_thread.start()

            # Add to connections
            self.connections[contact.uid] = connection
            connection._set_state(ConnectionState.AUTHENTICATED)
    
    def disconnect_all(self):
        """Disconnect from all peers."""
        with self.lock:
            for connection in list(self.connections.values()):
                connection.disconnect()
            self.connections.clear()
