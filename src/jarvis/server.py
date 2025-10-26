"""
Jarvis - Background server daemon for persistent connections.

Created by orpheus497

This module implements a background server that maintains P2P connections
and provides an IPC interface for client UI processes to interact with.
"""

import os
import sys
import json
import socket
import threading
import time
import signal
from pathlib import Path
from typing import Optional, Dict, Any, Callable
from datetime import datetime

from . import crypto
from .identity import IdentityManager
from .contact import ContactManager
from .message import MessageStore
from .group import GroupManager
from .network import NetworkManager
from .notification import get_notification_manager


class ServerCommand:
    """Command types for client-server IPC."""
    # Authentication
    LOGIN = "login"
    LOGOUT = "logout"
    
    # Messaging
    SEND_MESSAGE = "send_message"
    SEND_GROUP_MESSAGE = "send_group_message"
    GET_MESSAGES = "get_messages"
    GET_GROUP_MESSAGES = "get_group_messages"
    
    # Contacts
    ADD_CONTACT = "add_contact"
    REMOVE_CONTACT = "remove_contact"
    GET_CONTACTS = "get_contacts"
    GET_CONTACT = "get_contact"
    
    # Groups
    CREATE_GROUP = "create_group"
    DELETE_GROUP = "delete_group"
    GET_GROUPS = "get_groups"
    GET_GROUP = "get_group"
    
    # Identity
    GET_IDENTITY = "get_identity"
    DELETE_ACCOUNT = "delete_account"
    EXPORT_ACCOUNT = "export_account"
    
    # Connection status
    GET_CONNECTION_STATUS = "get_connection_status"
    CONNECT_TO_PEER = "connect_to_peer"
    
    # Server control
    SHUTDOWN = "shutdown"
    PING = "ping"


class JarvisServer:
    """Background server that maintains P2P connections."""
    
    def __init__(self, data_dir: str, ipc_port: int = 5999):
        """
        Initialize server.
        
        Args:
            data_dir: Directory for storing data
            ipc_port: Port for IPC communication with clients
        """
        self.data_dir = Path(data_dir)
        self.ipc_port = ipc_port
        self.running = False
        
        # Managers (initialized after login)
        self.identity_manager: Optional[IdentityManager] = None
        self.contact_manager: Optional[ContactManager] = None
        self.message_store: Optional[MessageStore] = None
        self.group_manager: Optional[GroupManager] = None
        self.network_manager: Optional[NetworkManager] = None
        self.notification_manager = None
        
        # Current identity
        self.identity = None
        self.password = None
        
        # IPC socket
        self.ipc_socket: Optional[socket.socket] = None
        self.ipc_thread: Optional[threading.Thread] = None
        
        # Client connections
        self.clients: Dict[int, socket.socket] = {}
        self.client_lock = threading.Lock()
        self.next_client_id = 1
        
        # PID file
        self.pid_file = self.data_dir / 'server.pid'
        
        # Event handlers for broadcasts
        self.message_callbacks = []
        
    def start(self) -> bool:
        """Start the server."""
        try:
            # Check if server is already running
            if self._is_server_running():
                print(f"Server already running (PID file exists: {self.pid_file})")
                return False
            
            # Create PID file
            self._write_pid_file()
            
            # Setup signal handlers
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            
            # Start IPC server
            self.ipc_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.ipc_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.ipc_socket.bind(('127.0.0.1', self.ipc_port))
            self.ipc_socket.listen(5)
            
            self.running = True
            
            # Start IPC listener thread
            self.ipc_thread = threading.Thread(target=self._ipc_listener, daemon=True)
            self.ipc_thread.start()
            
            print(f"Jarvis server started on port {self.ipc_port}")
            print(f"PID: {os.getpid()}")
            print(f"Data directory: {self.data_dir}")
            
            return True
            
        except Exception as e:
            print(f"Failed to start server: {e}")
            self._cleanup()
            return False
    
    def stop(self):
        """Stop the server."""
        print("Stopping server...")
        self.running = False
        
        # Disconnect all clients
        with self.client_lock:
            for client_socket in self.clients.values():
                try:
                    client_socket.close()
                except:
                    pass
            self.clients.clear()
        
        # Stop network manager
        if self.network_manager:
            self.network_manager.disconnect_all()
            self.network_manager.stop_server()
        
        # Close IPC socket
        if self.ipc_socket:
            try:
                self.ipc_socket.close()
            except:
                pass
        
        # Cleanup
        self._cleanup()
        
        print("Server stopped")
    
    def run(self):
        """Run server main loop."""
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()
    
    def _ipc_listener(self):
        """Listen for IPC client connections."""
        self.ipc_socket.settimeout(1.0)
        
        while self.running:
            try:
                client_socket, address = self.ipc_socket.accept()
                
                # Assign client ID
                with self.client_lock:
                    client_id = self.next_client_id
                    self.next_client_id += 1
                    self.clients[client_id] = client_socket
                
                # Handle client in separate thread
                threading.Thread(
                    target=self._handle_client,
                    args=(client_id, client_socket),
                    daemon=True
                ).start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"Error accepting client: {e}")
    
    def _handle_client(self, client_id: int, client_socket: socket.socket):
        """Handle client connection."""
        client_socket.settimeout(60.0)
        buffer = b''
        
        try:
            while self.running:
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    
                    buffer += data
                    
                    # Process complete messages (newline-delimited JSON)
                    while b'\n' in buffer:
                        line, buffer = buffer.split(b'\n', 1)
                        if line:
                            try:
                                request = json.loads(line.decode('utf-8'))
                                response = self._process_command(request)
                                
                                # Send response
                                response_data = json.dumps(response) + '\n'
                                client_socket.sendall(response_data.encode('utf-8'))
                            except json.JSONDecodeError:
                                error_response = {
                                    'success': False,
                                    'error': 'Invalid JSON'
                                }
                                client_socket.sendall(
                                    (json.dumps(error_response) + '\n').encode('utf-8')
                                )
                
                except socket.timeout:
                    continue
                except Exception as e:
                    break
        finally:
            # Remove client
            with self.client_lock:
                if client_id in self.clients:
                    del self.clients[client_id]
            
            try:
                client_socket.close()
            except:
                pass
    
    def _process_command(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Process client command and return response."""
        command = request.get('command')
        params = request.get('params', {})
        
        try:
            if command == ServerCommand.PING:
                return {'success': True, 'message': 'pong'}
            
            elif command == ServerCommand.LOGIN:
                return self._handle_login(params)
            
            elif command == ServerCommand.LOGOUT:
                return self._handle_logout()
            
            elif command == ServerCommand.SEND_MESSAGE:
                return self._handle_send_message(params)
            
            elif command == ServerCommand.SEND_GROUP_MESSAGE:
                return self._handle_send_group_message(params)
            
            elif command == ServerCommand.GET_MESSAGES:
                return self._handle_get_messages(params)
            
            elif command == ServerCommand.GET_GROUP_MESSAGES:
                return self._handle_get_group_messages(params)
            
            elif command == ServerCommand.ADD_CONTACT:
                return self._handle_add_contact(params)
            
            elif command == ServerCommand.REMOVE_CONTACT:
                return self._handle_remove_contact(params)
            
            elif command == ServerCommand.GET_CONTACTS:
                return self._handle_get_contacts()
            
            elif command == ServerCommand.GET_CONTACT:
                return self._handle_get_contact(params)
            
            elif command == ServerCommand.CREATE_GROUP:
                return self._handle_create_group(params)
            
            elif command == ServerCommand.DELETE_GROUP:
                return self._handle_delete_group(params)
            
            elif command == ServerCommand.GET_GROUPS:
                return self._handle_get_groups()
            
            elif command == ServerCommand.GET_GROUP:
                return self._handle_get_group(params)
            
            elif command == ServerCommand.GET_IDENTITY:
                return self._handle_get_identity()
            
            elif command == ServerCommand.DELETE_ACCOUNT:
                return self._handle_delete_account(params)
            
            elif command == ServerCommand.EXPORT_ACCOUNT:
                return self._handle_export_account(params)
            
            elif command == ServerCommand.GET_CONNECTION_STATUS:
                return self._handle_get_connection_status(params)
            
            elif command == ServerCommand.CONNECT_TO_PEER:
                return self._handle_connect_to_peer(params)
            
            elif command == ServerCommand.SHUTDOWN:
                return self._handle_shutdown()
            
            else:
                return {
                    'success': False,
                    'error': f'Unknown command: {command}'
                }
        
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
    
    def _handle_login(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle login command."""
        password = params.get('password')
        
        if not password:
            return {'success': False, 'error': 'Password required'}
        
        try:
            # Initialize managers
            self.identity_manager = IdentityManager(str(self.data_dir))
            
            # Check if identity exists
            if not self.identity_manager.has_identity():
                return {
                    'success': False,
                    'error': 'No identity found',
                    'needs_creation': True
                }
            
            # Load identity
            self.identity = self.identity_manager.load_identity(password)
            if not self.identity:
                return {'success': False, 'error': 'Invalid password'}
            
            self.password = password
            
            # Initialize other managers
            self.contact_manager = ContactManager(str(self.data_dir))
            self.message_store = MessageStore(str(self.data_dir))
            self.group_manager = GroupManager(str(self.data_dir))
            self.notification_manager = get_notification_manager()
            
            # Initialize network manager
            self.network_manager = NetworkManager(
                self.identity.keypair,
                self.identity.uid,
                self.identity.username,
                self.identity.listen_port,
                self.contact_manager
            )
            
            # Set up callbacks
            self.network_manager.on_message_callback = self._handle_incoming_message
            self.network_manager.on_group_message_callback = self._handle_incoming_group_message
            self.network_manager.on_connection_state_callback = self._handle_connection_state_change
            
            # Start network server
            if not self.network_manager.start_server():
                return {'success': False, 'error': 'Failed to start network server'}
            
            # Connect to all contacts
            self.network_manager.connect_all_contacts()
            
            # Setup group memberships
            for group in self.group_manager.get_all_groups():
                for member in group.members:
                    self.network_manager.add_group_member(group.group_id, member.uid)
            
            return {
                'success': True,
                'identity': {
                    'uid': self.identity.uid,
                    'username': self.identity.username,
                    'fingerprint': self.identity.fingerprint,
                    'listen_port': self.identity.listen_port
                }
            }
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _handle_logout(self) -> Dict[str, Any]:
        """Handle logout command."""
        try:
            if self.network_manager:
                self.network_manager.disconnect_all()
                self.network_manager.stop_server()
            
            self.identity = None
            self.password = None
            self.identity_manager = None
            self.contact_manager = None
            self.message_store = None
            self.group_manager = None
            self.network_manager = None
            
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _handle_send_message(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle send message command."""
        if not self.network_manager:
            return {'success': False, 'error': 'Not logged in'}
        
        uid = params.get('uid')
        message = params.get('message')
        
        if not uid or not message:
            return {'success': False, 'error': 'Missing parameters'}
        
        # Generate message ID and timestamp
        message_id = crypto.generate_uid()
        timestamp = datetime.now().isoformat()
        
        # Send via network
        success = self.network_manager.send_message(uid, message, message_id, timestamp)
        
        if success:
            # Store message
            self.message_store.add_message(
                self.identity.uid, uid, message, timestamp, message_id
            )
        
        return {
            'success': success,
            'message_id': message_id if success else None
        }
    
    def _handle_send_group_message(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle send group message command."""
        if not self.network_manager:
            return {'success': False, 'error': 'Not logged in'}
        
        group_id = params.get('group_id')
        message = params.get('message')
        
        if not group_id or not message:
            return {'success': False, 'error': 'Missing parameters'}
        
        # Generate message ID and timestamp
        message_id = crypto.generate_uid()
        timestamp = datetime.now().isoformat()
        
        # Send via network
        sent_count = self.network_manager.send_group_message(
            group_id, message, message_id, timestamp
        )
        
        # Store message locally
        self.message_store.add_group_message(
            group_id, self.identity.uid, message, timestamp, message_id
        )
        
        return {
            'success': sent_count > 0,
            'sent_count': sent_count,
            'message_id': message_id
        }
    
    def _handle_get_messages(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get messages command."""
        if not self.message_store:
            return {'success': False, 'error': 'Not logged in'}
        
        uid = params.get('uid')
        if not uid:
            return {'success': False, 'error': 'Missing uid'}
        
        messages = self.message_store.get_conversation(uid)
        
        return {
            'success': True,
            'messages': [
                {
                    'message_id': msg.message_id,
                    'sender_uid': msg.sender_uid,
                    'receiver_uid': msg.receiver_uid,
                    'content': msg.content,
                    'timestamp': msg.timestamp
                }
                for msg in messages
            ]
        }
    
    def _handle_get_group_messages(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get group messages command."""
        if not self.message_store:
            return {'success': False, 'error': 'Not logged in'}
        
        group_id = params.get('group_id')
        if not group_id:
            return {'success': False, 'error': 'Missing group_id'}
        
        messages = self.message_store.get_group_conversation(group_id)
        
        return {
            'success': True,
            'messages': [
                {
                    'message_id': msg.message_id,
                    'group_id': msg.group_id,
                    'sender_uid': msg.sender_uid,
                    'content': msg.content,
                    'timestamp': msg.timestamp
                }
                for msg in messages
            ]
        }
    
    def _handle_add_contact(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle add contact command."""
        if not self.contact_manager:
            return {'success': False, 'error': 'Not logged in'}
        
        try:
            from .contact import Contact
            
            contact = Contact(
                uid=params['uid'],
                username=params['username'],
                public_key=params['public_key'],
                fingerprint=params['fingerprint'],
                host=params['host'],
                port=params['port'],
                verified=params.get('verified', False)
            )
            
            self.contact_manager.add_contact(contact)
            
            # Try to connect
            if self.network_manager:
                self.network_manager.connect_to_peer(contact)
            
            return {'success': True}
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _handle_remove_contact(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle remove contact command."""
        if not self.contact_manager:
            return {'success': False, 'error': 'Not logged in'}
        
        uid = params.get('uid')
        if not uid:
            return {'success': False, 'error': 'Missing uid'}
        
        success = self.contact_manager.remove_contact(uid)
        
        if success and self.network_manager:
            self.network_manager.disconnect_from_peer(uid)
        
        return {'success': success}
    
    def _handle_get_contacts(self) -> Dict[str, Any]:
        """Handle get contacts command."""
        if not self.contact_manager:
            return {'success': False, 'error': 'Not logged in'}
        
        contacts = self.contact_manager.get_all_contacts()
        
        return {
            'success': True,
            'contacts': [
                {
                    'uid': c.uid,
                    'username': c.username,
                    'public_key': c.public_key,
                    'fingerprint': c.fingerprint,
                    'host': c.host,
                    'port': c.port,
                    'verified': c.verified
                }
                for c in contacts
            ]
        }
    
    def _handle_get_contact(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get contact command."""
        if not self.contact_manager:
            return {'success': False, 'error': 'Not logged in'}
        
        uid = params.get('uid')
        if not uid:
            return {'success': False, 'error': 'Missing uid'}
        
        contact = self.contact_manager.get_contact(uid)
        if not contact:
            return {'success': False, 'error': 'Contact not found'}
        
        return {
            'success': True,
            'contact': {
                'uid': contact.uid,
                'username': contact.username,
                'public_key': contact.public_key,
                'fingerprint': contact.fingerprint,
                'host': contact.host,
                'port': contact.port,
                'verified': contact.verified
            }
        }
    
    def _handle_create_group(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle create group command."""
        if not self.group_manager:
            return {'success': False, 'error': 'Not logged in'}
        
        try:
            from .group import GroupMember
            
            name = params.get('name')
            member_uids = params.get('member_uids', [])
            description = params.get('description', '')
            
            if not name:
                return {'success': False, 'error': 'Missing name'}
            
            # Create group
            group = self.group_manager.create_group(
                name=name,
                creator_uid=self.identity.uid,
                member_uids=member_uids,
                description=description
            )
            
            # Setup network group
            if self.network_manager:
                for member_uid in member_uids:
                    self.network_manager.add_group_member(group.group_id, member_uid)
                # Add ourselves
                self.network_manager.add_group_member(group.group_id, self.identity.uid)
            
            return {
                'success': True,
                'group_id': group.group_id
            }
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _handle_delete_group(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle delete group command."""
        if not self.group_manager:
            return {'success': False, 'error': 'Not logged in'}
        
        group_id = params.get('group_id')
        if not group_id:
            return {'success': False, 'error': 'Missing group_id'}
        
        success = self.group_manager.delete_group(group_id)
        
        return {'success': success}
    
    def _handle_get_groups(self) -> Dict[str, Any]:
        """Handle get groups command."""
        if not self.group_manager:
            return {'success': False, 'error': 'Not logged in'}
        
        groups = self.group_manager.get_all_groups()
        
        return {
            'success': True,
            'groups': [
                {
                    'group_id': g.group_id,
                    'name': g.name,
                    'creator_uid': g.creator_uid,
                    'created_at': g.created_at,
                    'description': g.description,
                    'members': [
                        {
                            'uid': m.uid,
                            'username': m.username
                        }
                        for m in g.members
                    ]
                }
                for g in groups
            ]
        }
    
    def _handle_get_group(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get group command."""
        if not self.group_manager:
            return {'success': False, 'error': 'Not logged in'}
        
        group_id = params.get('group_id')
        if not group_id:
            return {'success': False, 'error': 'Missing group_id'}
        
        group = self.group_manager.get_group(group_id)
        if not group:
            return {'success': False, 'error': 'Group not found'}
        
        return {
            'success': True,
            'group': {
                'group_id': group.group_id,
                'name': group.name,
                'creator_uid': group.creator_uid,
                'created_at': group.created_at,
                'description': group.description,
                'members': [
                    {
                        'uid': m.uid,
                        'username': m.username
                    }
                    for m in group.members
                ]
            }
        }
    
    def _handle_get_identity(self) -> Dict[str, Any]:
        """Handle get identity command."""
        if not self.identity:
            return {'success': False, 'error': 'Not logged in'}
        
        return {
            'success': True,
            'identity': {
                'uid': self.identity.uid,
                'username': self.identity.username,
                'fingerprint': self.identity.fingerprint,
                'listen_port': self.identity.listen_port
            }
        }
    
    def _handle_delete_account(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle delete account command."""
        if not self.identity_manager:
            return {'success': False, 'error': 'Not logged in'}
        
        password = params.get('password')
        if not password or password != self.password:
            return {'success': False, 'error': 'Invalid password'}
        
        try:
            # Delete all data
            self.identity_manager.delete_identity()
            if self.contact_manager:
                for contact in self.contact_manager.get_all_contacts():
                    self.contact_manager.remove_contact(contact.uid)
            if self.message_store:
                # Message store deletion is handled by identity manager
                pass
            if self.group_manager:
                for group in self.group_manager.get_all_groups():
                    self.group_manager.delete_group(group.group_id)
            
            # Logout
            self._handle_logout()
            
            return {'success': True}
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _handle_export_account(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle export account command."""
        if not self.identity_manager:
            return {'success': False, 'error': 'Not logged in'}
        
        filepath = params.get('filepath')
        if not filepath:
            return {'success': False, 'error': 'Missing filepath'}
        
        try:
            success = self.identity_manager.export_complete_account(
                self.password, filepath
            )
            return {'success': success}
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _handle_get_connection_status(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get connection status command."""
        if not self.network_manager:
            return {'success': False, 'error': 'Not logged in'}
        
        uid = params.get('uid')
        
        if uid:
            # Get status for specific contact
            is_connected = self.network_manager.is_connected(uid)
            return {
                'success': True,
                'connected': is_connected
            }
        else:
            # Get all connection statuses
            contacts = self.contact_manager.get_all_contacts() if self.contact_manager else []
            statuses = {}
            for contact in contacts:
                statuses[contact.uid] = self.network_manager.is_connected(contact.uid)
            
            return {
                'success': True,
                'statuses': statuses
            }
    
    def _handle_connect_to_peer(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle connect to peer command."""
        if not self.network_manager or not self.contact_manager:
            return {'success': False, 'error': 'Not logged in'}
        
        uid = params.get('uid')
        if not uid:
            return {'success': False, 'error': 'Missing uid'}
        
        contact = self.contact_manager.get_contact(uid)
        if not contact:
            return {'success': False, 'error': 'Contact not found'}
        
        success = self.network_manager.connect_to_peer(contact)
        
        return {'success': success}
    
    def _handle_shutdown(self) -> Dict[str, Any]:
        """Handle shutdown command."""
        # Schedule shutdown
        threading.Thread(target=self._delayed_shutdown, daemon=True).start()
        return {'success': True, 'message': 'Server shutting down'}
    
    def _delayed_shutdown(self):
        """Shutdown after a short delay to allow response to be sent."""
        time.sleep(0.5)
        self.running = False
    
    def _handle_incoming_message(self, sender_uid: str, message: str, 
                                 message_id: str, timestamp: str):
        """Handle incoming message from network."""
        if self.message_store and self.identity:
            self.message_store.add_message(
                sender_uid, self.identity.uid, message, timestamp, message_id
            )
        
        # Send notification
        if self.notification_manager and self.contact_manager:
            contact = self.contact_manager.get_contact(sender_uid)
            username = contact.username if contact else sender_uid[:8]
            self.notification_manager.notify(
                f"Message from {username}",
                message[:100]
            )
        
        # Broadcast to clients (for real-time updates)
        self._broadcast_to_clients({
            'event': 'message_received',
            'sender_uid': sender_uid,
            'message': message,
            'message_id': message_id,
            'timestamp': timestamp
        })
    
    def _handle_incoming_group_message(self, group_id: str, sender_uid: str,
                                       message: str, message_id: str, timestamp: str):
        """Handle incoming group message from network."""
        if self.message_store:
            self.message_store.add_group_message(
                group_id, sender_uid, message, timestamp, message_id
            )
        
        # Send notification
        if self.notification_manager and self.contact_manager and self.group_manager:
            contact = self.contact_manager.get_contact(sender_uid)
            group = self.group_manager.get_group(group_id)
            username = contact.username if contact else sender_uid[:8]
            group_name = group.name if group else group_id[:8]
            self.notification_manager.notify(
                f"{username} in {group_name}",
                message[:100]
            )
        
        # Broadcast to clients
        self._broadcast_to_clients({
            'event': 'group_message_received',
            'group_id': group_id,
            'sender_uid': sender_uid,
            'message': message,
            'message_id': message_id,
            'timestamp': timestamp
        })
    
    def _handle_connection_state_change(self, uid: str, state: int):
        """Handle connection state change."""
        # Broadcast to clients
        self._broadcast_to_clients({
            'event': 'connection_state_changed',
            'uid': uid,
            'state': state
        })
    
    def _broadcast_to_clients(self, event: Dict[str, Any]):
        """Broadcast event to all connected clients."""
        message = json.dumps({'type': 'event', 'data': event}) + '\n'
        message_bytes = message.encode('utf-8')
        
        with self.client_lock:
            for client_socket in list(self.clients.values()):
                try:
                    client_socket.sendall(message_bytes)
                except:
                    pass
    
    def _is_server_running(self) -> bool:
        """Check if server is already running."""
        if not self.pid_file.exists():
            return False
        
        try:
            with open(self.pid_file, 'r') as f:
                pid = int(f.read().strip())
            
            # Check if process exists
            try:
                os.kill(pid, 0)
                return True
            except OSError:
                # Process doesn't exist, remove stale PID file
                self.pid_file.unlink()
                return False
        
        except:
            return False
    
    def _write_pid_file(self):
        """Write PID file."""
        self.pid_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.pid_file, 'w') as f:
            f.write(str(os.getpid()))
    
    def _cleanup(self):
        """Cleanup server resources."""
        try:
            if self.pid_file.exists():
                self.pid_file.unlink()
        except:
            pass
    
    def _signal_handler(self, signum, frame):
        """Handle termination signals."""
        print(f"\nReceived signal {signum}, shutting down...")
        self.running = False


def main():
    """Main entry point for server daemon."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Jarvis Server - Background daemon for P2P connections'
    )
    
    parser.add_argument(
        '--data-dir',
        type=str,
        default=None,
        help='Data directory for storing identity, contacts, and messages'
    )
    
    parser.add_argument(
        '--ipc-port',
        type=int,
        default=5999,
        help='Port for IPC communication with clients (default: 5999)'
    )
    
    args = parser.parse_args()
    
    # Determine data directory
    if args.data_dir:
        data_dir = Path(args.data_dir).expanduser().resolve()
    else:
        # Use platform-specific default data directory
        if sys.platform == 'win32':
            data_dir = Path(os.getenv('APPDATA', '~')) / 'Jarvis'
        elif sys.platform == 'darwin':
            data_dir = Path.home() / 'Library' / 'Application Support' / 'Jarvis'
        else:
            data_dir = Path.home() / '.jarvis'
        
        data_dir = data_dir.expanduser().resolve()
    
    # Create data directory if it doesn't exist
    data_dir.mkdir(parents=True, exist_ok=True)
    
    # Create and start server
    server = JarvisServer(str(data_dir), args.ipc_port)
    
    if not server.start():
        sys.exit(1)
    
    # Run server
    server.run()


if __name__ == '__main__':
    main()
