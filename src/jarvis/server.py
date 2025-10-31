"""
Jarvis - Background server daemon for persistent connections using asyncio.

Created by orpheus497

This module implements a background server that maintains P2P connections
and provides an IPC interface for client UI processes to interact with.
Converted to unified asyncio architecture per technical blueprint.
"""

import os
import sys
import json
import asyncio
import signal
import logging
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
from .config import Config
from .rate_limiter import RateLimiter
from .backup import BackupManager
from .errors import JarvisError, ErrorCode
from .message_queue import MessageQueue

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


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
    MARK_MESSAGES_READ = "mark_messages_read"
    MARK_GROUP_MESSAGES_READ = "mark_group_messages_read"
    GET_UNREAD_COUNT = "get_unread_count"
    GET_GROUP_UNREAD_COUNT = "get_group_unread_count"
    GET_TOTAL_UNREAD_COUNT = "get_total_unread_count"
    
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
    
    # File transfer
    SEND_FILE = "send_file"
    RECEIVE_FILE = "receive_file"
    GET_FILE_TRANSFERS = "get_file_transfers"
    CANCEL_FILE_TRANSFER = "cancel_file_transfer"

    # Search
    SEARCH_MESSAGES = "search_messages"
    SEARCH_BY_CONTACT = "search_by_contact"
    SEARCH_BY_DATE = "search_by_date"

    # Backup
    CREATE_BACKUP = "create_backup"
    RESTORE_BACKUP = "restore_backup"
    LIST_BACKUPS = "list_backups"
    DELETE_BACKUP = "delete_backup"

    # Voice messages
    SEND_VOICE_MESSAGE = "send_voice_message"
    RECORD_VOICE = "record_voice"
    PLAY_VOICE = "play_voice"

    # Server control
    SHUTDOWN = "shutdown"
    PING = "ping"


class JarvisServer:
    """Background server that maintains P2P connections using asyncio."""
    
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

        # New v2.0 managers
        self.config: Optional[Config] = None
        self.rate_limiter: Optional[RateLimiter] = None
        self.backup_manager: Optional[BackupManager] = None
        self.file_transfers: Dict[str, Any] = {}  # Track active file transfers
        
        # Message queue
        self.message_queue: Optional[MessageQueue] = None
        
        # Current identity
        self.identity = None
        self.password = None
        
        # IPC server
        self.ipc_server: Optional[asyncio.Server] = None
        
        # Client connections
        self.clients: Dict[int, asyncio.StreamWriter] = {}
        self.client_lock = asyncio.Lock()
        self.next_client_id = 1
        
        # PID file
        self.pid_file = self.data_dir / 'server.pid'
        
        # Event handlers for broadcasts
        self.message_callbacks = []
        
    async def start(self) -> bool:
        """Start the server."""
        try:
            # Check if server is already running
            if self._is_server_running():
                logger.error(f"Server already running (PID file exists: {self.pid_file})")
                return False
            
            # Create PID file
            self._write_pid_file()
            
            # Setup signal handlers
            signal.signal(signal.SIGINT, self._signal_handler)
            signal.signal(signal.SIGTERM, self._signal_handler)
            
            # Start IPC server using asyncio
            self.ipc_server = await asyncio.start_server(
                self._handle_client,
                '127.0.0.1',
                self.ipc_port
            )
            
            self.running = True
            
            logger.info(f"Jarvis server started on port {self.ipc_port}")
            logger.info(f"PID: {os.getpid()}")
            logger.info(f"Data directory: {self.data_dir}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to start server: {e}", exc_info=True)
            self._cleanup()
            return False
    
    async def stop(self):
        """Stop the server."""
        logger.info("Stopping server...")
        self.running = False
        
        # Disconnect all clients
        async with self.client_lock:
            for writer in self.clients.values():
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception as e:
                    logger.debug(f"Error closing client: {e}")
            self.clients.clear()
        
        # Stop network manager
        if self.network_manager:
            await self.network_manager.disconnect_all()
            await self.network_manager.stop_server()
        
        # Close IPC server
        if self.ipc_server:
            self.ipc_server.close()
            await self.ipc_server.wait_closed()
        
        # Cleanup
        self._cleanup()
        
        logger.info("Server stopped")
    
    async def run(self):
        """Run server main loop."""
        try:
            while self.running:
                await asyncio.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            await self.stop()
    
    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle client connection."""
        address = writer.get_extra_info('peername')
        logger.debug(f"Client connected from {address}")
        
        # Assign client ID
        async with self.client_lock:
            client_id = self.next_client_id
            self.next_client_id += 1
            self.clients[client_id] = writer
        
        buffer = b''
        
        try:
            while self.running:
                try:
                    data = await asyncio.wait_for(reader.read(4096), timeout=60.0)
                    if not data:
                        break
                    
                    buffer += data
                    
                    # Process complete messages (newline-delimited JSON)
                    while b'\n' in buffer:
                        line, buffer = buffer.split(b'\n', 1)
                        if line:
                            try:
                                request = json.loads(line.decode('utf-8'))
                                response = await self._process_command(request)
                                
                                # Send response
                                response_data = json.dumps(response) + '\n'
                                writer.write(response_data.encode('utf-8'))
                                await writer.drain()
                            except json.JSONDecodeError as e:
                                logger.warning(f"Invalid JSON from client: {e}")
                                error_response = {
                                    'success': False,
                                    'error': 'Invalid JSON'
                                }
                                writer.write((json.dumps(error_response) + '\n').encode('utf-8'))
                                await writer.drain()
                
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    logger.error(f"Error handling client {client_id}: {e}", exc_info=True)
                    break
        finally:
            # Remove client
            async with self.client_lock:
                if client_id in self.clients:
                    del self.clients[client_id]
            
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as e:
                logger.debug(f"Error closing writer: {e}")
    
    async def _process_command(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Process client command and return response."""
        command = request.get('command')
        params = request.get('params', {})
        
        try:
            if command == ServerCommand.PING:
                return {'success': True, 'message': 'pong'}
            
            elif command == ServerCommand.LOGIN:
                return await self._handle_login(params)
            
            elif command == ServerCommand.LOGOUT:
                return await self._handle_logout()
            
            elif command == ServerCommand.SEND_MESSAGE:
                return await self._handle_send_message(params)
            
            elif command == ServerCommand.SEND_GROUP_MESSAGE:
                return await self._handle_send_group_message(params)
            
            elif command == ServerCommand.GET_MESSAGES:
                return await self._handle_get_messages(params)
            
            elif command == ServerCommand.GET_GROUP_MESSAGES:
                return await self._handle_get_group_messages(params)
            
            elif command == ServerCommand.MARK_MESSAGES_READ:
                return await self._handle_mark_messages_read(params)
            
            elif command == ServerCommand.MARK_GROUP_MESSAGES_READ:
                return await self._handle_mark_group_messages_read(params)
            
            elif command == ServerCommand.GET_UNREAD_COUNT:
                return await self._handle_get_unread_count(params)
            
            elif command == ServerCommand.GET_GROUP_UNREAD_COUNT:
                return await self._handle_get_group_unread_count(params)
            
            elif command == ServerCommand.GET_TOTAL_UNREAD_COUNT:
                return await self._handle_get_total_unread_count()
            
            elif command == ServerCommand.ADD_CONTACT:
                return await self._handle_add_contact(params)
            
            elif command == ServerCommand.REMOVE_CONTACT:
                return await self._handle_remove_contact(params)
            
            elif command == ServerCommand.GET_CONTACTS:
                return await self._handle_get_contacts()
            
            elif command == ServerCommand.GET_CONTACT:
                return await self._handle_get_contact(params)
            
            elif command == ServerCommand.CREATE_GROUP:
                return await self._handle_create_group(params)
            
            elif command == ServerCommand.DELETE_GROUP:
                return await self._handle_delete_group(params)
            
            elif command == ServerCommand.GET_GROUPS:
                return await self._handle_get_groups()
            
            elif command == ServerCommand.GET_GROUP:
                return await self._handle_get_group(params)
            
            elif command == ServerCommand.GET_IDENTITY:
                return await self._handle_get_identity()
            
            elif command == ServerCommand.DELETE_ACCOUNT:
                return await self._handle_delete_account(params)
            
            elif command == ServerCommand.EXPORT_ACCOUNT:
                return await self._handle_export_account(params)
            
            elif command == ServerCommand.GET_CONNECTION_STATUS:
                return await self._handle_get_connection_status(params)
            
            elif command == ServerCommand.CONNECT_TO_PEER:
                return await self._handle_connect_to_peer(params)
            
            elif command == ServerCommand.SHUTDOWN:
                return await self._handle_shutdown()

            # File transfer commands
            elif command == ServerCommand.SEND_FILE:
                return await self._handle_send_file(params)

            elif command == ServerCommand.GET_FILE_TRANSFERS:
                return await self._handle_get_file_transfers()

            elif command == ServerCommand.CANCEL_FILE_TRANSFER:
                return await self._handle_cancel_file_transfer(params)

            # Search commands
            elif command == ServerCommand.SEARCH_MESSAGES:
                return await self._handle_search_messages(params)

            elif command == ServerCommand.SEARCH_BY_CONTACT:
                return await self._handle_search_by_contact(params)

            elif command == ServerCommand.SEARCH_BY_DATE:
                return await self._handle_search_by_date(params)

            # Backup commands
            elif command == ServerCommand.CREATE_BACKUP:
                return await self._handle_create_backup(params)

            elif command == ServerCommand.RESTORE_BACKUP:
                return await self._handle_restore_backup(params)

            elif command == ServerCommand.LIST_BACKUPS:
                return await self._handle_list_backups()

            elif command == ServerCommand.DELETE_BACKUP:
                return await self._handle_delete_backup(params)

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
    
    async def _handle_login(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle login command."""
        password = params.get('password')
        
        if not password:
            return {'success': False, 'error': 'Password required'}
        
        try:
            # If already logged in, just verify password
            if self.identity is not None:
                if self.identity_manager and self.identity_manager.load_identity(password):
                    return {
                        'success': True,
                        'identity': {
                            'uid': self.identity.uid,
                            'username': self.identity.username,
                            'fingerprint': self.identity.fingerprint,
                            'listen_port': self.identity.listen_port
                        }
                    }
                else:
                    return {'success': False, 'error': 'Invalid password'}
            
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

            # Initialize v2.0 managers
            self.config = Config(self.data_dir / "config.toml")
            self.rate_limiter = RateLimiter()
            self.backup_manager = BackupManager(
                data_dir=self.data_dir,
                backup_dir=self.data_dir / "backups"
            )
            
            # Initialize message queue
            self.message_queue = MessageQueue(self.data_dir / 'message_queue.db')
            logger.info("Initialized managers (Config, RateLimiter, BackupManager, MessageQueue)")
            
            # Initialize network manager (but only start server if not already started)
            if self.network_manager is None:
                self.network_manager = NetworkManager(
                    self.identity.keypair,
                    self.identity.uid,
                    self.identity.username,
                    self.identity.listen_port,
                    self.contact_manager,
                    data_dir=self.data_dir
                )
                
                # Set up callbacks
                self.network_manager.on_message_callback = self._handle_incoming_message
                self.network_manager.on_group_message_callback = self._handle_incoming_group_message
                self.network_manager.on_connection_state_callback = self._handle_connection_state_change
                
                # Start network server (only on first login)
                logger.info(f"Starting P2P network server on port {self.identity.listen_port}")
                if not await self.network_manager.start_server():
                    return {'success': False, 'error': 'Failed to start network server'}
                logger.info("P2P network server started successfully")
            else:
                logger.info("Network manager already initialized, reusing existing instance")
            
            # Connect to all contacts
            logger.info("Connecting to all known contacts...")
            await self.network_manager.connect_all_contacts()
            
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
            logger.error(f"Login failed: {e}", exc_info=True)
            return {'success': False, 'error': str(e)}
    
    async def _handle_logout(self) -> Dict[str, Any]:
        """
        Handle logout command.
        
        Note: Disconnects from peers but keeps network server running
        for other potential clients and future logins.
        """
        try:
            if self.network_manager:
                # Disconnect from all peers but don't stop server
                logger.info("Disconnecting from all peers...")
                await self.network_manager.disconnect_all()
                logger.info("Disconnected from peers (server still running)")
                # Note: We deliberately do NOT call network_manager.stop_server()
                # The server persists for future logins and other UI clients
            
            # Clear identity and credentials (but keep network_manager for reuse)
            self.identity = None
            self.password = None
            self.contact_manager = None
            self.message_store = None
            self.group_manager = None
            # Note: identity_manager, config, rate_limiter, backup_manager persist
            
            logger.info("Logout successful, server remains active")
            return {'success': True}
        except Exception as e:
            logger.error(f"Logout failed: {e}", exc_info=True)
            return {'success': False, 'error': str(e)}
    
    async def _handle_send_message(self, params: Dict[str, Any]) -> Dict[str, Any]:
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
        success = await self.network_manager.send_message(uid, message, message_id, timestamp)
        
        if success:
            # Store message
            self.message_store.add_message(
                self.identity.uid, uid, message, timestamp, message_id
            )
        
        return {
            'success': success,
            'message_id': message_id if success else None
        }
    
    async def _handle_send_group_message(self, params: Dict[str, Any]) -> Dict[str, Any]:
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
        sent_count = await self.network_manager.send_group_message(
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
    
    async def _handle_get_messages(self, params: Dict[str, Any]) -> Dict[str, Any]:
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
    
    async def _handle_get_group_messages(self, params: Dict[str, Any]) -> Dict[str, Any]:
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
    
    async def _handle_mark_messages_read(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle mark messages as read command."""
        if not self.message_store:
            return {'success': False, 'error': 'Not logged in'}
        
        uid = params.get('uid')
        if not uid:
            return {'success': False, 'error': 'Missing uid'}
        
        self.message_store.mark_conversation_read(uid)
        
        return {'success': True}
    
    async def _handle_mark_group_messages_read(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle mark group messages as read command."""
        if not self.message_store:
            return {'success': False, 'error': 'Not logged in'}
        
        group_id = params.get('group_id')
        if not group_id:
            return {'success': False, 'error': 'Missing group_id'}
        
        self.message_store.mark_group_conversation_read(group_id)
        
        return {'success': True}
    
    async def _handle_get_unread_count(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get unread count command."""
        if not self.message_store:
            return {'success': False, 'error': 'Not logged in'}
        
        uid = params.get('uid')
        if not uid:
            return {'success': False, 'error': 'Missing uid'}
        
        count = self.message_store.get_unread_count(uid)
        
        return {
            'success': True,
            'count': count
        }
    
    async def _handle_get_unread_count(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get group unread count command."""
        if not self.message_store:
            return {'success': False, 'error': 'Not logged in'}
        
        group_id = params.get('group_id')
        if not group_id:
            return {'success': False, 'error': 'Missing group_id'}
        
        count = self.message_store.get_group_unread_count(group_id)
        
        return {
            'success': True,
            'count': count
        }
    
    async def _handle_get_total_unread_count(self) -> Dict[str, Any]:
        """Handle get total unread count command."""
        if not self.message_store:
            return {'success': False, 'error': 'Not logged in'}
        
        count = self.message_store.get_total_unread_count()
        
        return {
            'success': True,
            'count': count
        }
    
    async def _handle_add_contact(self, params: Dict[str, Any]) -> Dict[str, Any]:
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
                await self.network_manager.connect_to_peer(contact)
            
            return {'success': True}
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _handle_remove_contact(self, params: Dict[str, Any]) -> Dict[str, Any]:
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
    
    async def _handle_get_contacts(self) -> Dict[str, Any]:
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
    
    async def _handle_get_contact(self, params: Dict[str, Any]) -> Dict[str, Any]:
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
    
    async def _handle_create_group(self, params: Dict[str, Any]) -> Dict[str, Any]:
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
    
    async def _handle_delete_group(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle delete group command."""
        if not self.group_manager:
            return {'success': False, 'error': 'Not logged in'}
        
        group_id = params.get('group_id')
        if not group_id:
            return {'success': False, 'error': 'Missing group_id'}
        
        success = self.group_manager.delete_group(group_id)
        
        return {'success': success}
    
    async def _handle_get_groups(self) -> Dict[str, Any]:
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
    
    async def _handle_get_group(self, params: Dict[str, Any]) -> Dict[str, Any]:
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
    
    async def _handle_get_identity(self) -> Dict[str, Any]:
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
    
    async def _handle_delete_account(self, params: Dict[str, Any]) -> Dict[str, Any]:
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
    
    async def _handle_export_account(self, params: Dict[str, Any]) -> Dict[str, Any]:
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
    
    async def _handle_get_connection_status(self, params: Dict[str, Any]) -> Dict[str, Any]:
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
    
    async def _handle_connect_to_peer(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle connect to peer command."""
        if not self.network_manager or not self.contact_manager:
            return {'success': False, 'error': 'Not logged in'}
        
        uid = params.get('uid')
        if not uid:
            return {'success': False, 'error': 'Missing uid'}
        
        contact = self.contact_manager.get_contact(uid)
        if not contact:
            return {'success': False, 'error': 'Contact not found'}
        
        success = await self.network_manager.connect_to_peer(contact)
        
        return {'success': success}
    
    async def _handle_shutdown(self) -> Dict[str, Any]:
        """Handle shutdown command."""
        # Schedule shutdown
        asyncio.create_task(self._delayed_shutdown())
        return {'success': True, 'message': 'Server shutting down'}
    
    async def _delayed_shutdown(self):
        """Shutdown after a short delay to allow response to be sent."""
        await asyncio.sleep(0.5)
        self.running = False

    # File transfer handlers
    async def _handle_send_file(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Handle file transfer initiation."""
        try:
            contact_uid = params.get('contact_uid')
            file_path = params.get('file_path')

            if not contact_uid or not file_path:
                return {'success': False, 'error': 'Missing required parameters'}

            # TODO: Implement file transfer using file_transfer.py
            # For now, return a placeholder response
            import uuid
            transfer_id = str(uuid.uuid4())

            self.file_transfers[transfer_id] = {
                'contact_uid': contact_uid,
                'file_path': file_path,
                'status': 'pending',
                'progress': 0
            }

            return {
                'success': True,
                'transfer_id': transfer_id,
                'message': 'File transfer initiated (feature in development)'
            }
        except Exception as e:
            logger.error(f"File transfer error: {e}")
            return {'success': False, 'error': str(e)}

    async def _handle_get_file_transfers(self) -> Dict[str, Any]:
        """Get list of active file transfers."""
        return {
            'success': True,
            'transfers': self.file_transfers
        }

    async def _handle_cancel_file_transfer(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Cancel a file transfer."""
        transfer_id = params.get('transfer_id')

        if transfer_id in self.file_transfers:
            del self.file_transfers[transfer_id]
            return {'success': True, 'message': 'Transfer cancelled'}

        return {'success': False, 'error': 'Transfer not found'}

    # Search handlers
    async def _handle_search_messages(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Search messages."""
        try:
            query = params.get('query', '')
            limit = params.get('limit', 50)

            # TODO: Implement using search.py with MessageSearchEngine
            # For now, return basic search from message store
            return {
                'success': True,
                'results': [],
                'message': 'Search feature in development - requires SQLite migration'
            }
        except Exception as e:
            logger.error(f"Search error: {e}")
            return {'success': False, 'error': str(e)}

    async def _handle_search_by_contact(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Search messages by contact."""
        try:
            contact_uid = params.get('contact_uid')

            if not contact_uid or not self.message_store:
                return {'success': False, 'error': 'Invalid parameters'}

            # Get messages from current message store
            messages = self.message_store.get_messages(contact_uid)

            return {
                'success': True,
                'messages': messages
            }
        except Exception as e:
            logger.error(f"Search by contact error: {e}")
            return {'success': False, 'error': str(e)}

    async def _handle_search_by_date(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Search messages by date range."""
        try:
            start_date = params.get('start_date')
            end_date = params.get('end_date')

            # TODO: Implement with SQLite search engine
            return {
                'success': True,
                'results': [],
                'message': 'Date range search in development - requires SQLite migration'
            }
        except Exception as e:
            logger.error(f"Search by date error: {e}")
            return {'success': False, 'error': str(e)}

    # Backup handlers
    async def _handle_create_backup(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Create a backup."""
        try:
            if not self.backup_manager:
                return {'success': False, 'error': 'Backup manager not initialized'}

            password = params.get('password')  # Optional encryption

            backup_path = self.backup_manager.create_backup(password)

            return {
                'success': True,
                'backup_path': str(backup_path),
                'message': f'Backup created: {backup_path.name}'
            }
        except Exception as e:
            logger.error(f"Backup creation error: {e}")
            return {'success': False, 'error': str(e)}

    async def _handle_restore_backup(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Restore from a backup."""
        try:
            if not self.backup_manager:
                return {'success': False, 'error': 'Backup manager not initialized'}

            backup_path = params.get('backup_path')
            password = params.get('password')  # For encrypted backups

            if not backup_path:
                return {'success': False, 'error': 'Backup path required'}

            from pathlib import Path
            self.backup_manager.restore_backup(Path(backup_path), password)

            return {
                'success': True,
                'message': 'Backup restored successfully - restart required'
            }
        except Exception as e:
            logger.error(f"Backup restore error: {e}")
            return {'success': False, 'error': str(e)}

    async def _handle_list_backups(self) -> Dict[str, Any]:
        """List available backups."""
        try:
            if not self.backup_manager:
                return {'success': False, 'error': 'Backup manager not initialized'}

            backups = self.backup_manager.list_backups()

            return {
                'success': True,
                'backups': backups
            }
        except Exception as e:
            logger.error(f"List backups error: {e}")
            return {'success': False, 'error': str(e)}

    async def _handle_delete_backup(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Delete a backup."""
        try:
            backup_path = params.get('backup_path')

            if not backup_path:
                return {'success': False, 'error': 'Backup path required'}

            from pathlib import Path
            Path(backup_path).unlink()

            return {
                'success': True,
                'message': 'Backup deleted'
            }
        except Exception as e:
            logger.error(f"Delete backup error: {e}")
            return {'success': False, 'error': str(e)}

    async def _handle_incoming_message(self, sender_uid: str, message: str, 
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
        await self._broadcast_to_clients({
            'event': 'message_received',
            'sender_uid': sender_uid,
            'message': message,
            'message_id': message_id,
            'timestamp': timestamp
        })
    
    async def _handle_incoming_group_message(self, group_id: str, sender_uid: str,
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
        await self._broadcast_to_clients({
            'event': 'group_message_received',
            'group_id': group_id,
            'sender_uid': sender_uid,
            'message': message,
            'message_id': message_id,
            'timestamp': timestamp
        })
    
    async def _handle_connection_state_change(self, uid: str, state: int):
        """Handle connection state change."""
        # Broadcast to clients
        await self._broadcast_to_clients({
            'event': 'connection_state_changed',
            'uid': uid,
            'state': state
        })
    
    async def _broadcast_to_clients(self, event: Dict[str, Any]):
        """Broadcast event to all connected clients."""
        message = json.dumps({'type': 'event', 'data': event}) + '\n'
        message_bytes = message.encode('utf-8')
        
        async with self.client_lock:
            for writer in list(self.clients.values()):
                try:
                    writer.write(message_bytes)
                    await writer.drain()
                except Exception as e:
                    logger.debug(f"Error broadcasting to client: {e}")
    
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


async def async_main():
    """Async main entry point for server daemon."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Jarvis Server - Background daemon for P2P connections (asyncio)'
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
    
    if not await server.start():
        sys.exit(1)
    
    # Run server
    await server.run()


def main():
    """Main entry point - runs async_main."""
    asyncio.run(async_main())


if __name__ == '__main__':
    main()
