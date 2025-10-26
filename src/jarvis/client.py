"""
Jarvis - Client API for communicating with background server.

Created by orpheus497

This module provides a client interface for UI processes to communicate
with the background Jarvis server via IPC.
"""

import socket
import json
import threading
from typing import Optional, Dict, Any, Callable, List
from queue import Queue, Empty


class JarvisClient:
    """Client for communicating with Jarvis server."""
    
    def __init__(self, host: str = '127.0.0.1', port: int = 5999):
        """
        Initialize client.
        
        Args:
            host: Server host (default: 127.0.0.1)
            port: Server IPC port (default: 5999)
        """
        self.host = host
        self.port = port
        self.socket: Optional[socket.socket] = None
        self.connected = False
        
        # Receive thread
        self.receive_thread: Optional[threading.Thread] = None
        self.running = False
        self.buffer = b''
        
        # Event callbacks
        self.event_callbacks: Dict[str, List[Callable]] = {}
        
        # Response queue for synchronous requests
        self.response_queue = Queue()
        self.pending_request = False
        self.lock = threading.Lock()
    
    def connect(self) -> bool:
        """Connect to server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(5.0)
            self.socket.connect((self.host, self.port))
            self.connected = True
            
            # Start receive thread
            self.running = True
            self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
            self.receive_thread.start()
            
            return True
        
        except Exception as e:
            self.connected = False
            return False
    
    def disconnect(self):
        """Disconnect from server."""
        self.running = False
        self.connected = False
        
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
    
    def _receive_loop(self):
        """Background thread for receiving messages."""
        self.socket.settimeout(1.0)
        
        while self.running and self.connected:
            try:
                data = self.socket.recv(4096)
                if not data:
                    break
                
                self.buffer += data
                
                # Process complete messages (newline-delimited JSON)
                while b'\n' in self.buffer:
                    line, self.buffer = self.buffer.split(b'\n', 1)
                    if line:
                        try:
                            message = json.loads(line.decode('utf-8'))
                            self._handle_message(message)
                        except json.JSONDecodeError:
                            pass
            
            except socket.timeout:
                continue
            except Exception as e:
                break
        
        self.connected = False
    
    def _handle_message(self, message: Dict[str, Any]):
        """Handle received message."""
        msg_type = message.get('type')
        
        if msg_type == 'event':
            # Handle event broadcast from server
            event_data = message.get('data', {})
            event_name = event_data.get('event')
            
            if event_name and event_name in self.event_callbacks:
                for callback in self.event_callbacks[event_name]:
                    try:
                        callback(event_data)
                    except:
                        pass
        
        else:
            # Handle response to request
            with self.lock:
                if self.pending_request:
                    self.response_queue.put(message)
                    self.pending_request = False
    
    def _send_request(self, command: str, params: Dict[str, Any] = None, 
                     timeout: float = 30.0) -> Dict[str, Any]:
        """
        Send request to server and wait for response.
        
        Args:
            command: Command to execute
            params: Command parameters
            timeout: Timeout in seconds
        
        Returns:
            Response from server
        """
        if not self.connected:
            return {'success': False, 'error': 'Not connected to server'}
        
        request = {
            'command': command,
            'params': params or {}
        }
        
        try:
            with self.lock:
                # Clear response queue
                while not self.response_queue.empty():
                    try:
                        self.response_queue.get_nowait()
                    except Empty:
                        break
                
                # Send request
                request_data = json.dumps(request) + '\n'
                self.socket.sendall(request_data.encode('utf-8'))
                self.pending_request = True
            
            # Wait for response
            try:
                response = self.response_queue.get(timeout=timeout)
                return response
            except Empty:
                return {'success': False, 'error': 'Request timeout'}
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def on(self, event_name: str, callback: Callable):
        """
        Register callback for event.
        
        Args:
            event_name: Name of event to listen for
            callback: Function to call when event occurs
        """
        if event_name not in self.event_callbacks:
            self.event_callbacks[event_name] = []
        self.event_callbacks[event_name].append(callback)
    
    def off(self, event_name: str, callback: Callable):
        """
        Unregister callback for event.
        
        Args:
            event_name: Name of event
            callback: Callback to remove
        """
        if event_name in self.event_callbacks:
            try:
                self.event_callbacks[event_name].remove(callback)
            except ValueError:
                pass
    
    # Server control
    
    def ping(self) -> bool:
        """Ping server to check connectivity."""
        response = self._send_request('ping')
        return response.get('success', False)
    
    def shutdown_server(self) -> bool:
        """Request server shutdown."""
        response = self._send_request('shutdown')
        return response.get('success', False)
    
    # Authentication
    
    def login(self, password: str) -> Dict[str, Any]:
        """
        Login to server.
        
        Args:
            password: Master password
        
        Returns:
            Response with success status and identity info
        """
        return self._send_request('login', {'password': password})
    
    def logout(self) -> bool:
        """Logout from server."""
        response = self._send_request('logout')
        return response.get('success', False)
    
    # Messaging
    
    def send_message(self, uid: str, message: str) -> Dict[str, Any]:
        """
        Send message to contact.
        
        Args:
            uid: Contact UID
            message: Message content
        
        Returns:
            Response with success status and message_id
        """
        return self._send_request('send_message', {
            'uid': uid,
            'message': message
        })
    
    def send_group_message(self, group_id: str, message: str) -> Dict[str, Any]:
        """
        Send message to group.
        
        Args:
            group_id: Group ID
            message: Message content
        
        Returns:
            Response with success status and sent count
        """
        return self._send_request('send_group_message', {
            'group_id': group_id,
            'message': message
        })
    
    def get_messages(self, uid: str) -> List[Dict[str, Any]]:
        """
        Get messages for conversation.
        
        Args:
            uid: Contact UID
        
        Returns:
            List of messages
        """
        response = self._send_request('get_messages', {'uid': uid})
        if response.get('success'):
            return response.get('messages', [])
        return []
    
    def get_group_messages(self, group_id: str) -> List[Dict[str, Any]]:
        """
        Get messages for group conversation.
        
        Args:
            group_id: Group ID
        
        Returns:
            List of messages
        """
        response = self._send_request('get_group_messages', {'group_id': group_id})
        if response.get('success'):
            return response.get('messages', [])
        return []
    
    # Contacts
    
    def add_contact(self, uid: str, username: str, public_key: str,
                   fingerprint: str, host: str, port: int, 
                   verified: bool = False) -> bool:
        """
        Add contact.
        
        Args:
            uid: Contact UID
            username: Contact username
            public_key: Contact public key
            fingerprint: Contact fingerprint
            host: Contact host
            port: Contact port
            verified: Whether contact is verified
        
        Returns:
            Success status
        """
        response = self._send_request('add_contact', {
            'uid': uid,
            'username': username,
            'public_key': public_key,
            'fingerprint': fingerprint,
            'host': host,
            'port': port,
            'verified': verified
        })
        return response.get('success', False)
    
    def remove_contact(self, uid: str) -> bool:
        """
        Remove contact.
        
        Args:
            uid: Contact UID
        
        Returns:
            Success status
        """
        response = self._send_request('remove_contact', {'uid': uid})
        return response.get('success', False)
    
    def get_contacts(self) -> List[Dict[str, Any]]:
        """
        Get all contacts.
        
        Returns:
            List of contacts
        """
        response = self._send_request('get_contacts')
        if response.get('success'):
            return response.get('contacts', [])
        return []
    
    def get_contact(self, uid: str) -> Optional[Dict[str, Any]]:
        """
        Get specific contact.
        
        Args:
            uid: Contact UID
        
        Returns:
            Contact info or None
        """
        response = self._send_request('get_contact', {'uid': uid})
        if response.get('success'):
            return response.get('contact')
        return None
    
    # Groups
    
    def create_group(self, name: str, member_uids: List[str],
                    description: str = '') -> Optional[str]:
        """
        Create group.
        
        Args:
            name: Group name
            member_uids: List of member UIDs
            description: Group description
        
        Returns:
            Group ID if successful, None otherwise
        """
        response = self._send_request('create_group', {
            'name': name,
            'member_uids': member_uids,
            'description': description
        })
        if response.get('success'):
            return response.get('group_id')
        return None
    
    def delete_group(self, group_id: str) -> bool:
        """
        Delete group.
        
        Args:
            group_id: Group ID
        
        Returns:
            Success status
        """
        response = self._send_request('delete_group', {'group_id': group_id})
        return response.get('success', False)
    
    def get_groups(self) -> List[Dict[str, Any]]:
        """
        Get all groups.
        
        Returns:
            List of groups
        """
        response = self._send_request('get_groups')
        if response.get('success'):
            return response.get('groups', [])
        return []
    
    def get_group(self, group_id: str) -> Optional[Dict[str, Any]]:
        """
        Get specific group.
        
        Args:
            group_id: Group ID
        
        Returns:
            Group info or None
        """
        response = self._send_request('get_group', {'group_id': group_id})
        if response.get('success'):
            return response.get('group')
        return None
    
    # Identity
    
    def get_identity(self) -> Optional[Dict[str, Any]]:
        """
        Get current identity.
        
        Returns:
            Identity info or None
        """
        response = self._send_request('get_identity')
        if response.get('success'):
            return response.get('identity')
        return None
    
    def delete_account(self, password: str) -> bool:
        """
        Delete account.
        
        Args:
            password: Master password for confirmation
        
        Returns:
            Success status
        """
        response = self._send_request('delete_account', {'password': password})
        return response.get('success', False)
    
    def export_account(self, filepath: str) -> bool:
        """
        Export account.
        
        Args:
            filepath: Path to export file
        
        Returns:
            Success status
        """
        response = self._send_request('export_account', {'filepath': filepath})
        return response.get('success', False)
    
    # Connection status
    
    def get_connection_status(self, uid: Optional[str] = None) -> Dict[str, Any]:
        """
        Get connection status.
        
        Args:
            uid: Contact UID (None for all contacts)
        
        Returns:
            Connection status info
        """
        params = {'uid': uid} if uid else {}
        return self._send_request('get_connection_status', params)
    
    def connect_to_peer(self, uid: str) -> bool:
        """
        Connect to peer.
        
        Args:
            uid: Contact UID
        
        Returns:
            Success status
        """
        response = self._send_request('connect_to_peer', {'uid': uid})
        return response.get('success', False)
