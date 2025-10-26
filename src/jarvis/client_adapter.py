"""
Jarvis - Client adapter to bridge UI with client-server architecture.

Created by orpheus497

This module provides an adapter that wraps the JarvisClient to provide
an interface compatible with the original NetworkManager, minimizing
changes to the UI code.
"""

from typing import Optional, Callable, Dict, List
from datetime import datetime

from .client import JarvisClient
from .contact import Contact
from .group import Group, GroupMember


class ClientAdapter:
    """
    Adapter that provides NetworkManager-like interface using JarvisClient.
    
    This allows the UI to use the client-server architecture with minimal
    code changes.
    """
    
    def __init__(self, ipc_port: int = 5999):
        """
        Initialize adapter.
        
        Args:
            ipc_port: Port for IPC communication with server
        """
        self.client = JarvisClient(port=ipc_port)
        self.connected = False
        
        # Callbacks (compatible with NetworkManager interface)
        self.on_message_callback: Optional[Callable] = None
        self.on_group_message_callback: Optional[Callable] = None
        self.on_connection_state_callback: Optional[Callable] = None
        
        # Setup event handlers
        self.client.on('message_received', self._handle_message_event)
        self.client.on('group_message_received', self._handle_group_message_event)
        self.client.on('connection_state_changed', self._handle_connection_state_event)
    
    def connect_to_server(self) -> bool:
        """Connect to server."""
        self.connected = self.client.connect()
        return self.connected
    
    def disconnect_from_server(self):
        """Disconnect from server."""
        self.client.disconnect()
        self.connected = False
    
    def login(self, password: str) -> bool:
        """Login to server."""
        response = self.client.login(password)
        return response.get('success', False)
    
    def logout(self) -> bool:
        """Logout from server."""
        return self.client.logout()
    
    # NetworkManager-compatible interface
    
    def start_server(self) -> bool:
        """
        Compatible with NetworkManager.start_server().
        In client-server architecture, this just ensures connection to server.
        """
        return self.connected
    
    def stop_server(self):
        """
        Compatible with NetworkManager.stop_server().
        In client-server architecture, this disconnects from server.
        """
        self.disconnect_from_server()
    
    def connect_to_peer(self, contact: Contact) -> bool:
        """Connect to peer (delegates to server)."""
        return self.client.connect_to_peer(contact.uid)
    
    def connect_all_contacts(self) -> Dict[str, bool]:
        """
        Connect to all contacts (happens on server side).
        Returns empty dict as server handles this automatically.
        """
        # Server connects automatically on login
        # Return empty dict for compatibility
        return {}
    
    def disconnect_from_peer(self, uid: str):
        """Disconnect from peer (server manages this)."""
        # Server manages connections
        pass
    
    def disconnect_all(self):
        """Disconnect from all peers (server manages this)."""
        # Server manages connections
        pass
    
    def send_message(self, uid: str, message: str, message_id: str, timestamp: str) -> bool:
        """Send direct message to peer."""
        response = self.client.send_message(uid, message)
        return response.get('success', False)
    
    def send_group_message(self, group_id: str, message: str, 
                          message_id: str, timestamp: str) -> int:
        """Send group message."""
        response = self.client.send_group_message(group_id, message)
        if response.get('success'):
            return response.get('sent_count', 0)
        return 0
    
    def is_connected(self, uid: str) -> bool:
        """Check if connected to peer."""
        response = self.client.get_connection_status(uid)
        if response.get('success'):
            return response.get('connected', False)
        return False
    
    def add_group_member(self, group_id: str, uid: str):
        """Add group member (handled by server)."""
        # Server manages group membership
        pass
    
    def remove_group_member(self, group_id: str, uid: str):
        """Remove group member (handled by server)."""
        # Server manages group membership
        pass
    
    def get_connection_status(self, uid: Optional[str] = None) -> Dict[str, bool]:
        """Get connection status for contact(s)."""
        response = self.client.get_connection_status(uid)
        if response.get('success'):
            if uid:
                return {uid: response.get('connected', False)}
            else:
                return response.get('statuses', {})
        return {}
    
    # Event handlers
    
    def _handle_message_event(self, event: Dict):
        """Handle message received event from server."""
        if self.on_message_callback:
            self.on_message_callback(
                event.get('sender_uid'),
                event.get('message'),
                event.get('message_id'),
                event.get('timestamp')
            )
    
    def _handle_group_message_event(self, event: Dict):
        """Handle group message received event from server."""
        if self.on_group_message_callback:
            self.on_group_message_callback(
                event.get('group_id'),
                event.get('sender_uid'),
                event.get('message'),
                event.get('message_id'),
                event.get('timestamp')
            )
    
    def _handle_connection_state_event(self, event: Dict):
        """Handle connection state change event from server."""
        if self.on_connection_state_callback:
            self.on_connection_state_callback(
                event.get('uid'),
                event.get('state')
            )


class ServerManagedContactManager:
    """Contact manager that delegates to server via client."""
    
    def __init__(self, client: JarvisClient):
        self.client = client
    
    def add_contact(self, contact: Contact) -> bool:
        """Add contact."""
        return self.client.add_contact(
            contact.uid,
            contact.username,
            contact.public_key,
            contact.fingerprint,
            contact.host,
            contact.port,
            contact.verified
        )
    
    def remove_contact(self, uid: str) -> bool:
        """Remove contact."""
        return self.client.remove_contact(uid)
    
    def get_contact(self, uid: str) -> Optional[Contact]:
        """Get contact by UID."""
        contact_data = self.client.get_contact(uid)
        if contact_data:
            return Contact(
                uid=contact_data['uid'],
                username=contact_data['username'],
                public_key=contact_data['public_key'],
                fingerprint=contact_data['fingerprint'],
                host=contact_data['host'],
                port=contact_data['port'],
                verified=contact_data.get('verified', False)
            )
        return None
    
    def get_all_contacts(self) -> List[Contact]:
        """Get all contacts."""
        contacts_data = self.client.get_contacts()
        return [
            Contact(
                uid=c['uid'],
                username=c['username'],
                public_key=c['public_key'],
                fingerprint=c['fingerprint'],
                host=c['host'],
                port=c['port'],
                verified=c.get('verified', False)
            )
            for c in contacts_data
        ]


class ServerManagedGroupManager:
    """Group manager that delegates to server via client."""
    
    def __init__(self, client: JarvisClient):
        self.client = client
    
    def create_group(self, name: str, creator_uid: str, member_uids: List[str],
                    description: str = '') -> Optional[Group]:
        """Create group."""
        group_id = self.client.create_group(name, member_uids, description)
        if group_id:
            # Fetch the created group
            return self.get_group(group_id)
        return None
    
    def delete_group(self, group_id: str) -> bool:
        """Delete group."""
        return self.client.delete_group(group_id)
    
    def get_group(self, group_id: str) -> Optional[Group]:
        """Get group by ID."""
        group_data = self.client.get_group(group_id)
        if group_data:
            members = [
                GroupMember(uid=m['uid'], username=m['username'])
                for m in group_data.get('members', [])
            ]
            return Group(
                group_id=group_data['group_id'],
                name=group_data['name'],
                creator_uid=group_data['creator_uid'],
                members=members,
                created_at=group_data.get('created_at', ''),
                description=group_data.get('description', '')
            )
        return None
    
    def get_all_groups(self) -> List[Group]:
        """Get all groups."""
        groups_data = self.client.get_groups()
        result = []
        for g in groups_data:
            members = [
                GroupMember(uid=m['uid'], username=m['username'])
                for m in g.get('members', [])
            ]
            result.append(Group(
                group_id=g['group_id'],
                name=g['name'],
                creator_uid=g['creator_uid'],
                members=members,
                created_at=g.get('created_at', ''),
                description=g.get('description', '')
            ))
        return result
