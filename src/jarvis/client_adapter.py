"""
Jarvis - Client adapter to bridge UI with async client-server architecture.

Created by orpheus497

This module provides an adapter that wraps the async JarvisClient to provide
an interface compatible with the original NetworkManager, minimizing
changes to the UI code. Handles async/sync bridging for Textual UI.
"""

import asyncio
from typing import Optional, Callable, Dict, List
from datetime import datetime

from .client import JarvisClient
from .contact import Contact
from .group import Group, GroupMember


class ClientAdapter:
    """
    Adapter that provides NetworkManager-like interface using async JarvisClient.
    
    This allows the UI to use the async client-server architecture with minimal
    code changes. Handles async/sync bridging for compatibility.
    """
    
    def __init__(self, ipc_port: int = 5999):
        """
        Initialize adapter.
        
        Args:
            ipc_port: Port for IPC communication with server
        """
        self.client = JarvisClient(port=ipc_port)
        self.connected = False
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        
        # Callbacks (compatible with NetworkManager interface)
        self.on_message_callback: Optional[Callable] = None
        self.on_group_message_callback: Optional[Callable] = None
        self.on_connection_state_callback: Optional[Callable] = None
        
        # Setup event handlers
        self.client.on('message_received', self._handle_message_event)
        self.client.on('group_message_received', self._handle_group_message_event)
        self.client.on('connection_state_changed', self._handle_connection_state_event)
    
    def _get_loop(self) -> asyncio.AbstractEventLoop:
        """Get or create event loop."""
        if self._loop is None or self._loop.is_closed():
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
        return self._loop
    
    def _run_async(self, coro):
        """Run async coroutine and return result."""
        loop = self._get_loop()
        if loop.is_running():
            # If loop is already running (e.g., in Textual), create task
            return asyncio.create_task(coro)
        else:
            # If no loop running, run until complete
            return loop.run_until_complete(coro)
    
    async def connect_to_server_async(self) -> bool:
        """Connect to server (async)."""
        self.connected = await self.client.connect()
        return self.connected
    
    def connect_to_server(self) -> bool:
        """Connect to server (sync wrapper)."""
        return self._run_async(self.connect_to_server_async())
    
    async def disconnect_from_server_async(self):
        """Disconnect from server (async)."""
        await self.client.disconnect()
        self.connected = False
    
    def disconnect_from_server(self):
        """Disconnect from server (sync wrapper)."""
        self._run_async(self.disconnect_from_server_async())
    
    async def login_async(self, password: str) -> bool:
        """Login to server (async)."""
        response = await self.client.login(password)
        return response.get('success', False)
    
    def login(self, password: str) -> bool:
        """Login to server (sync wrapper)."""
        return self._run_async(self.login_async(password))
    
    async def logout_async(self) -> bool:
        """Logout from server (async)."""
        return await self.client.logout()
    
    def logout(self) -> bool:
        """Logout from server (sync wrapper)."""
        return self._run_async(self.logout_async())
    
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
    
    async def connect_to_peer_async(self, contact: Contact) -> bool:
        """Connect to peer (delegates to server) - async."""
        return await self.client.connect_to_peer(contact.uid)
    
    def connect_to_peer(self, contact: Contact) -> bool:
        """Connect to peer (delegates to server) - sync wrapper."""
        return self._run_async(self.connect_to_peer_async(contact))
    
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
        """Disconnect from all peers (server manages this)."""
        # Server manages connections
        pass
    
    async def send_message_async(self, uid: str, message: str, message_id: str, timestamp: str) -> bool:
        """Send direct message to peer (async)."""
        response = await self.client.send_message(uid, message)
        return response.get('success', False)
    
    def send_message(self, uid: str, message: str, message_id: str, timestamp: str) -> bool:
        """Send direct message to peer (sync wrapper)."""
        return self._run_async(self.send_message_async(uid, message, message_id, timestamp))
    
    async def send_group_message_async(self, group_id: str, message: str, 
                                       message_id: str, timestamp: str) -> int:
        """Send group message (async)."""
        response = await self.client.send_group_message(group_id, message)
        if response.get('success'):
            return response.get('sent_count', 0)
        return 0
    
    def send_group_message(self, group_id: str, message: str, 
                          message_id: str, timestamp: str) -> int:
        """Send group message (sync wrapper)."""
        return self._run_async(self.send_group_message_async(group_id, message, message_id, timestamp))
    
    async def is_connected_async(self, uid: str) -> bool:
        """Check if connected to peer (async)."""
        response = await self.client.get_connection_status(uid)
        if response.get('success'):
            return response.get('connected', False)
        return False
    
    def is_connected(self, uid: str) -> bool:
        """Check if connected to peer (sync wrapper)."""
        return self._run_async(self.is_connected_async(uid))
    
    def add_group_member(self, group_id: str, uid: str):
        """Add group member (handled by server)."""
        # Server manages group membership
        pass
    
    def remove_group_member(self, group_id: str, uid: str):
        """Remove group member (handled by server)."""
        # Server manages group membership
        pass
    
    async def get_connection_status_async(self, uid: Optional[str] = None) -> Dict[str, bool]:
        """Get connection status for contact(s) (async)."""
        response = await self.client.get_connection_status(uid)
        if response.get('success'):
            if uid:
                return {uid: response.get('connected', False)}
            else:
                return response.get('statuses', {})
        return {}
    
    def get_connection_status(self, uid: Optional[str] = None) -> Dict[str, bool]:
        """Get connection status for contact(s) (sync wrapper)."""
        return self._run_async(self.get_connection_status_async(uid))
    
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
    """Contact manager that delegates to server via async client."""
    
    def __init__(self, client: JarvisClient):
        self.client = client
        self._loop: Optional[asyncio.AbstractEventLoop] = None
    
    def _get_loop(self) -> asyncio.AbstractEventLoop:
        """Get or create event loop."""
        if self._loop is None or self._loop.is_closed():
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
        return self._loop
    
    def _run_async(self, coro):
        """Run async coroutine and return result."""
        loop = self._get_loop()
        if loop.is_running():
            return asyncio.create_task(coro)
        else:
            return loop.run_until_complete(coro)
    
    async def add_contact_async(self, contact: Contact) -> bool:
        """Add contact (async)."""
        return await self.client.add_contact(
            contact.uid,
            contact.username,
            contact.public_key,
            contact.fingerprint,
            contact.host,
            contact.port,
            contact.verified
        )
    
    def add_contact(self, contact: Contact) -> bool:
        """Add contact (sync wrapper)."""
        return self._run_async(self.add_contact_async(contact))
    
    async def remove_contact_async(self, uid: str) -> bool:
        """Remove contact (async)."""
        return await self.client.remove_contact(uid)
    
    def remove_contact(self, uid: str) -> bool:
        """Remove contact (sync wrapper)."""
        return self._run_async(self.remove_contact_async(uid))
    
    async def get_contact_async(self, uid: str) -> Optional[Contact]:
        """Get contact by UID (async)."""
        contact_data = await self.client.get_contact(uid)
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
    
    def get_contact(self, uid: str) -> Optional[Contact]:
        """Get contact by UID (sync wrapper)."""
        return self._run_async(self.get_contact_async(uid))
    
    async def get_contact_by_fingerprint_async(self, fingerprint: str) -> Optional[Contact]:
        """Get contact by fingerprint (async)."""
        contacts = await self.client.get_contacts()
        for contact_data in contacts:
            if contact_data.get('fingerprint') == fingerprint:
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
    
    def get_contact_by_fingerprint(self, fingerprint: str) -> Optional[Contact]:
        """Get contact by fingerprint (sync wrapper)."""
        return self._run_async(self.get_contact_by_fingerprint_async(fingerprint))
    
    async def get_all_contacts_async(self) -> List[Contact]:
        """Get all contacts (async)."""
        contacts_data = await self.client.get_contacts()
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
    
    def get_all_contacts(self) -> List[Contact]:
        """Get all contacts (sync wrapper)."""
        return self._run_async(self.get_all_contacts_async())


class ServerManagedGroupManager:
    """Group manager that delegates to server via async client."""
    
    def __init__(self, client: JarvisClient):
        self.client = client
        self._loop: Optional[asyncio.AbstractEventLoop] = None
    
    def _get_loop(self) -> asyncio.AbstractEventLoop:
        """Get or create event loop."""
        if self._loop is None or self._loop.is_closed():
            try:
                self._loop = asyncio.get_running_loop()
            except RuntimeError:
                self._loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self._loop)
        return self._loop
    
    def _run_async(self, coro):
        """Run async coroutine and return result."""
        loop = self._get_loop()
        if loop.is_running():
            return asyncio.create_task(coro)
        else:
            return loop.run_until_complete(coro)
    
    async def create_group_async(self, name: str, creator_uid: str, 
                                 member_uids: List[str], description: str = '') -> Group:
        """Create group (async)."""
        group_id = await self.client.create_group(name, member_uids, description)
        if group_id:
            # Fetch group details
            group_data = await self.client.get_group(group_id)
            if group_data:
                members = [
                    GroupMember(uid=m['uid'], username=m['username'])
                    for m in group_data.get('members', [])
                ]
                return Group(
                    group_id=group_data['group_id'],
                    name=group_data['name'],
                    creator_uid=group_data['creator_uid'],
                    created_at=group_data['created_at'],
                    members=members,
                    description=group_data.get('description', '')
                )
        return None
    
    def create_group(self, name: str, creator_uid: str, 
                    member_uids: List[str], description: str = '') -> Group:
        """Create group (sync wrapper)."""
        return self._run_async(self.create_group_async(name, creator_uid, member_uids, description))
    
    async def delete_group_async(self, group_id: str) -> bool:
        """Delete group (async)."""
        return await self.client.delete_group(group_id)
    
    def delete_group(self, group_id: str) -> bool:
        """Delete group (sync wrapper)."""
        return self._run_async(self.delete_group_async(group_id))
    
    async def get_group_async(self, group_id: str) -> Optional[Group]:
        """Get group by ID (async)."""
        group_data = await self.client.get_group(group_id)
        if group_data:
            members = [
                GroupMember(uid=m['uid'], username=m['username'])
                for m in group_data.get('members', [])
            ]
            return Group(
                group_id=group_data['group_id'],
                name=group_data['name'],
                creator_uid=group_data['creator_uid'],
                created_at=group_data['created_at'],
                members=members,
                description=group_data.get('description', '')
            )
        return None
    
    def get_group(self, group_id: str) -> Optional[Group]:
        """Get group by ID (sync wrapper)."""
        return self._run_async(self.get_group_async(group_id))
    
    async def get_all_groups_async(self) -> List[Group]:
        """Get all groups (async)."""
        groups_data = await self.client.get_groups()
        groups = []
        for g in groups_data:
            members = [
                GroupMember(uid=m['uid'], username=m['username'])
                for m in g.get('members', [])
            ]
            groups.append(Group(
                group_id=g['group_id'],
                name=g['name'],
                creator_uid=g['creator_uid'],
                created_at=g['created_at'],
                members=members,
                description=g.get('description', '')
            ))
        return groups
    
    def get_all_groups(self) -> List[Group]:
        """Get all groups (sync wrapper)."""
        return self._run_async(self.get_all_groups_async())
