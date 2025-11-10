"""
Jarvis - Client adapter to bridge UI with async client-server architecture.

Created by orpheus497

This module provides an adapter that wraps the async JarvisClient to provide
an interface compatible with the original NetworkManager, minimizing
changes to the UI code. Handles async/sync bridging for Textual UI.
"""

import asyncio
import logging
from typing import Callable, Dict, List, Optional

from .client import JarvisClient
from .contact import Contact
from .group import Group, GroupMember

logger = logging.getLogger(__name__)


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

        # Connection state cache for sync access
        self._connection_cache: Dict[str, bool] = {}

        # Callbacks (compatible with NetworkManager interface)
        self.on_message_callback: Optional[Callable] = None
        self.on_group_message_callback: Optional[Callable] = None
        self.on_connection_state_callback: Optional[Callable] = None

        # Setup event handlers
        self.client.on("message_received", self._handle_message_event)
        self.client.on("group_message_received", self._handle_group_message_event)
        self.client.on("connection_state_changed", self._handle_connection_state_event)

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
        """
        Run async coroutine and return result synchronously.

        Note: This should only be called from truly synchronous contexts,
        not from within an async event loop. If called from within a running
        event loop, returns None.
        """
        try:
            loop = asyncio.get_running_loop()
            # We're in an async context - this is a programming error
            # Return None to avoid blocking
            logger.warning("_run_async called from within running event loop - returning None")
            # Schedule the coroutine to run but don't wait for it
            asyncio.create_task(coro)
            return None
        except RuntimeError:
            # No running loop, safe to use run_until_complete
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(coro)
            finally:
                asyncio.set_event_loop(None)

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
        return response.get("success", False)

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
        """Send direct message to peer (sync wrapper - fires async task)."""
        try:
            asyncio.get_running_loop()
            # Create task to send message asynchronously
            asyncio.create_task(self.send_message_async(uid, message, message_id, timestamp))
            # Return True to indicate message was scheduled
            # Actual success/failure will be in the async callback
            return True
        except RuntimeError:
            # No running loop
            response = self._run_async(self.send_message_async(uid, message, message_id, timestamp))
            return response if isinstance(response, bool) else False

    async def send_message_async(
        self, uid: str, message: str, message_id: str, timestamp: str
    ) -> bool:
        """Send direct message to peer (async)."""
        response = await self.client.send_message(uid, message)
        return response.get("success", False) if isinstance(response, dict) else False

    def send_group_message(
        self, group_id: str, message: str, message_id: str, timestamp: str
    ) -> int:
        """Send group message (sync wrapper - fires async task)."""
        try:
            asyncio.get_running_loop()
            # Create task to send message asynchronously
            asyncio.create_task(
                self.send_group_message_async(group_id, message, message_id, timestamp)
            )
            # Return 1 to indicate message was scheduled
            # Actual count will be determined asynchronously
            return 1
        except RuntimeError:
            # No running loop
            response = self._run_async(
                self.send_group_message_async(group_id, message, message_id, timestamp)
            )
            return response if isinstance(response, int) else 0

    async def send_group_message_async(
        self, group_id: str, message: str, message_id: str, timestamp: str
    ) -> int:
        """Send group message (async)."""
        response = await self.client.send_group_message(group_id, message)
        if isinstance(response, dict) and response.get("success"):
            return response.get("sent_count", 0)
        return 0

    def is_connected(self, uid: str) -> bool:
        """Check if connected to peer (uses cached state for sync access)."""
        return self._connection_cache.get(uid, False)

    async def is_connected_async(self, uid: str) -> bool:
        """Check if connected to peer (async)."""
        response = await self.client.get_connection_status(uid)
        if isinstance(response, dict) and response.get("success"):
            return response.get("connected", False)
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
        if response.get("success"):
            if uid:
                return {uid: response.get("connected", False)}
            else:
                return response.get("statuses", {})
        return {}

    # Event handlers

    def _handle_message_event(self, event: Dict):
        """Handle message received event from server."""
        if self.on_message_callback:
            self.on_message_callback(
                event.get("sender_uid"),
                event.get("message"),
                event.get("message_id"),
                event.get("timestamp"),
            )

    def _handle_group_message_event(self, event: Dict):
        """Handle group message received event from server."""
        if self.on_group_message_callback:
            self.on_group_message_callback(
                event.get("group_id"),
                event.get("sender_uid"),
                event.get("message"),
                event.get("message_id"),
                event.get("timestamp"),
            )

    def _handle_connection_state_event(self, event: Dict):
        """Handle connection state change event from server."""
        uid = event.get("uid")
        state = event.get("state")

        # Update connection cache
        if uid:
            from .network import ConnectionState

            self._connection_cache[uid] = state == ConnectionState.CONNECTED

        # Call user callback
        if self.on_connection_state_callback:
            self.on_connection_state_callback(uid, state)


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
            contact.verified,
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
                uid=contact_data["uid"],
                username=contact_data["username"],
                public_key=contact_data["public_key"],
                fingerprint=contact_data["fingerprint"],
                host=contact_data["host"],
                port=contact_data["port"],
                verified=contact_data.get("verified", False),
            )
        return None

    def get_contact(self, uid: str) -> Optional[Contact]:
        """Get contact by UID (sync wrapper)."""
        return self._run_async(self.get_contact_async(uid))

    async def get_contact_by_fingerprint_async(self, fingerprint: str) -> Optional[Contact]:
        """Get contact by fingerprint (async)."""
        contacts = await self.client.get_contacts()
        for contact_data in contacts:
            if contact_data.get("fingerprint") == fingerprint:
                return Contact(
                    uid=contact_data["uid"],
                    username=contact_data["username"],
                    public_key=contact_data["public_key"],
                    fingerprint=contact_data["fingerprint"],
                    host=contact_data["host"],
                    port=contact_data["port"],
                    verified=contact_data.get("verified", False),
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
                uid=c["uid"],
                username=c["username"],
                public_key=c["public_key"],
                fingerprint=c["fingerprint"],
                host=c["host"],
                port=c["port"],
                verified=c.get("verified", False),
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

    async def create_group_async(
        self, name: str, creator_uid: str, member_uids: List[str], description: str = ""
    ) -> Group:
        """Create group (async)."""
        group_id = await self.client.create_group(name, member_uids, description)
        if group_id:
            # Fetch group details
            group_data = await self.client.get_group(group_id)
            if group_data:
                members = [
                    GroupMember(uid=m["uid"], username=m["username"])
                    for m in group_data.get("members", [])
                ]
                return Group(
                    group_id=group_data["group_id"],
                    name=group_data["name"],
                    creator_uid=group_data["creator_uid"],
                    created_at=group_data["created_at"],
                    members=members,
                    description=group_data.get("description", ""),
                )
        return None

    def create_group(
        self, name: str, creator_uid: str, member_uids: List[str], description: str = ""
    ) -> Group:
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
                GroupMember(uid=m["uid"], username=m["username"])
                for m in group_data.get("members", [])
            ]
            return Group(
                group_id=group_data["group_id"],
                name=group_data["name"],
                creator_uid=group_data["creator_uid"],
                created_at=group_data["created_at"],
                members=members,
                description=group_data.get("description", ""),
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
                GroupMember(uid=m["uid"], username=m["username"]) for m in g.get("members", [])
            ]
            groups.append(
                Group(
                    group_id=g["group_id"],
                    name=g["name"],
                    creator_uid=g["creator_uid"],
                    created_at=g["created_at"],
                    members=members,
                    description=g.get("description", ""),
                )
            )
        return groups

    def get_all_groups(self) -> List[Group]:
        """Get all groups (sync wrapper)."""
        return self._run_async(self.get_all_groups_async())

    # File Transfer Methods (v2.0)

    async def send_file_async(self, contact_uid: str, file_path: str) -> Dict:
        """Send file to contact (async)."""
        return await self.client.send_command(
            "send_file", {"contact_uid": contact_uid, "file_path": file_path}
        )

    def send_file(self, contact_uid: str, file_path: str) -> Dict:
        """Send file to contact (sync wrapper)."""
        return self._run_async(self.send_file_async(contact_uid, file_path))

    async def get_file_transfers_async(self) -> Dict:
        """Get active file transfers (async)."""
        return await self.client.send_command("get_file_transfers", {})

    def get_file_transfers(self) -> Dict:
        """Get active file transfers (sync wrapper)."""
        return self._run_async(self.get_file_transfers_async())

    async def cancel_file_transfer_async(self, transfer_id: str) -> Dict:
        """Cancel file transfer (async)."""
        return await self.client.send_command("cancel_file_transfer", {"transfer_id": transfer_id})

    def cancel_file_transfer(self, transfer_id: str) -> Dict:
        """Cancel file transfer (sync wrapper)."""
        return self._run_async(self.cancel_file_transfer_async(transfer_id))

    # Search Methods (v2.0)

    async def search_messages_async(self, query: str, limit: int = 50) -> Dict:
        """Search messages (async)."""
        return await self.client.send_command("search_messages", {"query": query, "limit": limit})

    def search_messages(self, query: str, limit: int = 50) -> Dict:
        """Search messages (sync wrapper)."""
        return self._run_async(self.search_messages_async(query, limit))

    async def search_by_contact_async(self, contact_uid: str) -> Dict:
        """Search messages by contact (async)."""
        return await self.client.send_command("search_by_contact", {"contact_uid": contact_uid})

    def search_by_contact(self, contact_uid: str) -> Dict:
        """Search messages by contact (sync wrapper)."""
        return self._run_async(self.search_by_contact_async(contact_uid))

    async def search_by_date_async(self, start_date: int, end_date: int) -> Dict:
        """Search messages by date range (async)."""
        return await self.client.send_command(
            "search_by_date", {"start_date": start_date, "end_date": end_date}
        )

    def search_by_date(self, start_date: int, end_date: int) -> Dict:
        """Search messages by date range (sync wrapper)."""
        return self._run_async(self.search_by_date_async(start_date, end_date))

    # Backup Methods (v2.0)

    async def create_backup_async(self, password: Optional[str] = None) -> Dict:
        """Create backup (async)."""
        params = {}
        if password:
            params["password"] = password
        return await self.client.send_command("create_backup", params)

    def create_backup(self, password: Optional[str] = None) -> Dict:
        """Create backup (sync wrapper)."""
        return self._run_async(self.create_backup_async(password))

    async def restore_backup_async(self, backup_path: str, password: Optional[str] = None) -> Dict:
        """Restore from backup (async)."""
        params = {"backup_path": backup_path}
        if password:
            params["password"] = password
        return await self.client.send_command("restore_backup", params)

    def restore_backup(self, backup_path: str, password: Optional[str] = None) -> Dict:
        """Restore from backup (sync wrapper)."""
        return self._run_async(self.restore_backup_async(backup_path, password))

    async def list_backups_async(self) -> Dict:
        """List available backups (async)."""
        return await self.client.send_command("list_backups", {})

    def list_backups(self) -> Dict:
        """List available backups (sync wrapper)."""
        return self._run_async(self.list_backups_async())

    async def delete_backup_async(self, backup_path: str) -> Dict:
        """Delete a backup (async)."""
        return await self.client.send_command("delete_backup", {"backup_path": backup_path})

    def delete_backup(self, backup_path: str) -> Dict:
        """Delete a backup (sync wrapper)."""
        return self._run_async(self.delete_backup_async(backup_path))
