"""
Jarvis - Client API for communicating with background server using asyncio.

Created by orpheus497

This module provides a client interface for UI processes to communicate
with the background Jarvis server via IPC using unified async architecture.
"""

import asyncio
import contextlib
import json
import logging
from typing import Any, Callable, Dict, List, Optional

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class JarvisClient:
    """Async client for communicating with Jarvis server."""

    def __init__(self, host: str = "127.0.0.1", port: int = 5999):
        """
        Initialize client.

        Args:
            host: Server host (default: 127.0.0.1)
            port: Server IPC port (default: 5999)
        """
        self.host = host
        self.port = port
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.connected = False

        # Receive task
        self.receive_task: Optional[asyncio.Task] = None
        self.running = False
        self.buffer = b""

        # Event callbacks
        self.event_callbacks: Dict[str, List[Callable]] = {}

        # Response queue for synchronous requests
        self.response_queue = asyncio.Queue()
        self.pending_request = False
        self.lock = asyncio.Lock()

    async def connect(self) -> bool:
        """Connect to server."""
        try:
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(self.host, self.port), timeout=5.0
            )
            self.connected = True

            # Start receive task
            self.running = True
            self.receive_task = asyncio.create_task(self._receive_loop())

            logger.info(f"Connected to server at {self.host}:{self.port}")
            return True

        except asyncio.TimeoutError:
            logger.error("Connection timeout")
            self.connected = False
            return False
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            self.connected = False
            return False

    async def disconnect(self):
        """Disconnect from server."""
        self.running = False
        self.connected = False

        if self.receive_task and not self.receive_task.done():
            self.receive_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.receive_task

        if self.writer:
            try:
                self.writer.close()
                await self.writer.wait_closed()
            except Exception as e:
                logger.debug(f"Error closing writer: {e}")
            self.writer = None

        self.reader = None

    async def _receive_loop(self):
        """Background task for receiving messages."""
        logger.debug("Receive loop started")

        try:
            while self.running and self.connected:
                try:
                    data = await asyncio.wait_for(self.reader.read(4096), timeout=1.0)
                    if not data:
                        logger.warning("Server closed connection")
                        break

                    self.buffer += data

                    # Process complete messages (newline-delimited JSON)
                    while b"\n" in self.buffer:
                        line, self.buffer = self.buffer.split(b"\n", 1)
                        if line:
                            try:
                                message = json.loads(line.decode("utf-8"))
                                await self._handle_message(message)
                            except json.JSONDecodeError as e:
                                logger.warning(f"Invalid JSON from server: {e}")

                except asyncio.TimeoutError:
                    continue
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    logger.error(f"Error in receive loop: {e}", exc_info=True)
                    break
        finally:
            self.connected = False
            logger.debug("Receive loop ended")

    async def _handle_message(self, message: Dict[str, Any]):
        """Handle received message."""
        msg_type = message.get("type")

        if msg_type == "event":
            # Handle event broadcast from server
            event_data = message.get("data", {})
            event_name = event_data.get("event")

            if event_name and event_name in self.event_callbacks:
                for callback in self.event_callbacks[event_name]:
                    try:
                        # Handle both sync and async callbacks
                        if asyncio.iscoroutinefunction(callback):
                            await callback(event_data)
                        else:
                            callback(event_data)
                    except Exception as e:
                        logger.error(f"Error in event callback: {e}", exc_info=True)

        else:
            # Handle response to request
            async with self.lock:
                if self.pending_request:
                    await self.response_queue.put(message)
                    self.pending_request = False

    async def _send_request(
        self, command: str, params: Optional[Dict[str, Any]] = None, timeout: float = 30.0
    ) -> Dict[str, Any]:
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
            return {"success": False, "error": "Not connected to server"}

        request = {"command": command, "params": params or {}}

        try:
            async with self.lock:
                # Clear response queue
                while not self.response_queue.empty():
                    try:
                        self.response_queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break

                # Send request
                request_data = json.dumps(request) + "\n"
                self.writer.write(request_data.encode("utf-8"))
                await self.writer.drain()
                self.pending_request = True

            # Wait for response
            try:
                response = await asyncio.wait_for(self.response_queue.get(), timeout=timeout)
                return response
            except asyncio.TimeoutError:
                logger.warning(f"Request timeout for command: {command}")
                return {"success": False, "error": "Request timeout"}

        except Exception as e:
            logger.error(f"Error sending request: {e}", exc_info=True)
            return {"success": False, "error": str(e)}

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
            with contextlib.suppress(ValueError):
                self.event_callbacks[event_name].remove(callback)

    # Server control

    async def ping(self) -> bool:
        """Ping server to check connectivity."""
        response = await self._send_request("ping")
        return response.get("success", False)

    async def shutdown_server(self) -> bool:
        """Request server shutdown."""
        response = await self._send_request("shutdown")
        return response.get("success", False)

    # Authentication

    async def login(self, password: str) -> Dict[str, Any]:
        """
        Login to server.

        Args:
            password: Master password

        Returns:
            Response with success status and identity info
        """
        return await self._send_request("login", {"password": password})

    async def logout(self) -> bool:
        """Logout from server."""
        response = await self._send_request("logout")
        return response.get("success", False)

    # Messaging

    async def send_message(self, uid: str, message: str) -> Dict[str, Any]:
        """
        Send message to contact.

        Args:
            uid: Contact UID
            message: Message content

        Returns:
            Response with success status and message_id
        """
        return await self._send_request("send_message", {"uid": uid, "message": message})

    async def send_group_message(self, group_id: str, message: str) -> Dict[str, Any]:
        """
        Send message to group.

        Args:
            group_id: Group ID
            message: Message content

        Returns:
            Response with success status and sent count
        """
        return await self._send_request(
            "send_group_message", {"group_id": group_id, "message": message}
        )

    async def get_messages(self, uid: str) -> List[Dict[str, Any]]:
        """
        Get messages for conversation.

        Args:
            uid: Contact UID

        Returns:
            List of messages
        """
        response = await self._send_request("get_messages", {"uid": uid})
        if response.get("success"):
            return response.get("messages", [])
        return []

    async def get_group_messages(self, group_id: str) -> List[Dict[str, Any]]:
        """
        Get messages for group conversation.

        Args:
            group_id: Group ID

        Returns:
            List of messages
        """
        response = await self._send_request("get_group_messages", {"group_id": group_id})
        if response.get("success"):
            return response.get("messages", [])
        return []

    async def mark_messages_read(self, uid: str) -> bool:
        """
        Mark all messages from a contact as read.

        Args:
            uid: Contact UID

        Returns:
            Success status
        """
        response = await self._send_request("mark_messages_read", {"uid": uid})
        return response.get("success", False)

    async def mark_group_messages_read(self, group_id: str) -> bool:
        """
        Mark all messages in a group as read.

        Args:
            group_id: Group ID

        Returns:
            Success status
        """
        response = await self._send_request("mark_group_messages_read", {"group_id": group_id})
        return response.get("success", False)

    async def get_unread_count(self, uid: str) -> int:
        """
        Get unread message count for a contact.

        Args:
            uid: Contact UID

        Returns:
            Number of unread messages
        """
        response = await self._send_request("get_unread_count", {"uid": uid})
        if response.get("success"):
            return response.get("count", 0)
        return 0

    async def get_group_unread_count(self, group_id: str) -> int:
        """
        Get unread message count for a group.

        Args:
            group_id: Group ID

        Returns:
            Number of unread messages
        """
        response = await self._send_request("get_group_unread_count", {"group_id": group_id})
        if response.get("success"):
            return response.get("count", 0)
        return 0

    async def get_total_unread_count(self) -> int:
        """
        Get total unread message count across all contacts and groups.

        Returns:
            Total number of unread messages
        """
        response = await self._send_request("get_total_unread_count")
        if response.get("success"):
            return response.get("count", 0)
        return 0

    # Contacts

    async def add_contact(
        self,
        uid: str,
        username: str,
        public_key: str,
        fingerprint: str,
        host: str,
        port: int,
        verified: bool = False,
    ) -> bool:
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
        response = await self._send_request(
            "add_contact",
            {
                "uid": uid,
                "username": username,
                "public_key": public_key,
                "fingerprint": fingerprint,
                "host": host,
                "port": port,
                "verified": verified,
            },
        )
        return response.get("success", False)

    async def remove_contact(self, uid: str) -> bool:
        """
        Remove contact.

        Args:
            uid: Contact UID

        Returns:
            Success status
        """
        response = await self._send_request("remove_contact", {"uid": uid})
        return response.get("success", False)

    async def get_contacts(self) -> List[Dict[str, Any]]:
        """
        Get all contacts.

        Returns:
            List of contacts
        """
        response = await self._send_request("get_contacts")
        if response.get("success"):
            return response.get("contacts", [])
        return []

    async def get_contact(self, uid: str) -> Optional[Dict[str, Any]]:
        """
        Get specific contact.

        Args:
            uid: Contact UID

        Returns:
            Contact info or None
        """
        response = await self._send_request("get_contact", {"uid": uid})
        if response.get("success"):
            return response.get("contact")
        return None

    # Groups

    async def create_group(
        self, name: str, member_uids: List[str], description: str = ""
    ) -> Optional[str]:
        """
        Create group.

        Args:
            name: Group name
            member_uids: List of member UIDs
            description: Group description

        Returns:
            Group ID if successful, None otherwise
        """
        response = await self._send_request(
            "create_group", {"name": name, "member_uids": member_uids, "description": description}
        )
        if response.get("success"):
            return response.get("group_id")
        return None

    async def delete_group(self, group_id: str) -> bool:
        """
        Delete group.

        Args:
            group_id: Group ID

        Returns:
            Success status
        """
        response = await self._send_request("delete_group", {"group_id": group_id})
        return response.get("success", False)

    async def get_groups(self) -> List[Dict[str, Any]]:
        """
        Get all groups.

        Returns:
            List of groups
        """
        response = await self._send_request("get_groups")
        if response.get("success"):
            return response.get("groups", [])
        return []

    async def get_group(self, group_id: str) -> Optional[Dict[str, Any]]:
        """
        Get specific group.

        Args:
            group_id: Group ID

        Returns:
            Group info or None
        """
        response = await self._send_request("get_group", {"group_id": group_id})
        if response.get("success"):
            return response.get("group")
        return None

    # Identity

    async def get_identity(self) -> Optional[Dict[str, Any]]:
        """
        Get current identity.

        Returns:
            Identity info or None
        """
        response = await self._send_request("get_identity")
        if response.get("success"):
            return response.get("identity")
        return None

    async def delete_account(self, password: str) -> bool:
        """
        Delete account.

        Args:
            password: Master password for confirmation

        Returns:
            Success status
        """
        response = await self._send_request("delete_account", {"password": password})
        return response.get("success", False)

    async def export_account(self, filepath: str) -> bool:
        """
        Export account.

        Args:
            filepath: Path to export file

        Returns:
            Success status
        """
        response = await self._send_request("export_account", {"filepath": filepath})
        return response.get("success", False)

    # Connection status

    async def get_connection_status(self, uid: Optional[str] = None) -> Dict[str, Any]:
        """
        Get connection status.

        Args:
            uid: Contact UID (None for all contacts)

        Returns:
            Connection status info
        """
        params = {"uid": uid} if uid else {}
        return await self._send_request("get_connection_status", params)

    async def connect_to_peer(self, uid: str) -> bool:
        """
        Connect to peer.

        Args:
            uid: Contact UID

        Returns:
            Success status
        """
        response = await self._send_request("connect_to_peer", {"uid": uid})
        return response.get("success", False)
