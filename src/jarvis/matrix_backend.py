"""
Jarvis - Matrix Protocol Integration Backend.

Created by orpheus497

This module provides integration with the Matrix decentralized communication protocol,
enabling federated, end-to-end encrypted messaging through Matrix homeservers.

Matrix protocol features:
- Decentralized federation: Messages can traverse multiple homeservers
- End-to-end encryption: Via Olm/Megolm cryptographic ratchets
- Room-based messaging: Direct chats and group rooms
- Interoperability: Bridge to other platforms via Matrix bridges

This backend acts as an alternative transport layer alongside the existing P2P
network, allowing users to communicate via Matrix homeservers.
"""

import asyncio
import contextlib
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from nio import (
    AsyncClient,
    AsyncClientConfig,
    InviteMemberEvent,
    JoinError,
    LoginResponse,
    RoomMessageText,
    SyncResponse,
)
from nio import (
    MatrixRoom as NioRoom,
)

from .constants import (
    FEATURE_MATRIX_PROTOCOL,
    MATRIX_AUTO_JOIN,
    MATRIX_DEFAULT_HOMESERVER,
    MATRIX_DEVICE_NAME,
    MATRIX_E2EE_ENABLED,
    MATRIX_RETRY_ATTEMPTS,
    MATRIX_RETRY_DELAY,
    MATRIX_SYNC_TIMEOUT,
    MATRIX_TYPING_TIMEOUT,
)

logger = logging.getLogger(__name__)


class MatrixConnectionState(Enum):
    """Connection state for Matrix client."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    SYNCING = "syncing"
    ERROR = "error"


@dataclass
class MatrixConfig:
    """Configuration for Matrix backend connection."""

    homeserver_url: str = MATRIX_DEFAULT_HOMESERVER
    user_id: str = ""
    access_token: str = ""
    device_id: str = ""
    device_name: str = MATRIX_DEVICE_NAME
    store_path: Optional[Path] = None
    e2ee_enabled: bool = MATRIX_E2EE_ENABLED
    auto_join: bool = MATRIX_AUTO_JOIN
    sync_timeout: int = MATRIX_SYNC_TIMEOUT


@dataclass
class MatrixMessage:
    """Represents a Matrix message."""

    event_id: str
    room_id: str
    sender: str
    content: str
    timestamp: datetime
    is_encrypted: bool = False
    message_type: str = "m.text"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class JarvisMatrixRoom:
    """Represents a Matrix room in Jarvis."""

    room_id: str
    name: str
    is_direct: bool = False
    is_encrypted: bool = False
    members: List[str] = field(default_factory=list)
    topic: str = ""
    unread_count: int = 0


class MatrixBackend:
    """
    Matrix protocol backend for Jarvis Messenger.

    Provides async Matrix client functionality for:
    - User authentication (login/logout)
    - Room management (create, join, leave)
    - Message sending/receiving
    - End-to-end encryption (when available)
    - Real-time sync with homeserver

    This backend runs alongside the existing P2P network as an alternative
    transport layer for federated communication.
    """

    def __init__(self, config: MatrixConfig, data_dir: Optional[Path] = None):
        """
        Initialize Matrix backend.

        Args:
            config: Matrix configuration settings
            data_dir: Directory for storing session data
        """
        if not FEATURE_MATRIX_PROTOCOL:
            raise RuntimeError("Matrix protocol feature is disabled")

        self.config = config
        self.data_dir = data_dir or Path.home() / ".jarvis" / "matrix"
        self.data_dir.mkdir(parents=True, exist_ok=True)

        self.state = MatrixConnectionState.DISCONNECTED
        self.client: Optional[AsyncClient] = None
        self._sync_task: Optional[asyncio.Task] = None
        self._running = False

        # Callbacks
        self.on_message_callback: Optional[Callable] = None
        self.on_invite_callback: Optional[Callable] = None
        self.on_state_change_callback: Optional[Callable] = None
        self.on_room_update_callback: Optional[Callable] = None

        # Room cache
        self._rooms: Dict[str, JarvisMatrixRoom] = {}
        self._direct_rooms: Dict[str, str] = {}  # user_id -> room_id mapping

        # Track async callback tasks for proper cleanup
        self._callback_tasks: Set[asyncio.Task] = set()

        logger.info(f"Matrix backend initialized for {config.homeserver_url}")

    async def connect(self, username: str, password: str) -> bool:
        """
        Connect to Matrix homeserver with credentials.

        Args:
            username: Matrix username or full user ID (@user:server.org)
            password: Account password

        Returns:
            True if connection successful, False otherwise
        """
        try:
            self._set_state(MatrixConnectionState.CONNECTING)

            # Parse user ID
            if not username.startswith("@"):
                # Construct full user ID
                server_name = self.config.homeserver_url.split("//")[-1].split(":")[0]
                user_id = f"@{username}:{server_name}"
            else:
                user_id = username

            # Configure client
            client_config = AsyncClientConfig(
                max_limit_exceeded=0,
                max_timeouts=0,
                store_sync_tokens=True,
            )

            self.client = AsyncClient(
                homeserver=self.config.homeserver_url,
                user=user_id,
                device_id=self.config.device_id or None,
                store_path=str(self.data_dir),
                config=client_config,
            )

            # Attempt login
            response = await self.client.login(
                password=password, device_name=self.config.device_name
            )

            if isinstance(response, LoginResponse):
                self.config.user_id = response.user_id
                self.config.device_id = response.device_id
                self.config.access_token = response.access_token

                logger.info(f"Matrix login successful: {response.user_id}")
                self._set_state(MatrixConnectionState.CONNECTED)

                # Start sync loop
                await self._start_sync()

                return True
            else:
                logger.error(f"Matrix login failed: {response}")
                self._set_state(MatrixConnectionState.ERROR)
                return False

        except Exception as e:
            logger.error(f"Matrix connection error: {e}", exc_info=True)
            self._set_state(MatrixConnectionState.ERROR)
            return False

    async def connect_with_token(self, user_id: str, access_token: str) -> bool:
        """
        Connect using existing access token.

        Args:
            user_id: Full Matrix user ID (@user:server.org)
            access_token: Valid access token

        Returns:
            True if connection successful, False otherwise
        """
        try:
            self._set_state(MatrixConnectionState.CONNECTING)

            client_config = AsyncClientConfig(
                max_limit_exceeded=0,
                max_timeouts=0,
                store_sync_tokens=True,
            )

            self.client = AsyncClient(
                homeserver=self.config.homeserver_url,
                user=user_id,
                device_id=self.config.device_id or None,
                store_path=str(self.data_dir),
                config=client_config,
            )

            self.client.access_token = access_token
            self.client.user_id = user_id
            self.config.user_id = user_id
            self.config.access_token = access_token

            # Verify token by doing initial sync
            response = await self.client.sync(timeout=5000, full_state=True)

            if isinstance(response, SyncResponse):
                logger.info(f"Matrix token auth successful: {user_id}")
                self._set_state(MatrixConnectionState.CONNECTED)

                # Start sync loop
                await self._start_sync()

                return True
            else:
                logger.error(f"Matrix token auth failed: {response}")
                self._set_state(MatrixConnectionState.ERROR)
                return False

        except Exception as e:
            logger.error(f"Matrix token connection error: {e}", exc_info=True)
            self._set_state(MatrixConnectionState.ERROR)
            return False

    async def disconnect(self) -> None:
        """Disconnect from Matrix homeserver."""
        logger.info("Disconnecting from Matrix...")
        self._running = False

        if self._sync_task and not self._sync_task.done():
            self._sync_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._sync_task

        if self.client:
            await self.client.close()
            self.client = None

        self._set_state(MatrixConnectionState.DISCONNECTED)
        logger.info("Matrix disconnected")

    async def send_message(self, room_id: str, content: str) -> Optional[str]:
        """
        Send a text message to a room.

        Args:
            room_id: Target room ID
            content: Message text content

        Returns:
            Event ID if successful, None otherwise
        """
        if not self.client or self.state != MatrixConnectionState.SYNCING:
            logger.warning("Cannot send message: not connected to Matrix")
            return None

        try:
            response = await self.client.room_send(
                room_id=room_id,
                message_type="m.room.message",
                content={"msgtype": "m.text", "body": content},
            )

            if hasattr(response, "event_id"):
                logger.debug(f"Message sent to {room_id}: {response.event_id}")
                return response.event_id
            else:
                logger.error(f"Failed to send message: {response}")
                return None

        except Exception as e:
            logger.error(f"Error sending Matrix message: {e}", exc_info=True)
            return None

    async def send_direct_message(self, user_id: str, content: str) -> Optional[str]:
        """
        Send a direct message to a user.

        Creates a direct room if one doesn't exist.

        Args:
            user_id: Target user's Matrix ID
            content: Message text content

        Returns:
            Event ID if successful, None otherwise
        """
        # Get or create direct room
        room_id = await self._get_or_create_direct_room(user_id)
        if not room_id:
            logger.error(f"Could not get/create direct room for {user_id}")
            return None

        return await self.send_message(room_id, content)

    async def create_room(
        self, name: str, invite_users: Optional[List[str]] = None, is_direct: bool = False
    ) -> Optional[str]:
        """
        Create a new Matrix room.

        Args:
            name: Room name
            invite_users: List of user IDs to invite
            is_direct: Whether this is a direct message room

        Returns:
            Room ID if successful, None otherwise
        """
        if not self.client:
            return None

        try:
            response = await self.client.room_create(
                name=name,
                invite=invite_users or [],
                is_direct=is_direct,
                preset="trusted_private_chat" if is_direct else "private_chat",
            )

            if hasattr(response, "room_id"):
                room_id = response.room_id
                logger.info(f"Created room: {room_id}")

                # Track direct room mapping
                if is_direct and invite_users and len(invite_users) == 1:
                    self._direct_rooms[invite_users[0]] = room_id

                return room_id
            else:
                logger.error(f"Failed to create room: {response}")
                return None

        except Exception as e:
            logger.error(f"Error creating Matrix room: {e}", exc_info=True)
            return None

    async def join_room(self, room_id_or_alias: str) -> bool:
        """
        Join a Matrix room.

        Args:
            room_id_or_alias: Room ID or alias to join

        Returns:
            True if joined successfully, False otherwise
        """
        if not self.client:
            return False

        try:
            response = await self.client.join(room_id_or_alias)

            if isinstance(response, JoinError):
                logger.error(f"Failed to join room {room_id_or_alias}: {response}")
                return False

            logger.info(f"Joined room: {room_id_or_alias}")
            return True

        except Exception as e:
            logger.error(f"Error joining Matrix room: {e}", exc_info=True)
            return False

    async def leave_room(self, room_id: str) -> bool:
        """
        Leave a Matrix room.

        Args:
            room_id: Room ID to leave

        Returns:
            True if left successfully, False otherwise
        """
        if not self.client:
            return False

        try:
            response = await self.client.room_leave(room_id)

            if hasattr(response, "room_id"):
                logger.info(f"Left room: {room_id}")

                # Clean up tracking
                if room_id in self._rooms:
                    del self._rooms[room_id]

                # Remove from direct rooms if applicable
                for user_id, rid in list(self._direct_rooms.items()):
                    if rid == room_id:
                        del self._direct_rooms[user_id]

                return True
            else:
                logger.error(f"Failed to leave room: {response}")
                return False

        except Exception as e:
            logger.error(f"Error leaving Matrix room: {e}", exc_info=True)
            return False

    async def send_typing(self, room_id: str, typing: bool = True) -> None:
        """
        Send typing indicator to a room.

        Args:
            room_id: Room ID
            typing: Whether user is typing
        """
        if not self.client:
            return

        try:
            await self.client.room_typing(room_id, typing=typing, timeout=MATRIX_TYPING_TIMEOUT)
        except Exception as e:
            logger.debug(f"Error sending typing indicator: {e}")

    def get_rooms(self) -> List[JarvisMatrixRoom]:
        """Get list of joined rooms."""
        return list(self._rooms.values())

    def get_room(self, room_id: str) -> Optional[JarvisMatrixRoom]:
        """Get room by ID."""
        return self._rooms.get(room_id)

    def is_connected(self) -> bool:
        """Check if connected and syncing."""
        return self.state == MatrixConnectionState.SYNCING

    # Private methods

    def _set_state(self, state: MatrixConnectionState) -> None:
        """Update connection state and notify callback."""
        old_state = self.state
        self.state = state

        if old_state != state:
            logger.debug(f"Matrix state change: {old_state.value} -> {state.value}")
            if self.on_state_change_callback:
                if asyncio.iscoroutinefunction(self.on_state_change_callback):
                    task = asyncio.create_task(self.on_state_change_callback(state))
                    self._callback_tasks.add(task)
                    task.add_done_callback(lambda t: self._callback_tasks.discard(t))
                else:
                    self.on_state_change_callback(state)

    async def _start_sync(self) -> None:
        """Start the background sync loop."""
        self._running = True
        self._set_state(MatrixConnectionState.SYNCING)

        # Register callbacks
        if self.client:
            self.client.add_event_callback(self._on_message, RoomMessageText)
            self.client.add_event_callback(self._on_invite, InviteMemberEvent)

        # Start sync task
        self._sync_task = asyncio.create_task(self._sync_loop())
        logger.info("Matrix sync started")

    async def _sync_loop(self) -> None:
        """Background sync loop for receiving events."""
        retry_count = 0

        while self._running:
            try:
                if not self.client:
                    break

                # Perform sync
                response = await self.client.sync(
                    timeout=self.config.sync_timeout, full_state=False
                )

                if isinstance(response, SyncResponse):
                    # Update room cache
                    await self._process_sync_response(response)
                    retry_count = 0
                else:
                    logger.warning(f"Sync returned non-success: {response}")
                    retry_count += 1

                    if retry_count >= MATRIX_RETRY_ATTEMPTS:
                        logger.error("Max sync retries reached")
                        self._set_state(MatrixConnectionState.ERROR)
                        break

                    await asyncio.sleep(MATRIX_RETRY_DELAY)

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Sync error: {e}", exc_info=True)
                retry_count += 1

                if retry_count >= MATRIX_RETRY_ATTEMPTS:
                    logger.error("Max sync retries reached")
                    self._set_state(MatrixConnectionState.ERROR)
                    break

                await asyncio.sleep(MATRIX_RETRY_DELAY)

        logger.info("Matrix sync loop ended")

    async def _process_sync_response(self, response: SyncResponse) -> None:
        """Process sync response and update room cache."""
        if not self.client:
            return

        # Update joined rooms
        for room_id, room_info in response.rooms.join.items():
            nio_room = self.client.rooms.get(room_id)
            if nio_room:
                matrix_room = JarvisMatrixRoom(
                    room_id=room_id,
                    name=nio_room.display_name or room_id,
                    is_direct=nio_room.is_direct,
                    is_encrypted=nio_room.encrypted,
                    members=[m.user_id for m in nio_room.users.values()],
                    topic=nio_room.topic or "",
                    unread_count=room_info.unread_notifications.notification_count or 0,
                )
                self._rooms[room_id] = matrix_room

    async def _on_message(self, room: NioRoom, event: RoomMessageText) -> None:
        """Handle incoming message event."""
        # Skip our own messages
        if event.sender == self.config.user_id:
            return

        message = MatrixMessage(
            event_id=event.event_id,
            room_id=room.room_id,
            sender=event.sender,
            content=event.body,
            timestamp=datetime.fromtimestamp(event.server_timestamp / 1000),
            is_encrypted=False,  # Would be True for encrypted rooms
            message_type=event.msgtype,
        )

        logger.debug(f"Matrix message from {event.sender} in {room.room_id}")

        if self.on_message_callback:
            if asyncio.iscoroutinefunction(self.on_message_callback):
                await self.on_message_callback(message)
            else:
                self.on_message_callback(message)

    async def _on_invite(self, room: NioRoom, event: InviteMemberEvent) -> None:
        """Handle room invite event."""
        if event.state_key != self.config.user_id:
            return

        logger.info(f"Received invite to {room.room_id} from {event.sender}")

        # Auto-join if configured
        if self.config.auto_join:
            await self.join_room(room.room_id)
        elif self.on_invite_callback:
            if asyncio.iscoroutinefunction(self.on_invite_callback):
                await self.on_invite_callback(room.room_id, event.sender)
            else:
                self.on_invite_callback(room.room_id, event.sender)

    async def _get_or_create_direct_room(self, user_id: str) -> Optional[str]:
        """Get existing direct room with user or create one."""
        # Check cache first
        if user_id in self._direct_rooms:
            return self._direct_rooms[user_id]

        # Check existing rooms
        for room in self._rooms.values():
            if room.is_direct and user_id in room.members:
                self._direct_rooms[user_id] = room.room_id
                return room.room_id

        # Create new direct room
        room_id = await self.create_room(
            name=f"Direct: {user_id}", invite_users=[user_id], is_direct=True
        )

        if room_id:
            self._direct_rooms[user_id] = room_id

        return room_id


class MatrixTransport:
    """
    Transport layer adapter for integrating Matrix with existing Jarvis messaging.

    This class bridges the Matrix backend with the existing Jarvis message
    handling infrastructure, allowing seamless use of both P2P and Matrix
    transports.
    """

    def __init__(self, backend: MatrixBackend, jarvis_uid: str):
        """
        Initialize Matrix transport adapter.

        Args:
            backend: MatrixBackend instance
            jarvis_uid: Local Jarvis user UID
        """
        self.backend = backend
        self.jarvis_uid = jarvis_uid

        # Mapping between Jarvis UIDs and Matrix user IDs
        self._uid_to_matrix: Dict[str, str] = {}
        self._matrix_to_uid: Dict[str, str] = {}

        # Setup callbacks
        self.backend.on_message_callback = self._handle_matrix_message

        # External callbacks
        self.on_message_callback: Optional[Callable] = None

    def register_contact(self, jarvis_uid: str, matrix_user_id: str) -> None:
        """
        Register mapping between Jarvis UID and Matrix user ID.

        Args:
            jarvis_uid: Jarvis contact UID
            matrix_user_id: Matrix user ID (@user:server.org)
        """
        self._uid_to_matrix[jarvis_uid] = matrix_user_id
        self._matrix_to_uid[matrix_user_id] = jarvis_uid
        logger.debug(f"Registered Matrix mapping: {jarvis_uid} <-> {matrix_user_id}")

    def unregister_contact(self, jarvis_uid: str) -> None:
        """Remove contact mapping."""
        if jarvis_uid in self._uid_to_matrix:
            matrix_id = self._uid_to_matrix.pop(jarvis_uid)
            self._matrix_to_uid.pop(matrix_id, None)

    async def send_message(
        self, recipient_uid: str, content: str, message_id: str, timestamp: str
    ) -> bool:
        """
        Send message via Matrix to a registered contact.

        Args:
            recipient_uid: Jarvis UID of recipient
            content: Message content
            message_id: Jarvis message ID
            timestamp: Message timestamp

        Returns:
            True if sent successfully
        """
        matrix_user_id = self._uid_to_matrix.get(recipient_uid)
        if not matrix_user_id:
            logger.warning(f"No Matrix ID registered for UID {recipient_uid}")
            return False

        event_id = await self.backend.send_direct_message(matrix_user_id, content)
        return event_id is not None

    async def _handle_matrix_message(self, message: MatrixMessage) -> None:
        """Handle incoming Matrix message and forward to Jarvis."""
        # Map Matrix sender to Jarvis UID
        sender_uid = self._matrix_to_uid.get(message.sender)

        if not sender_uid:
            logger.debug(f"Unknown Matrix sender: {message.sender}")
            return

        if self.on_message_callback:
            if asyncio.iscoroutinefunction(self.on_message_callback):
                await self.on_message_callback(
                    sender_uid,
                    message.content,
                    message.event_id,
                    message.timestamp.isoformat(),
                )
            else:
                self.on_message_callback(
                    sender_uid,
                    message.content,
                    message.event_id,
                    message.timestamp.isoformat(),
                )

    def is_contact_on_matrix(self, jarvis_uid: str) -> bool:
        """Check if contact has Matrix mapping."""
        return jarvis_uid in self._uid_to_matrix

    def get_matrix_id(self, jarvis_uid: str) -> Optional[str]:
        """Get Matrix ID for Jarvis UID."""
        return self._uid_to_matrix.get(jarvis_uid)

    def get_jarvis_uid(self, matrix_id: str) -> Optional[str]:
        """Get Jarvis UID for Matrix ID."""
        return self._matrix_to_uid.get(matrix_id)
