"""
Tests for Matrix protocol backend integration.

Created by orpheus497

This module provides tests for the Matrix backend functionality.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path

from jarvis.matrix_backend import (
    MatrixBackend,
    MatrixConfig,
    MatrixConnectionState,
    MatrixMessage,
    JarvisMatrixRoom,
    MatrixTransport,
)


class TestMatrixConfig:
    """Tests for MatrixConfig dataclass."""

    def test_default_config(self):
        """Test default configuration values."""
        config = MatrixConfig()
        assert config.homeserver_url == "https://matrix.org"
        assert config.user_id == ""
        assert config.device_name == "Jarvis Messenger"
        assert config.e2ee_enabled is True
        assert config.auto_join is True

    def test_custom_config(self):
        """Test custom configuration values."""
        config = MatrixConfig(
            homeserver_url="https://custom.matrix.server",
            user_id="@testuser:custom.matrix.server",
            device_name="TestDevice",
            e2ee_enabled=False,
            auto_join=False,
        )
        assert config.homeserver_url == "https://custom.matrix.server"
        assert config.user_id == "@testuser:custom.matrix.server"
        assert config.device_name == "TestDevice"
        assert config.e2ee_enabled is False
        assert config.auto_join is False


class TestMatrixConnectionState:
    """Tests for MatrixConnectionState enum."""

    def test_states_exist(self):
        """Test that all expected states exist."""
        assert MatrixConnectionState.DISCONNECTED.value == "disconnected"
        assert MatrixConnectionState.CONNECTING.value == "connecting"
        assert MatrixConnectionState.CONNECTED.value == "connected"
        assert MatrixConnectionState.SYNCING.value == "syncing"
        assert MatrixConnectionState.ERROR.value == "error"


class TestMatrixMessage:
    """Tests for MatrixMessage dataclass."""

    def test_message_creation(self):
        """Test creating a MatrixMessage."""
        from datetime import datetime

        msg = MatrixMessage(
            event_id="$test_event_123",
            room_id="!test_room:matrix.org",
            sender="@sender:matrix.org",
            content="Hello, Matrix!",
            timestamp=datetime.now(),
            is_encrypted=True,
            message_type="m.text",
        )
        assert msg.event_id == "$test_event_123"
        assert msg.room_id == "!test_room:matrix.org"
        assert msg.sender == "@sender:matrix.org"
        assert msg.content == "Hello, Matrix!"
        assert msg.is_encrypted is True
        assert msg.message_type == "m.text"

    def test_message_defaults(self):
        """Test MatrixMessage default values."""
        from datetime import datetime

        msg = MatrixMessage(
            event_id="$test_event",
            room_id="!room:matrix.org",
            sender="@user:matrix.org",
            content="Test",
            timestamp=datetime.now(),
        )
        assert msg.is_encrypted is False
        assert msg.message_type == "m.text"
        assert msg.metadata == {}


class TestJarvisMatrixRoom:
    """Tests for JarvisMatrixRoom dataclass."""

    def test_room_creation(self):
        """Test creating a JarvisMatrixRoom."""
        room = JarvisMatrixRoom(
            room_id="!test_room:matrix.org",
            name="Test Room",
            is_direct=False,
            is_encrypted=True,
            members=["@user1:matrix.org", "@user2:matrix.org"],
            topic="Test topic",
            unread_count=5,
        )
        assert room.room_id == "!test_room:matrix.org"
        assert room.name == "Test Room"
        assert room.is_direct is False
        assert room.is_encrypted is True
        assert len(room.members) == 2
        assert room.topic == "Test topic"
        assert room.unread_count == 5

    def test_room_defaults(self):
        """Test JarvisMatrixRoom default values."""
        room = JarvisMatrixRoom(room_id="!room:matrix.org", name="Room")
        assert room.is_direct is False
        assert room.is_encrypted is False
        assert room.members == []
        assert room.topic == ""
        assert room.unread_count == 0


class TestMatrixBackend:
    """Tests for MatrixBackend class."""

    def test_initialization(self, temp_dir):
        """Test MatrixBackend initialization."""
        config = MatrixConfig()
        backend = MatrixBackend(config, data_dir=temp_dir)

        assert backend.config == config
        assert backend.state == MatrixConnectionState.DISCONNECTED
        assert backend.client is None
        assert backend._running is False
        assert backend.data_dir.exists()

    def test_initialization_creates_data_dir(self, temp_dir):
        """Test that initialization creates the data directory."""
        data_dir = temp_dir / "matrix_data"
        config = MatrixConfig()
        backend = MatrixBackend(config, data_dir=data_dir)

        assert data_dir.exists()

    def test_is_connected_when_disconnected(self, temp_dir):
        """Test is_connected returns False when disconnected."""
        config = MatrixConfig()
        backend = MatrixBackend(config, data_dir=temp_dir)

        assert backend.is_connected() is False

    def test_is_connected_when_syncing(self, temp_dir):
        """Test is_connected returns True when syncing."""
        config = MatrixConfig()
        backend = MatrixBackend(config, data_dir=temp_dir)
        backend.state = MatrixConnectionState.SYNCING

        assert backend.is_connected() is True

    def test_get_rooms_empty(self, temp_dir):
        """Test get_rooms returns empty list initially."""
        config = MatrixConfig()
        backend = MatrixBackend(config, data_dir=temp_dir)

        assert backend.get_rooms() == []

    def test_get_room_not_found(self, temp_dir):
        """Test get_room returns None for non-existent room."""
        config = MatrixConfig()
        backend = MatrixBackend(config, data_dir=temp_dir)

        assert backend.get_room("!nonexistent:matrix.org") is None


class TestMatrixTransport:
    """Tests for MatrixTransport class."""

    def test_initialization(self, temp_dir):
        """Test MatrixTransport initialization."""
        config = MatrixConfig()
        backend = MatrixBackend(config, data_dir=temp_dir)
        transport = MatrixTransport(backend, jarvis_uid="test_uid_123")

        assert transport.backend == backend
        assert transport.jarvis_uid == "test_uid_123"

    def test_register_contact(self, temp_dir):
        """Test registering contact mapping."""
        config = MatrixConfig()
        backend = MatrixBackend(config, data_dir=temp_dir)
        transport = MatrixTransport(backend, jarvis_uid="test_uid")

        transport.register_contact("jarvis_contact_uid", "@matrix_user:matrix.org")

        assert transport.is_contact_on_matrix("jarvis_contact_uid") is True
        assert transport.get_matrix_id("jarvis_contact_uid") == "@matrix_user:matrix.org"
        assert transport.get_jarvis_uid("@matrix_user:matrix.org") == "jarvis_contact_uid"

    def test_unregister_contact(self, temp_dir):
        """Test unregistering contact mapping."""
        config = MatrixConfig()
        backend = MatrixBackend(config, data_dir=temp_dir)
        transport = MatrixTransport(backend, jarvis_uid="test_uid")

        transport.register_contact("jarvis_contact_uid", "@matrix_user:matrix.org")
        transport.unregister_contact("jarvis_contact_uid")

        assert transport.is_contact_on_matrix("jarvis_contact_uid") is False
        assert transport.get_matrix_id("jarvis_contact_uid") is None
        assert transport.get_jarvis_uid("@matrix_user:matrix.org") is None

    def test_is_contact_on_matrix_false(self, temp_dir):
        """Test is_contact_on_matrix returns False for unknown contact."""
        config = MatrixConfig()
        backend = MatrixBackend(config, data_dir=temp_dir)
        transport = MatrixTransport(backend, jarvis_uid="test_uid")

        assert transport.is_contact_on_matrix("unknown_uid") is False


@pytest.mark.asyncio
class TestMatrixBackendAsync:
    """Async tests for MatrixBackend."""

    async def test_disconnect_when_not_connected(self, temp_dir):
        """Test disconnect when not connected does nothing harmful."""
        config = MatrixConfig()
        backend = MatrixBackend(config, data_dir=temp_dir)

        # Should not raise
        await backend.disconnect()
        assert backend.state == MatrixConnectionState.DISCONNECTED

    async def test_send_message_when_not_connected(self, temp_dir):
        """Test send_message returns None when not connected."""
        config = MatrixConfig()
        backend = MatrixBackend(config, data_dir=temp_dir)

        result = await backend.send_message("!room:matrix.org", "Hello")
        assert result is None

    async def test_send_direct_message_when_not_connected(self, temp_dir):
        """Test send_direct_message returns None when not connected."""
        config = MatrixConfig()
        backend = MatrixBackend(config, data_dir=temp_dir)

        result = await backend.send_direct_message("@user:matrix.org", "Hello")
        assert result is None

    async def test_create_room_when_not_connected(self, temp_dir):
        """Test create_room returns None when not connected."""
        config = MatrixConfig()
        backend = MatrixBackend(config, data_dir=temp_dir)

        result = await backend.create_room("Test Room")
        assert result is None

    async def test_join_room_when_not_connected(self, temp_dir):
        """Test join_room returns False when not connected."""
        config = MatrixConfig()
        backend = MatrixBackend(config, data_dir=temp_dir)

        result = await backend.join_room("!room:matrix.org")
        assert result is False

    async def test_leave_room_when_not_connected(self, temp_dir):
        """Test leave_room returns False when not connected."""
        config = MatrixConfig()
        backend = MatrixBackend(config, data_dir=temp_dir)

        result = await backend.leave_room("!room:matrix.org")
        assert result is False

    async def test_send_typing_when_not_connected(self, temp_dir):
        """Test send_typing does nothing when not connected."""
        config = MatrixConfig()
        backend = MatrixBackend(config, data_dir=temp_dir)

        # Should not raise
        await backend.send_typing("!room:matrix.org", True)


@pytest.mark.asyncio
class TestMatrixTransportAsync:
    """Async tests for MatrixTransport."""

    async def test_send_message_no_mapping(self, temp_dir):
        """Test send_message returns False when contact not mapped."""
        config = MatrixConfig()
        backend = MatrixBackend(config, data_dir=temp_dir)
        transport = MatrixTransport(backend, jarvis_uid="test_uid")

        result = await transport.send_message(
            "unknown_uid", "Hello", "msg_id_123", "2025-01-01T00:00:00"
        )
        assert result is False
