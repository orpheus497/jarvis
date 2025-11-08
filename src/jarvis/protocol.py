"""
Jarvis - Network protocol definitions.

Created by orpheus497

This module defines the wire protocol for P2P communication.
All messages are prefixed with a header containing:
- Protocol version (1 byte)
- Message type (2 bytes)
- Payload length (4 bytes)

Total header size: 7 bytes
"""

import json
import struct
from enum import IntEnum
from typing import Dict, Optional, Tuple

from .constants import MAX_MESSAGE_SIZE, MAX_TEXT_MESSAGE_SIZE
from .errors import ErrorCode, NetworkError


class MessageType(IntEnum):
    """Message type definitions."""

    # Connection management
    HANDSHAKE = 1
    HANDSHAKE_RESPONSE = 2
    PING = 3
    PONG = 4
    DISCONNECT = 5

    # Direct messaging
    TEXT_MESSAGE = 10
    MESSAGE_ACK = 11
    MESSAGE_DELIVERED = 12
    MESSAGE_READ = 13

    # Group chat
    GROUP_CREATE = 20
    GROUP_INVITE = 21
    GROUP_JOIN = 22
    GROUP_LEAVE = 23
    GROUP_MESSAGE = 24
    GROUP_MEMBER_LIST = 25
    GROUP_KEY_EXCHANGE = 26

    # Contact management
    CONTACT_REQUEST = 30
    CONTACT_ACCEPT = 31
    CONTACT_REJECT = 32
    CONTACT_REMOVE = 33

    # Status updates
    STATUS_ONLINE = 40
    STATUS_AWAY = 41
    STATUS_OFFLINE = 42
    TYPING_INDICATOR = 43

    # File transfer
    FILE_START = 50
    FILE_CHUNK = 51
    FILE_END = 52
    FILE_CANCEL = 53
    FILE_REQUEST = 54
    FILE_ACCEPT = 55
    FILE_REJECT = 56

    # Voice messages
    VOICE_MESSAGE = 60
    VOICE_CHUNK = 61

    # Message reactions
    REACTION = 70
    REACTION_REMOVE = 71


class Protocol:
    """Network protocol handler."""

    VERSION = 1
    HEADER_SIZE = 7
    MAX_PAYLOAD_SIZE = MAX_MESSAGE_SIZE  # Use constant from config

    @staticmethod
    def pack_message(msg_type: MessageType, payload: Dict) -> bytes:
        """
        Pack a message with protocol header.

        Format:
        - Version: 1 byte (unsigned char)
        - Message Type: 2 bytes (unsigned short, big-endian)
        - Payload Length: 4 bytes (unsigned int, big-endian)
        - Payload: variable length (JSON)

        Returns packed message bytes.

        Raises:
            NetworkError: If message validation fails
            ValueError: If payload is too large
        """
        # Validate message before packing
        Protocol.validate_message(msg_type, payload)

        payload_bytes = json.dumps(payload).encode("utf-8")

        if len(payload_bytes) > Protocol.MAX_PAYLOAD_SIZE:
            raise NetworkError(
                ErrorCode.E207_MESSAGE_TOO_LARGE,
                f"Payload too large: {len(payload_bytes)} bytes",
                {"size": len(payload_bytes), "max_size": Protocol.MAX_PAYLOAD_SIZE},
            )

        header = struct.pack("!BHI", Protocol.VERSION, int(msg_type), len(payload_bytes))

        return header + payload_bytes

    @staticmethod
    def unpack_message(data: bytes) -> Optional[Tuple[MessageType, Dict, int]]:
        """
        Unpack a message from received data.

        Returns:
        - Message type
        - Payload dictionary
        - Total bytes consumed (header + payload)

        Returns None if insufficient data or invalid format.

        Raises:
            NetworkError: If message is invalid
            ValueError: If protocol version unsupported
        """
        if len(data) < Protocol.HEADER_SIZE:
            return None

        # Unpack header
        version, msg_type_int, length = struct.unpack("!BHI", data[: Protocol.HEADER_SIZE])

        # Verify protocol version
        if version != Protocol.VERSION:
            raise NetworkError(
                ErrorCode.E206_INVALID_MESSAGE,
                f"Unsupported protocol version: {version}",
                {"version": version, "expected": Protocol.VERSION},
            )

        # Check if we have complete payload
        if len(data) < Protocol.HEADER_SIZE + length:
            return None

        # Verify payload size
        if length > Protocol.MAX_PAYLOAD_SIZE:
            raise NetworkError(
                ErrorCode.E207_MESSAGE_TOO_LARGE,
                f"Payload too large: {length} bytes",
                {"size": length, "max_size": Protocol.MAX_PAYLOAD_SIZE},
            )

        # Extract and parse payload
        payload_bytes = data[Protocol.HEADER_SIZE : Protocol.HEADER_SIZE + length]

        try:
            payload = json.loads(payload_bytes.decode("utf-8"))
            msg_type = MessageType(msg_type_int)

            # Validate unpacked message
            Protocol.validate_message(msg_type, payload)

            return msg_type, payload, Protocol.HEADER_SIZE + length
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            raise NetworkError(
                ErrorCode.E206_INVALID_MESSAGE, f"Failed to parse message: {e}", {"error": str(e)}
            )
        except ValueError:
            # Invalid message type
            raise NetworkError(
                ErrorCode.E206_INVALID_MESSAGE,
                f"Invalid message type: {msg_type_int}",
                {"type": msg_type_int},
            )

    @staticmethod
    def create_handshake(uid: str, username: str, public_key: str) -> bytes:
        """Create handshake message."""
        payload = {
            "uid": uid,
            "username": username,
            "public_key": public_key,
            "protocol_version": Protocol.VERSION,
        }
        return Protocol.pack_message(MessageType.HANDSHAKE, payload)

    @staticmethod
    def create_handshake_response(
        uid: str, username: str, public_key: str, accepted: bool
    ) -> bytes:
        """Create handshake response message."""
        payload = {"uid": uid, "username": username, "public_key": public_key, "accepted": accepted}
        return Protocol.pack_message(MessageType.HANDSHAKE_RESPONSE, payload)

    @staticmethod
    def create_text_message(
        message_id: str, content: str, timestamp: str, encrypted_data: Dict
    ) -> bytes:
        """Create text message."""
        payload = {
            "message_id": message_id,
            "content": content,
            "timestamp": timestamp,
            "encrypted": encrypted_data,
        }
        return Protocol.pack_message(MessageType.TEXT_MESSAGE, payload)

    @staticmethod
    def create_group_message(
        group_id: str,
        message_id: str,
        sender_uid: str,
        content: str,
        timestamp: str,
        encrypted_data: Dict,
    ) -> bytes:
        """Create group message."""
        payload = {
            "group_id": group_id,
            "message_id": message_id,
            "sender_uid": sender_uid,
            "content": content,
            "timestamp": timestamp,
            "encrypted": encrypted_data,
        }
        return Protocol.pack_message(MessageType.GROUP_MESSAGE, payload)

    @staticmethod
    def create_ping() -> bytes:
        """Create ping message for keepalive."""
        return Protocol.pack_message(MessageType.PING, {})

    @staticmethod
    def create_pong() -> bytes:
        """Create pong response."""
        return Protocol.pack_message(MessageType.PONG, {})

    @staticmethod
    def create_file_start(
        transfer_id: str, filename: str, size: int, checksum: str, total_chunks: int
    ) -> bytes:
        """Create file transfer start message."""
        payload = {
            "transfer_id": transfer_id,
            "filename": filename,
            "size": size,
            "checksum": checksum,
            "total_chunks": total_chunks,
        }
        return Protocol.pack_message(MessageType.FILE_START, payload)

    @staticmethod
    def create_file_chunk(transfer_id: str, chunk_number: int, data: str, checksum: str) -> bytes:
        """Create file chunk message."""
        payload = {
            "transfer_id": transfer_id,
            "chunk_number": chunk_number,
            "data": data,  # base64 encoded
            "checksum": checksum,
        }
        return Protocol.pack_message(MessageType.FILE_CHUNK, payload)

    @staticmethod
    def create_file_end(transfer_id: str, success: bool, error: Optional[str] = None) -> bytes:
        """Create file transfer end message."""
        payload = {"transfer_id": transfer_id, "success": success}
        if error:
            payload["error"] = error
        return Protocol.pack_message(MessageType.FILE_END, payload)

    @staticmethod
    def create_voice_message(message_id: str, duration: float, data: str, timestamp: str) -> bytes:
        """Create voice message."""
        payload = {
            "message_id": message_id,
            "duration": duration,
            "data": data,  # base64 encoded
            "timestamp": timestamp,
        }
        return Protocol.pack_message(MessageType.VOICE_MESSAGE, payload)

    @staticmethod
    def create_reaction(message_id: str, reaction: str, timestamp: str) -> bytes:
        """Create message reaction."""
        payload = {"message_id": message_id, "reaction": reaction, "timestamp": timestamp}
        return Protocol.pack_message(MessageType.REACTION, payload)

    @staticmethod
    def create_typing_indicator(is_typing: bool) -> bytes:
        """Create typing indicator message."""
        payload = {"typing": is_typing}
        return Protocol.pack_message(MessageType.TYPING_INDICATOR, payload)

    @staticmethod
    def validate_message(msg_type: MessageType, payload: Dict) -> None:
        """
        Validate message structure and size.

        Args:
            msg_type: Message type
            payload: Message payload

        Raises:
            NetworkError: If validation fails
        """
        # Check text message size limits
        if msg_type == MessageType.TEXT_MESSAGE:
            content = payload.get("content", "")
            if len(content) > MAX_TEXT_MESSAGE_SIZE:
                raise NetworkError(
                    ErrorCode.E207_MESSAGE_TOO_LARGE,
                    f"Text message too large: {len(content)} > {MAX_TEXT_MESSAGE_SIZE}",
                    {"size": len(content), "max_size": MAX_TEXT_MESSAGE_SIZE},
                )

        # Check required fields for handshake
        if msg_type in (MessageType.HANDSHAKE, MessageType.HANDSHAKE_RESPONSE):
            required = ["uid", "username", "public_key"]
            for field in required:
                if field not in payload:
                    raise NetworkError(
                        ErrorCode.E206_INVALID_MESSAGE,
                        f"Missing required field: {field}",
                        {"message_type": msg_type.name, "field": field},
                    )

        # Check file transfer fields
        if msg_type == MessageType.FILE_START:
            required = ["transfer_id", "filename", "size", "checksum", "total_chunks"]
            for field in required:
                if field not in payload:
                    raise NetworkError(
                        ErrorCode.E206_INVALID_MESSAGE,
                        f"Missing required field: {field}",
                        {"message_type": msg_type.name, "field": field},
                    )

        if msg_type == MessageType.FILE_CHUNK:
            required = ["transfer_id", "chunk_number", "data", "checksum"]
            for field in required:
                if field not in payload:
                    raise NetworkError(
                        ErrorCode.E206_INVALID_MESSAGE,
                        f"Missing required field: {field}",
                        {"message_type": msg_type.name, "field": field},
                    )
