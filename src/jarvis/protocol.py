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
from typing import Dict, Optional, Tuple
from enum import IntEnum


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


class Protocol:
    """Network protocol handler."""
    
    VERSION = 1
    HEADER_SIZE = 7
    MAX_PAYLOAD_SIZE = 10 * 1024 * 1024  # 10 MB max payload
    
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
        """
        payload_bytes = json.dumps(payload).encode('utf-8')
        
        if len(payload_bytes) > Protocol.MAX_PAYLOAD_SIZE:
            raise ValueError(f"Payload too large: {len(payload_bytes)} bytes")
        
        header = struct.pack(
            '!BHI',
            Protocol.VERSION,
            int(msg_type),
            len(payload_bytes)
        )
        
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
        """
        if len(data) < Protocol.HEADER_SIZE:
            return None
        
        # Unpack header
        version, msg_type_int, length = struct.unpack('!BHI', data[:Protocol.HEADER_SIZE])
        
        # Verify protocol version
        if version != Protocol.VERSION:
            raise ValueError(f"Unsupported protocol version: {version}")
        
        # Check if we have complete payload
        if len(data) < Protocol.HEADER_SIZE + length:
            return None
        
        # Verify payload size
        if length > Protocol.MAX_PAYLOAD_SIZE:
            raise ValueError(f"Payload too large: {length} bytes")
        
        # Extract and parse payload
        payload_bytes = data[Protocol.HEADER_SIZE:Protocol.HEADER_SIZE + length]
        
        try:
            payload = json.loads(payload_bytes.decode('utf-8'))
            msg_type = MessageType(msg_type_int)
            return msg_type, payload, Protocol.HEADER_SIZE + length
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as e:
            raise ValueError(f"Failed to parse message: {e}")
    
    @staticmethod
    def create_handshake(uid: str, username: str, public_key: str) -> bytes:
        """Create handshake message."""
        payload = {
            'uid': uid,
            'username': username,
            'public_key': public_key,
            'protocol_version': Protocol.VERSION
        }
        return Protocol.pack_message(MessageType.HANDSHAKE, payload)
    
    @staticmethod
    def create_handshake_response(uid: str, username: str, public_key: str, accepted: bool) -> bytes:
        """Create handshake response message."""
        payload = {
            'uid': uid,
            'username': username,
            'public_key': public_key,
            'accepted': accepted
        }
        return Protocol.pack_message(MessageType.HANDSHAKE_RESPONSE, payload)
    
    @staticmethod
    def create_text_message(message_id: str, content: str, timestamp: str, encrypted_data: Dict) -> bytes:
        """Create text message."""
        payload = {
            'message_id': message_id,
            'content': content,
            'timestamp': timestamp,
            'encrypted': encrypted_data
        }
        return Protocol.pack_message(MessageType.TEXT_MESSAGE, payload)
    
    @staticmethod
    def create_group_message(group_id: str, message_id: str, sender_uid: str, 
                            content: str, timestamp: str, encrypted_data: Dict) -> bytes:
        """Create group message."""
        payload = {
            'group_id': group_id,
            'message_id': message_id,
            'sender_uid': sender_uid,
            'content': content,
            'timestamp': timestamp,
            'encrypted': encrypted_data
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
