"""
Jarvis - Network protocol tests.

Created by orpheus497

Tests for the network protocol, message packing/unpacking, and connection handling.
"""

import pytest
from jarvis.protocol import Protocol, MessageType


def test_protocol_pack_unpack():
    """Test message packing and unpacking."""
    payload = {
        'uid': 'test_uid',
        'username': 'testuser',
        'message': 'Hello, World!'
    }
    
    # Pack message
    packed = Protocol.pack_message(MessageType.TEXT_MESSAGE, payload)
    
    # Verify structure
    assert len(packed) >= Protocol.HEADER_SIZE
    assert packed[0] == Protocol.VERSION
    
    # Unpack message
    msg_type, unpacked_payload, consumed = Protocol.unpack_message(packed)
    
    # Verify unpacked data
    assert msg_type == MessageType.TEXT_MESSAGE
    assert unpacked_payload == payload
    assert consumed == len(packed)


def test_protocol_version():
    """Test protocol version checking."""
    payload = {'test': 'data'}
    packed = Protocol.pack_message(MessageType.PING, payload)
    
    # Verify version byte
    assert packed[0] == Protocol.VERSION


def test_protocol_incomplete_message():
    """Test handling of incomplete messages."""
    payload = {'test': 'data'}
    packed = Protocol.pack_message(MessageType.PING, payload)
    
    # Try to unpack incomplete message (only header)
    result = Protocol.unpack_message(packed[:5])
    assert result is None
    
    # Try to unpack header only (no payload)
    result = Protocol.unpack_message(packed[:Protocol.HEADER_SIZE])
    assert result is None


def test_protocol_handshake():
    """Test handshake message creation."""
    uid = "test_uid_12345"
    username = "testuser"
    public_key = "test_public_key_base64"
    
    # Create handshake
    handshake = Protocol.create_handshake(uid, username, public_key)
    
    # Unpack and verify
    msg_type, payload, _ = Protocol.unpack_message(handshake)
    
    assert msg_type == MessageType.HANDSHAKE
    assert payload['uid'] == uid
    assert payload['username'] == username
    assert payload['public_key'] == public_key
    assert payload['protocol_version'] == Protocol.VERSION


def test_protocol_text_message():
    """Test text message creation."""
    message_id = "msg_123"
    content = "Hello, this is a test message"
    timestamp = "2025-10-25T00:00:00Z"
    encrypted_data = {
        'nonce1': 'abc',
        'nonce2': 'def',
        'nonce3': 'ghi',
        'nonce4': 'jkl',
        'nonce5': 'mno',
        'ciphertext': 'encrypted_content'
    }
    
    # Create message
    message = Protocol.create_text_message(message_id, content, timestamp, encrypted_data)
    
    # Unpack and verify
    msg_type, payload, _ = Protocol.unpack_message(message)
    
    assert msg_type == MessageType.TEXT_MESSAGE
    assert payload['message_id'] == message_id
    assert payload['content'] == content
    assert payload['timestamp'] == timestamp
    assert payload['encrypted'] == encrypted_data


def test_protocol_group_message():
    """Test group message creation."""
    group_id = "g123456789"
    message_id = "msg_123"
    sender_uid = "sender_uid"
    content = "Group message content"
    timestamp = "2025-10-25T00:00:00Z"
    encrypted_data = {'ciphertext': 'encrypted'}
    
    # Create group message
    message = Protocol.create_group_message(
        group_id, message_id, sender_uid, 
        content, timestamp, encrypted_data
    )
    
    # Unpack and verify
    msg_type, payload, _ = Protocol.unpack_message(message)
    
    assert msg_type == MessageType.GROUP_MESSAGE
    assert payload['group_id'] == group_id
    assert payload['message_id'] == message_id
    assert payload['sender_uid'] == sender_uid
    assert payload['content'] == content


def test_protocol_ping_pong():
    """Test ping/pong messages."""
    # Create ping
    ping = Protocol.create_ping()
    msg_type, _, _ = Protocol.unpack_message(ping)
    assert msg_type == MessageType.PING
    
    # Create pong
    pong = Protocol.create_pong()
    msg_type, _, _ = Protocol.unpack_message(pong)
    assert msg_type == MessageType.PONG


def test_protocol_max_payload_size():
    """Test maximum payload size enforcement."""
    # Create payload larger than max size
    huge_payload = {'data': 'x' * (Protocol.MAX_PAYLOAD_SIZE + 1)}
    
    # Should raise ValueError
    with pytest.raises(ValueError):
        Protocol.pack_message(MessageType.TEXT_MESSAGE, huge_payload)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
