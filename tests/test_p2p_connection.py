"""
Jarvis - P2P Connection Integration Tests.

Created by orpheus497

Tests for peer-to-peer connection establishment between two instances.
"""

import pytest
import time
import threading
from jarvis import crypto
from jarvis.network import NetworkManager, P2PServer, P2PConnection, ConnectionState
from jarvis.contact import Contact, ContactManager
import tempfile
import os


class MockContactManager:
    """Mock contact manager for testing."""
    
    def __init__(self):
        self.contacts = {}
    
    def add_contact(self, contact):
        self.contacts[contact.uid] = contact
    
    def get_contact(self, uid):
        return self.contacts.get(uid)
    
    def get_contact_by_fingerprint(self, fingerprint):
        for contact in self.contacts.values():
            if contact.fingerprint == fingerprint:
                return contact
        return None
    
    def get_all_contacts(self):
        return list(self.contacts.values())


def test_two_instance_connection():
    """Test connection establishment between two instances."""
    
    # Create identities for two users
    identity1 = crypto.IdentityKeyPair()
    identity2 = crypto.IdentityKeyPair()
    
    # User info
    uid1 = "user1_" + "a" * 24
    username1 = "Alice"
    port1 = 15001
    
    uid2 = "user2_" + "b" * 24
    username2 = "Bob"
    port2 = 15002
    
    # Generate fingerprints
    fingerprint1 = crypto.generate_fingerprint(identity1.get_public_key_bytes())
    fingerprint2 = crypto.generate_fingerprint(identity2.get_public_key_bytes())
    
    # Create contact managers
    contact_manager1 = MockContactManager()
    contact_manager2 = MockContactManager()
    
    # Each user adds the other as a contact
    contact1_for_2 = Contact(
        uid=uid1,
        username=username1,
        public_key=crypto.base64.b64encode(identity1.get_public_key_bytes()).decode('utf-8'),
        host="127.0.0.1",
        port=port1,
        fingerprint=fingerprint1,
        verified=True
    )
    
    contact2_for_1 = Contact(
        uid=uid2,
        username=username2,
        public_key=crypto.base64.b64encode(identity2.get_public_key_bytes()).decode('utf-8'),
        host="127.0.0.1",
        port=port2,
        fingerprint=fingerprint2,
        verified=True
    )
    
    contact_manager1.add_contact(contact2_for_1)
    contact_manager2.add_contact(contact1_for_2)
    
    # Create network managers for both users
    network_manager1 = NetworkManager(identity1, uid1, username1, port1, contact_manager1)
    network_manager2 = NetworkManager(identity2, uid2, username2, port2, contact_manager2)
    
    # Track connection states
    connection_states_1 = []
    connection_states_2 = []
    
    def state_callback_1(uid, state):
        connection_states_1.append((uid, state))
    
    def state_callback_2(uid, state):
        connection_states_2.append((uid, state))
    
    network_manager1.on_connection_state_callback = state_callback_1
    network_manager2.on_connection_state_callback = state_callback_2
    
    # Start both servers
    assert network_manager1.start_server(), "Failed to start server 1"
    assert network_manager2.start_server(), "Failed to start server 2"
    
    # Give servers time to start
    time.sleep(0.5)
    
    try:
        # User 1 connects to User 2
        success = network_manager1.connect_to_peer(contact2_for_1)
        assert success, "Failed to establish connection from user 1 to user 2"
        
        # Wait for connection to be fully established
        time.sleep(1.0)
        
        # Verify connection states
        assert network_manager1.is_connected(uid2), "User 1 should be connected to User 2"
        assert network_manager1.get_connection_state(uid2) == ConnectionState.AUTHENTICATED, \
            "Connection should be in AUTHENTICATED state"
        
        # Verify state transitions were recorded
        assert len(connection_states_1) > 0, "Connection state callbacks should have been called"
        
        # Verify final state is AUTHENTICATED
        final_state = connection_states_1[-1][1]
        assert final_state == ConnectionState.AUTHENTICATED, \
            f"Final state should be AUTHENTICATED, got {final_state}"
        
    finally:
        # Cleanup
        network_manager1.disconnect_all()
        network_manager2.disconnect_all()
        network_manager1.stop_server()
        network_manager2.stop_server()
        time.sleep(0.5)


def test_bidirectional_connection():
    """Test that both sides can establish and maintain a connection."""
    
    # Create identities
    identity1 = crypto.IdentityKeyPair()
    identity2 = crypto.IdentityKeyPair()
    
    uid1 = "user1_" + "c" * 24
    username1 = "Charlie"
    port1 = 15003
    
    uid2 = "user2_" + "d" * 24
    username2 = "Diana"
    port2 = 15004
    
    fingerprint1 = crypto.generate_fingerprint(identity1.get_public_key_bytes())
    fingerprint2 = crypto.generate_fingerprint(identity2.get_public_key_bytes())
    
    contact_manager1 = MockContactManager()
    contact_manager2 = MockContactManager()
    
    contact1_for_2 = Contact(
        uid=uid1,
        username=username1,
        public_key=crypto.base64.b64encode(identity1.get_public_key_bytes()).decode('utf-8'),
        host="127.0.0.1",
        port=port1,
        fingerprint=fingerprint1,
        verified=True
    )
    
    contact2_for_1 = Contact(
        uid=uid2,
        username=username2,
        public_key=crypto.base64.b64encode(identity2.get_public_key_bytes()).decode('utf-8'),
        host="127.0.0.1",
        port=port2,
        fingerprint=fingerprint2,
        verified=True
    )
    
    contact_manager1.add_contact(contact2_for_1)
    contact_manager2.add_contact(contact1_for_2)
    
    network_manager1 = NetworkManager(identity1, uid1, username1, port1, contact_manager1)
    network_manager2 = NetworkManager(identity2, uid2, username2, port2, contact_manager2)
    
    # Track received messages
    messages_received_1 = []
    messages_received_2 = []
    
    def message_callback_1(sender_uid, content, message_id, timestamp):
        messages_received_1.append((sender_uid, content))
    
    def message_callback_2(sender_uid, content, message_id, timestamp):
        messages_received_2.append((sender_uid, content))
    
    network_manager1.on_message_callback = message_callback_1
    network_manager2.on_message_callback = message_callback_2
    
    # Start servers
    assert network_manager1.start_server()
    assert network_manager2.start_server()
    time.sleep(0.5)
    
    try:
        # Establish connection from user 1 to user 2
        assert network_manager1.connect_to_peer(contact2_for_1)
        time.sleep(1.0)
        
        # Verify connection is established
        assert network_manager1.is_connected(uid2)
        
        # Send a message from user 1 to user 2
        message_id = "msg_001"
        timestamp = "2025-10-26T00:00:00Z"
        plaintext = "Hello from Alice!"
        
        success = network_manager1.send_message(uid2, plaintext, message_id, timestamp)
        assert success, "Failed to send message"
        
        # Wait for message to be received
        time.sleep(1.0)
        
        # Verify message was received by user 2
        assert len(messages_received_2) > 0, "User 2 should have received a message"
        sender_uid, received_content = messages_received_2[0]
        assert sender_uid == uid1, f"Expected sender {uid1}, got {sender_uid}"
        assert received_content == plaintext, f"Message content mismatch"
        
    finally:
        network_manager1.disconnect_all()
        network_manager2.disconnect_all()
        network_manager1.stop_server()
        network_manager2.stop_server()
        time.sleep(0.5)


def test_connection_rejection_unknown_contact():
    """Test that connections from unknown contacts are rejected."""
    
    # Create identities
    identity1 = crypto.IdentityKeyPair()
    identity2 = crypto.IdentityKeyPair()
    
    uid1 = "user1_" + "e" * 24
    username1 = "Eve"
    port1 = 15005
    
    uid2 = "user2_" + "f" * 24
    username2 = "Frank"
    port2 = 15006
    
    fingerprint2 = crypto.generate_fingerprint(identity2.get_public_key_bytes())
    
    # User 1 has empty contact list
    contact_manager1 = MockContactManager()
    contact_manager2 = MockContactManager()
    
    # Only user 1 knows about user 2, but not vice versa
    contact2_for_1 = Contact(
        uid=uid2,
        username=username2,
        public_key=crypto.base64.b64encode(identity2.get_public_key_bytes()).decode('utf-8'),
        host="127.0.0.1",
        port=port2,
        fingerprint=fingerprint2,
        verified=True
    )
    
    contact_manager1.add_contact(contact2_for_1)
    # Note: contact_manager2 does NOT have user1 in contacts
    
    network_manager1 = NetworkManager(identity1, uid1, username1, port1, contact_manager1)
    network_manager2 = NetworkManager(identity2, uid2, username2, port2, contact_manager2)
    
    # Start servers
    assert network_manager1.start_server()
    assert network_manager2.start_server()
    time.sleep(0.5)
    
    try:
        # User 1 attempts to connect to User 2
        # This should fail because User 2 doesn't have User 1 in their contacts
        success = network_manager1.connect_to_peer(contact2_for_1)
        
        # The connection may succeed initially but should be rejected
        time.sleep(1.0)
        
        # Verify connection was not established or was rejected
        is_connected = network_manager1.is_connected(uid2)
        assert not is_connected, "Connection should not be established with unknown contact"
        
    finally:
        network_manager1.disconnect_all()
        network_manager2.disconnect_all()
        network_manager1.stop_server()
        network_manager2.stop_server()
        time.sleep(0.5)


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
