"""
Jarvis - Connection Status Tests.

Created by orpheus497

Tests for connection status indicators and automatic connection establishment.
"""

import pytest
import time
from jarvis import crypto
from jarvis.network import NetworkManager, ConnectionStatus, ConnectionState
from jarvis.contact import Contact


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


def test_connection_status_grey_when_server_offline():
    """Test that connection status is GREY when server is offline."""
    identity = crypto.IdentityKeyPair()
    uid = "user_" + "a" * 24
    username = "TestUser"
    port = 15100
    
    contact_manager = MockContactManager()
    network_manager = NetworkManager(identity, uid, username, port, contact_manager)
    
    # Server not started yet - should be GREY
    contact_uid = "contact_" + "b" * 24
    status = network_manager.get_connection_status(contact_uid)
    assert status == ConnectionStatus.GREY, "Status should be GREY when server is offline"


def test_connection_status_green_when_connected():
    """Test that connection status is GREEN when contact is connected."""
    identity1 = crypto.IdentityKeyPair()
    identity2 = crypto.IdentityKeyPair()
    
    uid1 = "user1_" + "c" * 24
    username1 = "Alice"
    port1 = 15101
    
    uid2 = "user2_" + "d" * 24
    username2 = "Bob"
    port2 = 15102
    
    fingerprint1 = crypto.generate_fingerprint(identity1.get_public_key_bytes())
    fingerprint2 = crypto.generate_fingerprint(identity2.get_public_key_bytes())
    
    contact_manager1 = MockContactManager()
    contact_manager2 = MockContactManager()
    
    contact2_for_1 = Contact(
        uid=uid2,
        username=username2,
        public_key=crypto.base64.b64encode(identity2.get_public_key_bytes()).decode('utf-8'),
        host="127.0.0.1",
        port=port2,
        fingerprint=fingerprint2,
        verified=True
    )
    
    contact1_for_2 = Contact(
        uid=uid1,
        username=username1,
        public_key=crypto.base64.b64encode(identity1.get_public_key_bytes()).decode('utf-8'),
        host="127.0.0.1",
        port=port1,
        fingerprint=fingerprint1,
        verified=True
    )
    
    contact_manager1.add_contact(contact2_for_1)
    contact_manager2.add_contact(contact1_for_2)
    
    network_manager1 = NetworkManager(identity1, uid1, username1, port1, contact_manager1)
    network_manager2 = NetworkManager(identity2, uid2, username2, port2, contact_manager2)
    
    try:
        network_manager1.start_server()
        network_manager2.start_server()
        time.sleep(0.5)
        
        # Before connection - should be RED (server running but not connected)
        status = network_manager1.get_connection_status(uid2)
        assert status == ConnectionStatus.RED, "Status should be RED before connection"
        
        # Establish connection
        network_manager1.connect_to_peer(contact2_for_1)
        time.sleep(1.0)
        
        # After connection - should be GREEN
        status = network_manager1.get_connection_status(uid2)
        assert status == ConnectionStatus.GREEN, "Status should be GREEN when connected"
        
    finally:
        network_manager1.disconnect_all()
        network_manager2.disconnect_all()
        network_manager1.stop_server()
        network_manager2.stop_server()
        time.sleep(0.5)


def test_group_connection_status_green_all_connected():
    """Test group status is GREEN when all members are connected."""
    identity1 = crypto.IdentityKeyPair()
    identity2 = crypto.IdentityKeyPair()
    identity3 = crypto.IdentityKeyPair()
    
    uid1 = "user1_" + "e" * 24
    uid2 = "user2_" + "f" * 24
    uid3 = "user3_" + "g" * 24
    
    port1, port2, port3 = 15103, 15104, 15105
    
    fingerprint1 = crypto.generate_fingerprint(identity1.get_public_key_bytes())
    fingerprint2 = crypto.generate_fingerprint(identity2.get_public_key_bytes())
    fingerprint3 = crypto.generate_fingerprint(identity3.get_public_key_bytes())
    
    contact_manager1 = MockContactManager()
    
    contact2 = Contact(
        uid=uid2, username="User2",
        public_key=crypto.base64.b64encode(identity2.get_public_key_bytes()).decode('utf-8'),
        host="127.0.0.1", port=port2, fingerprint=fingerprint2, verified=True
    )
    contact3 = Contact(
        uid=uid3, username="User3",
        public_key=crypto.base64.b64encode(identity3.get_public_key_bytes()).decode('utf-8'),
        host="127.0.0.1", port=port3, fingerprint=fingerprint3, verified=True
    )
    
    contact_manager1.add_contact(contact2)
    contact_manager1.add_contact(contact3)
    
    network_manager1 = NetworkManager(identity1, uid1, "User1", port1, contact_manager1)
    
    # Add group members
    group_id = "group_test_123"
    network_manager1.add_group_member(group_id, uid1)
    network_manager1.add_group_member(group_id, uid2)
    network_manager1.add_group_member(group_id, uid3)
    
    try:
        network_manager1.start_server()
        time.sleep(0.5)
        
        # No connections - should be RED
        status = network_manager1.get_group_connection_status(group_id)
        assert status == ConnectionStatus.RED, "Group status should be RED with no connections"
        
    finally:
        network_manager1.stop_server()


def test_group_connection_status_amber_partial_connections():
    """Test group status is AMBER when some members are connected."""
    identity1 = crypto.IdentityKeyPair()
    identity2 = crypto.IdentityKeyPair()
    
    uid1 = "user1_" + "h" * 24
    uid2 = "user2_" + "i" * 24
    uid3 = "user3_" + "j" * 24  # This user won't be connected
    
    port1, port2 = 15106, 15107
    
    fingerprint2 = crypto.generate_fingerprint(identity2.get_public_key_bytes())
    
    contact_manager1 = MockContactManager()
    contact_manager2 = MockContactManager()
    
    contact2 = Contact(
        uid=uid2, username="User2",
        public_key=crypto.base64.b64encode(identity2.get_public_key_bytes()).decode('utf-8'),
        host="127.0.0.1", port=port2, fingerprint=fingerprint2, verified=True
    )
    
    contact_manager1.add_contact(contact2)
    
    fingerprint1 = crypto.generate_fingerprint(identity1.get_public_key_bytes())
    contact1 = Contact(
        uid=uid1, username="User1",
        public_key=crypto.base64.b64encode(identity1.get_public_key_bytes()).decode('utf-8'),
        host="127.0.0.1", port=port1, fingerprint=fingerprint1, verified=True
    )
    contact_manager2.add_contact(contact1)
    
    network_manager1 = NetworkManager(identity1, uid1, "User1", port1, contact_manager1)
    network_manager2 = NetworkManager(identity2, uid2, "User2", port2, contact_manager2)
    
    # Add group members (uid3 doesn't exist as a connection)
    group_id = "group_test_456"
    network_manager1.add_group_member(group_id, uid1)
    network_manager1.add_group_member(group_id, uid2)
    network_manager1.add_group_member(group_id, uid3)  # Not connected
    
    try:
        network_manager1.start_server()
        network_manager2.start_server()
        time.sleep(0.5)
        
        # Connect to user2 but not user3
        network_manager1.connect_to_peer(contact2)
        time.sleep(1.0)
        
        # Should be AMBER (some members connected)
        status = network_manager1.get_group_connection_status(group_id)
        assert status == ConnectionStatus.AMBER, "Group status should be AMBER with partial connections"
        
    finally:
        network_manager1.disconnect_all()
        network_manager2.disconnect_all()
        network_manager1.stop_server()
        network_manager2.stop_server()
        time.sleep(0.5)


def test_connect_all_contacts():
    """Test automatic connection to all contacts."""
    identity1 = crypto.IdentityKeyPair()
    identity2 = crypto.IdentityKeyPair()
    identity3 = crypto.IdentityKeyPair()
    
    uid1 = "user1_" + "k" * 24
    uid2 = "user2_" + "l" * 24
    uid3 = "user3_" + "m" * 24
    
    port1, port2, port3 = 15108, 15109, 15110
    
    fingerprint1 = crypto.generate_fingerprint(identity1.get_public_key_bytes())
    fingerprint2 = crypto.generate_fingerprint(identity2.get_public_key_bytes())
    fingerprint3 = crypto.generate_fingerprint(identity3.get_public_key_bytes())
    
    # Setup user1's contacts
    contact_manager1 = MockContactManager()
    contact2 = Contact(
        uid=uid2, username="User2",
        public_key=crypto.base64.b64encode(identity2.get_public_key_bytes()).decode('utf-8'),
        host="127.0.0.1", port=port2, fingerprint=fingerprint2, verified=True
    )
    contact3 = Contact(
        uid=uid3, username="User3",
        public_key=crypto.base64.b64encode(identity3.get_public_key_bytes()).decode('utf-8'),
        host="127.0.0.1", port=port3, fingerprint=fingerprint3, verified=True
    )
    contact_manager1.add_contact(contact2)
    contact_manager1.add_contact(contact3)
    
    # Setup user2 and user3 with user1 as contact
    contact_manager2 = MockContactManager()
    contact_manager3 = MockContactManager()
    
    contact1_for_2 = Contact(
        uid=uid1, username="User1",
        public_key=crypto.base64.b64encode(identity1.get_public_key_bytes()).decode('utf-8'),
        host="127.0.0.1", port=port1, fingerprint=fingerprint1, verified=True
    )
    contact_manager2.add_contact(contact1_for_2)
    contact_manager3.add_contact(contact1_for_2)
    
    network_manager1 = NetworkManager(identity1, uid1, "User1", port1, contact_manager1)
    network_manager2 = NetworkManager(identity2, uid2, "User2", port2, contact_manager2)
    network_manager3 = NetworkManager(identity3, uid3, "User3", port3, contact_manager3)
    
    try:
        network_manager1.start_server()
        network_manager2.start_server()
        network_manager3.start_server()
        time.sleep(0.5)
        
        # Connect to all contacts at once
        results = network_manager1.connect_all_contacts()
        time.sleep(1.5)
        
        # Verify results
        assert uid2 in results, "Should attempt to connect to user2"
        assert uid3 in results, "Should attempt to connect to user3"
        assert results[uid2] == True, "Connection to user2 should succeed"
        assert results[uid3] == True, "Connection to user3 should succeed"
        
        # Verify connections are established
        assert network_manager1.is_connected(uid2), "Should be connected to user2"
        assert network_manager1.is_connected(uid3), "Should be connected to user3"
        
    finally:
        network_manager1.disconnect_all()
        network_manager2.disconnect_all()
        network_manager3.disconnect_all()
        network_manager1.stop_server()
        network_manager2.stop_server()
        network_manager3.stop_server()
        time.sleep(0.5)


if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
