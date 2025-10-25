"""
Jarvis - Integration tests.

Created by orpheus497

End-to-end integration tests for complete workflows.
"""

import pytest
import os
import tempfile
from jarvis.identity import IdentityManager
from jarvis.contact import ContactManager, Contact
from jarvis.message import MessageStore, Message
from jarvis.group import GroupManager
from jarvis import crypto


def test_identity_creation_and_loading():
    """Test complete identity creation and loading workflow."""
    with tempfile.TemporaryDirectory() as tmpdir:
        identity_file = os.path.join(tmpdir, 'identity.enc')
        manager = IdentityManager(identity_file)
        
        # Create identity
        username = "testuser"
        password = "testpassword123"
        identity = manager.create_identity(username, password)
        
        # Verify identity created
        assert identity.username == username
        assert len(identity.uid) == 32
        assert len(identity.fingerprint) == 64
        assert os.path.exists(identity_file)
        
        # Create new manager and load identity
        manager2 = IdentityManager(identity_file)
        loaded = manager2.load_identity(password)
        
        # Verify loaded identity matches
        assert loaded.username == identity.username
        assert loaded.uid == identity.uid
        assert loaded.fingerprint == identity.fingerprint


def test_contact_management_workflow():
    """Test complete contact management workflow."""
    with tempfile.TemporaryDirectory() as tmpdir:
        contacts_file = os.path.join(tmpdir, 'contacts.json')
        manager = ContactManager(contacts_file)
        
        # Create contact
        keypair = crypto.IdentityKeyPair()
        contact = Contact(
            uid=crypto.generate_uid(),
            username="friend",
            public_key=crypto.generate_secure_token(32),
            host="192.168.1.100",
            port=5000,
            fingerprint=crypto.generate_fingerprint(keypair.get_public_key_bytes())
        )
        
        # Add contact
        assert manager.add_contact(contact)
        assert not manager.add_contact(contact)  # Duplicate should fail
        
        # Get contact
        retrieved = manager.get_contact(contact.uid)
        assert retrieved.username == contact.username
        assert retrieved.host == contact.host
        
        # Mark verified
        assert manager.mark_verified(contact.uid)
        verified = manager.get_contact(contact.uid)
        assert verified.verified
        
        # Remove contact
        assert manager.remove_contact(contact.uid)
        assert manager.get_contact(contact.uid) is None


def test_message_storage_workflow():
    """Test complete message storage workflow."""
    with tempfile.TemporaryDirectory() as tmpdir:
        messages_file = os.path.join(tmpdir, 'messages.json')
        store = MessageStore(messages_file)
        
        contact_uid = crypto.generate_uid()
        
        # Add messages
        msg1 = Message(contact_uid, "Hello", sent_by_me=True)
        msg2 = Message(contact_uid, "Hi there", sent_by_me=False)
        msg3 = Message(contact_uid, "How are you?", sent_by_me=True)
        
        store.add_message(msg1)
        store.add_message(msg2)
        store.add_message(msg3)
        
        # Get conversation
        conversation = store.get_conversation(contact_uid)
        assert len(conversation) == 3
        
        # Check unread count
        unread = store.get_unread_count(contact_uid)
        assert unread == 1  # Only msg2 is from contact and unread
        
        # Mark as read
        store.mark_as_read(contact_uid)
        unread = store.get_unread_count(contact_uid)
        assert unread == 0


def test_group_chat_workflow():
    """Test complete group chat workflow."""
    with tempfile.TemporaryDirectory() as tmpdir:
        groups_file = os.path.join(tmpdir, 'groups.json')
        manager = GroupManager(groups_file)
        
        # Create identity
        keypair = crypto.IdentityKeyPair()
        creator_uid = crypto.generate_uid()
        
        # Create group
        group = manager.create_group(
            name="Test Group",
            creator_uid=creator_uid,
            creator_username="creator",
            creator_public_key="pubkey",
            creator_fingerprint=crypto.generate_fingerprint(keypair.get_public_key_bytes())
        )
        
        # Verify group created
        assert group.name == "Test Group"
        assert group.creator_uid == creator_uid
        assert len(group.members) == 1  # Creator is member
        assert group.is_admin(creator_uid)
        
        # Add member
        from jarvis.group import GroupMember
        member = GroupMember(
            uid=crypto.generate_uid(),
            username="member1",
            public_key="pubkey2",
            fingerprint="fingerprint2"
        )
        manager.add_member_to_group(group.group_id, member)
        
        # Verify member added
        retrieved = manager.get_group(group.group_id)
        assert len(retrieved.members) == 2


def test_end_to_end_encryption_workflow():
    """Test complete end-to-end encryption workflow."""
    # Alice and Bob create identities
    alice_keypair = crypto.IdentityKeyPair()
    bob_keypair = crypto.IdentityKeyPair()
    
    # Exchange public keys (out of band)
    alice_public = alice_keypair.get_public_key_bytes()
    bob_public = bob_keypair.get_public_key_bytes()
    
    # Generate fingerprints
    alice_fingerprint = crypto.generate_fingerprint(alice_public)
    bob_fingerprint = crypto.generate_fingerprint(bob_public)
    
    # Both parties verify fingerprints (out of band)
    # In real use, this would be done via phone call or in person
    
    # Perform key exchange
    alice_session_keys = crypto.perform_key_exchange(
        alice_keypair.private_key,
        bob_keypair.public_key
    )
    
    bob_session_keys = crypto.perform_key_exchange(
        bob_keypair.private_key,
        alice_keypair.public_key
    )
    
    # Verify both derive same keys
    assert alice_session_keys == bob_session_keys
    
    # Alice sends message to Bob
    plaintext = "Secret message from Alice to Bob"
    encrypted = crypto.encrypt_message_five_layer(plaintext, alice_session_keys)
    
    # Bob receives and decrypts
    decrypted = crypto.decrypt_message_five_layer(encrypted, bob_session_keys)
    
    # Verify message received correctly
    assert decrypted == plaintext


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
