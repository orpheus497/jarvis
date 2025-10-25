"""
Jarvis - UI tests.

Created by orpheus497

Tests for UI components including LinkCodeGenerator,
keyboard shortcuts, and modal screen handlers.
"""

import pytest
import tempfile
import os
import base64
from jarvis.ui import LinkCodeGenerator
from jarvis.identity import IdentityManager, Identity
from jarvis.contact import ContactManager, Contact
from jarvis import crypto


def test_link_code_generation():
    """Test that LinkCodeGenerator creates jarvis:// link codes."""
    # Create a test identity
    with tempfile.TemporaryDirectory() as tmpdir:
        identity_file = os.path.join(tmpdir, 'identity.enc')
        manager = IdentityManager(identity_file)
        identity = manager.create_identity("testuser", "testpass123", 5000)
        
        # Generate link code
        link_code = LinkCodeGenerator.generate_link_code(identity, "192.168.1.100")
        
        # Verify format
        assert link_code.startswith("jarvis://")
        assert len(link_code) > 10
        
        # Verify it's parseable
        data = LinkCodeGenerator.parse_link_code(link_code)
        assert data is not None
        assert data['uid'] == identity.uid
        assert data['username'] == identity.username
        assert data['host'] == "192.168.1.100"
        assert data['port'] == 5000


def test_link_code_parsing():
    """Test that LinkCodeGenerator correctly parses link codes."""
    # Create a test identity
    with tempfile.TemporaryDirectory() as tmpdir:
        identity_file = os.path.join(tmpdir, 'identity.enc')
        manager = IdentityManager(identity_file)
        identity = manager.create_identity("alice", "password123", 5001)
        
        # Generate and parse link code
        link_code = LinkCodeGenerator.generate_link_code(identity, "10.0.0.5")
        data = LinkCodeGenerator.parse_link_code(link_code)
        
        # Verify all fields
        assert data['uid'] == identity.uid
        assert data['username'] == "alice"
        assert data['fingerprint'] == identity.fingerprint
        assert data['host'] == "10.0.0.5"
        assert data['port'] == 5001
        
        # Verify public key is valid base64
        public_key_bytes = base64.b64decode(data['public_key'])
        assert len(public_key_bytes) == 32


def test_link_code_invalid():
    """Test that invalid link codes are rejected."""
    # Test various invalid inputs
    invalid_codes = [
        "invalid",
        "http://example.com",
        "jarvis://",
        "jarvis://invalid_base64!@#$",
        "jarvis://YWJj",  # Valid base64 but invalid JSON
    ]
    
    for code in invalid_codes:
        result = LinkCodeGenerator.parse_link_code(code)
        assert result is None, f"Should reject invalid code: {code}"


def test_contact_linking_via_link_code():
    """Test adding a contact via link code."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create two identities
        identity1_file = os.path.join(tmpdir, 'identity1.enc')
        manager1 = IdentityManager(identity1_file)
        alice = manager1.create_identity("alice", "pass1", 5001)
        
        identity2_file = os.path.join(tmpdir, 'identity2.enc')
        manager2 = IdentityManager(identity2_file)
        bob = manager2.create_identity("bob", "pass2", 5002)
        
        # Bob generates a link code
        bob_link = LinkCodeGenerator.generate_link_code(bob, "192.168.1.50")
        
        # Alice adds Bob via link code
        contacts_file = os.path.join(tmpdir, 'contacts.json')
        contact_manager = ContactManager(contacts_file)
        
        # Parse link code and create contact
        data = LinkCodeGenerator.parse_link_code(bob_link)
        assert data is not None
        
        contact = Contact(
            uid=data['uid'],
            username=data['username'],
            public_key=data['public_key'],
            host=data['host'],
            port=data['port'],
            fingerprint=data['fingerprint']
        )
        
        # Add contact
        success = contact_manager.add_contact(contact)
        assert success
        
        # Verify contact was added
        retrieved = contact_manager.get_contact(bob.uid)
        assert retrieved is not None
        assert retrieved.username == "bob"
        assert retrieved.host == "192.168.1.50"
        assert retrieved.port == 5002


def test_contact_manual_entry():
    """Test adding a contact manually (without link code)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a test identity
        identity_file = os.path.join(tmpdir, 'identity.enc')
        manager = IdentityManager(identity_file)
        identity = manager.create_identity("testuser", "pass", 5000)
        
        # Get shareable info
        public_key_b64 = base64.b64encode(
            identity.keypair.get_public_key_bytes()
        ).decode('utf-8')
        
        # Manually create contact
        contacts_file = os.path.join(tmpdir, 'contacts.json')
        contact_manager = ContactManager(contacts_file)
        
        contact = Contact(
            uid=identity.uid,
            username=identity.username,
            public_key=public_key_b64,
            host="example.com",
            port=5000,
            fingerprint=identity.fingerprint
        )
        
        # Add contact
        success = contact_manager.add_contact(contact)
        assert success
        
        # Verify contact
        retrieved = contact_manager.get_contact(identity.uid)
        assert retrieved is not None
        assert retrieved.username == identity.username
        assert retrieved.host == "example.com"


def test_link_code_with_different_hosts():
    """Test link code generation with various host types."""
    with tempfile.TemporaryDirectory() as tmpdir:
        identity_file = os.path.join(tmpdir, 'identity.enc')
        manager = IdentityManager(identity_file)
        identity = manager.create_identity("user", "pass", 5000)
        
        # Test different host formats
        hosts = [
            "192.168.1.1",
            "10.0.0.5",
            "example.com",
            "localhost",
            "my-server.local",
        ]
        
        for host in hosts:
            link_code = LinkCodeGenerator.generate_link_code(identity, host)
            data = LinkCodeGenerator.parse_link_code(link_code)
            
            assert data is not None
            assert data['host'] == host


def test_link_code_with_different_ports():
    """Test link code generation with various ports."""
    with tempfile.TemporaryDirectory() as tmpdir:
        identity_file = os.path.join(tmpdir, 'identity.enc')
        manager = IdentityManager(identity_file)
        
        # Test different ports
        ports = [5000, 8080, 3000, 9999, 1337]
        
        for port in ports:
            identity = manager.create_identity("user", "pass", port)
            link_code = LinkCodeGenerator.generate_link_code(identity, "localhost")
            data = LinkCodeGenerator.parse_link_code(link_code)
            
            assert data is not None
            assert data['port'] == port
            
            # Reset for next iteration
            os.remove(identity_file)


def test_fingerprint_in_link_code():
    """Test that fingerprint is included and valid in link code."""
    with tempfile.TemporaryDirectory() as tmpdir:
        identity_file = os.path.join(tmpdir, 'identity.enc')
        manager = IdentityManager(identity_file)
        identity = manager.create_identity("user", "pass", 5000)
        
        # Generate link code
        link_code = LinkCodeGenerator.generate_link_code(identity, "localhost")
        data = LinkCodeGenerator.parse_link_code(link_code)
        
        # Verify fingerprint matches
        assert data['fingerprint'] == identity.fingerprint
        
        # Verify fingerprint format (should be hex string)
        assert len(data['fingerprint']) == 64  # SHA-256 = 64 hex chars
        assert all(c in '0123456789abcdef' for c in data['fingerprint'])


def test_link_code_contains_username():
    """Test that username is preserved in link code."""
    with tempfile.TemporaryDirectory() as tmpdir:
        identity_file = os.path.join(tmpdir, 'identity.enc')
        manager = IdentityManager(identity_file)
        
        # Test various usernames
        usernames = ["alice", "bob123", "user_name", "test-user"]
        
        for username in usernames:
            identity = manager.create_identity(username, "pass", 5000)
            link_code = LinkCodeGenerator.generate_link_code(identity, "localhost")
            data = LinkCodeGenerator.parse_link_code(link_code)
            
            assert data['username'] == username
            
            # Reset for next iteration
            os.remove(identity_file)


def test_link_code_roundtrip():
    """Test that link code can be generated and parsed back correctly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create identity
        identity_file = os.path.join(tmpdir, 'identity.enc')
        manager = IdentityManager(identity_file)
        identity = manager.create_identity("roundtrip_test", "password", 7777)
        
        # Generate link code
        original_host = "test.example.com"
        link_code = LinkCodeGenerator.generate_link_code(identity, original_host)
        
        # Parse it back
        data = LinkCodeGenerator.parse_link_code(link_code)
        
        # Verify all data matches
        assert data['uid'] == identity.uid
        assert data['username'] == identity.username
        assert data['fingerprint'] == identity.fingerprint
        assert data['host'] == original_host
        assert data['port'] == identity.listen_port
        
        # Verify public key matches
        original_pubkey = base64.b64encode(
            identity.keypair.get_public_key_bytes()
        ).decode('utf-8')
        assert data['public_key'] == original_pubkey
