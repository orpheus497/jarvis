#!/usr/bin/env python3
"""
UI Interaction Verification Script

This script verifies that all UI components work as expected:
1. LinkCodeGenerator produces jarvis:// codes
2. Contact linking via link code works
3. Manual contact entry works
4. Keyboard shortcuts are defined
5. Enter/Escape handlers are present
"""

import sys
import os
import tempfile

# Import from installed package
try:
    from jarvis.ui import (
        LinkCodeGenerator, JarvisApp, LoadIdentityScreen,
        AddContactScreen, CreateGroupScreen, SettingsScreen
    )
    from jarvis.identity import IdentityManager
    from jarvis.contact import ContactManager, Contact
    from jarvis import crypto
except ImportError:
    # Fallback to local path for development
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../src'))
    from jarvis.ui import (
        LinkCodeGenerator, JarvisApp, LoadIdentityScreen,
        AddContactScreen, CreateGroupScreen, SettingsScreen
    )
    from jarvis.identity import IdentityManager
    from jarvis.contact import ContactManager, Contact
    from jarvis import crypto

import base64

# Constants
BANNER_WIDTH = 58


def print_banner(message, style='double'):
    """Print a formatted banner with the given message."""
    if style == 'double':
        print("\n╔" + "=" * BANNER_WIDTH + "╗")
        print("║" + " " * BANNER_WIDTH + "║")
        print("║" + message.center(BANNER_WIDTH) + "║")
        print("║" + " " * BANNER_WIDTH + "║")
        print("╚" + "=" * BANNER_WIDTH + "╝")
    else:
        print("=" * (BANNER_WIDTH + 2))


def test_link_code_generator():
    """Test LinkCodeGenerator functionality."""
    print("=" * 60)
    print("Testing LinkCodeGenerator")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        identity_file = os.path.join(tmpdir, 'identity.enc')
        manager = IdentityManager(identity_file)
        
        # Create test identity
        identity = manager.create_identity('alice', 'password123', 5001)
        
        # Test 1: Generate link code
        print("\n1. Generating link code...")
        link_code = LinkCodeGenerator.generate_link_code(identity, '192.168.1.100')
        print(f"   ✓ Generated: {link_code[:50]}...")
        
        # Test 2: Verify format
        print("\n2. Verifying format...")
        assert link_code.startswith('jarvis://'), "Link code must start with jarvis://"
        print("   ✓ Starts with 'jarvis://'")
        
        # Test 3: Parse link code
        print("\n3. Parsing link code...")
        data = LinkCodeGenerator.parse_link_code(link_code)
        assert data is not None, "Failed to parse link code"
        print("   ✓ Parsed successfully")
        
        # Test 4: Verify data integrity
        print("\n4. Verifying data integrity...")
        assert data['uid'] == identity.uid, "UID mismatch"
        assert data['username'] == 'alice', "Username mismatch"
        assert data['host'] == '192.168.1.100', "Host mismatch"
        assert data['port'] == 5001, "Port mismatch"
        assert data['fingerprint'] == identity.fingerprint, "Fingerprint mismatch"
        print(f"   ✓ UID: {data['uid'][:16]}...")
        print(f"   ✓ Username: {data['username']}")
        print(f"   ✓ Host: {data['host']}")
        print(f"   ✓ Port: {data['port']}")
        print(f"   ✓ Fingerprint: {data['fingerprint'][:16]}...")
        
        # Test 5: Public key verification
        print("\n5. Verifying public key...")
        public_key_bytes = base64.b64decode(data['public_key'])
        assert len(public_key_bytes) == 32, "Public key should be 32 bytes"
        print("   ✓ Public key is valid (32 bytes)")
        
    print("\n" + "=" * 60)
    print("✓ LinkCodeGenerator: ALL TESTS PASSED")
    print("=" * 60)


def test_contact_linking():
    """Test contact linking via link code."""
    print("\n" + "=" * 60)
    print("Testing Contact Linking")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create two identities
        identity1_file = os.path.join(tmpdir, 'identity1.enc')
        manager1 = IdentityManager(identity1_file)
        alice = manager1.create_identity('alice', 'pass1', 5001)
        
        identity2_file = os.path.join(tmpdir, 'identity2.enc')
        manager2 = IdentityManager(identity2_file)
        bob = manager2.create_identity('bob', 'pass2', 5002)
        
        # Test 1: Generate Bob's link code
        print("\n1. Bob generates link code...")
        bob_link = LinkCodeGenerator.generate_link_code(bob, '10.0.0.5')
        print(f"   ✓ Bob's link: {bob_link[:50]}...")
        
        # Test 2: Alice parses Bob's link code
        print("\n2. Alice parses Bob's link code...")
        data = LinkCodeGenerator.parse_link_code(bob_link)
        assert data is not None, "Failed to parse Bob's link code"
        print("   ✓ Parsed successfully")
        
        # Test 3: Alice creates contact from link code
        print("\n3. Alice creates contact from link code...")
        contacts_file = os.path.join(tmpdir, 'contacts.json')
        contact_manager = ContactManager(contacts_file)
        
        contact = Contact(
            uid=data['uid'],
            username=data['username'],
            public_key=data['public_key'],
            host=data['host'],
            port=data['port'],
            fingerprint=data['fingerprint']
        )
        
        success = contact_manager.add_contact(contact)
        assert success, "Failed to add contact"
        print("   ✓ Contact added to Alice's contact list")
        
        # Test 4: Verify contact retrieval
        print("\n4. Verifying contact retrieval...")
        retrieved = contact_manager.get_contact(bob.uid)
        assert retrieved is not None, "Contact not found"
        assert retrieved.username == 'bob', "Username mismatch"
        assert retrieved.host == '10.0.0.5', "Host mismatch"
        print(f"   ✓ Retrieved contact: {retrieved.username}")
        print(f"   ✓ Host: {retrieved.host}")
        print(f"   ✓ Port: {retrieved.port}")
        
    print("\n" + "=" * 60)
    print("✓ Contact Linking: ALL TESTS PASSED")
    print("=" * 60)


def test_manual_contact_entry():
    """Test manual contact entry."""
    print("\n" + "=" * 60)
    print("Testing Manual Contact Entry")
    print("=" * 60)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create identity
        identity_file = os.path.join(tmpdir, 'identity.enc')
        manager = IdentityManager(identity_file)
        identity = manager.create_identity('testuser', 'pass', 5000)
        
        # Test 1: Prepare manual entry data
        print("\n1. Preparing manual entry data...")
        public_key_b64 = base64.b64encode(
            identity.keypair.get_public_key_bytes()
        ).decode('utf-8')
        print("   ✓ Public key encoded")
        
        # Test 2: Create contact manually
        print("\n2. Creating contact manually...")
        contacts_file = os.path.join(tmpdir, 'contacts.json')
        contact_manager = ContactManager(contacts_file)
        
        contact = Contact(
            uid=identity.uid,
            username='manual_contact',
            public_key=public_key_b64,
            host='example.com',
            port=8080,
            fingerprint=identity.fingerprint
        )
        
        success = contact_manager.add_contact(contact)
        assert success, "Failed to add manual contact"
        print("   ✓ Contact added manually")
        
        # Test 3: Verify retrieval
        print("\n3. Verifying manual contact...")
        retrieved = contact_manager.get_contact(identity.uid)
        assert retrieved is not None, "Manual contact not found"
        assert retrieved.username == 'manual_contact', "Username mismatch"
        assert retrieved.host == 'example.com', "Host mismatch"
        assert retrieved.port == 8080, "Port mismatch"
        print(f"   ✓ Username: {retrieved.username}")
        print(f"   ✓ Host: {retrieved.host}")
        print(f"   ✓ Port: {retrieved.port}")
        
    print("\n" + "=" * 60)
    print("✓ Manual Contact Entry: ALL TESTS PASSED")
    print("=" * 60)


def test_ui_bindings():
    """Test that UI bindings are properly defined."""
    print("\n" + "=" * 60)
    print("Testing UI Bindings and Actions")
    print("=" * 60)
    
    # Test 1: Check JarvisApp bindings
    print("\n1. Checking JarvisApp keyboard shortcuts...")
    app_bindings = JarvisApp.BINDINGS
    binding_keys = [b.key for b in app_bindings]
    
    assert 'ctrl+c' in binding_keys, "Ctrl+C binding missing"
    print("   ✓ Ctrl+C - Add Contact")
    
    assert 'ctrl+g' in binding_keys, "Ctrl+G binding missing"
    print("   ✓ Ctrl+G - New Group")
    
    assert 'ctrl+s' in binding_keys, "Ctrl+S binding missing"
    print("   ✓ Ctrl+S - Settings")
    
    assert 'ctrl+q' in binding_keys, "Ctrl+Q binding missing"
    print("   ✓ Ctrl+Q - Quit")
    
    # Test 2: Check action methods exist
    print("\n2. Checking action methods...")
    assert hasattr(JarvisApp, 'action_add_contact'), "action_add_contact missing"
    print("   ✓ action_add_contact defined")
    
    assert hasattr(JarvisApp, 'action_create_group'), "action_create_group missing"
    print("   ✓ action_create_group defined")
    
    assert hasattr(JarvisApp, 'action_settings'), "action_settings missing"
    print("   ✓ action_settings defined")
    
    assert hasattr(JarvisApp, 'action_quit'), "action_quit missing"
    print("   ✓ action_quit defined")
    
    # Test 3: Check modal screen escape bindings
    print("\n3. Checking Escape key bindings in modal screens...")
    
    # All modal screens that should have escape handlers
    modal_screens = [
        LoadIdentityScreen,
        AddContactScreen,
        CreateGroupScreen,
        SettingsScreen
    ]
    
    for screen_class in modal_screens:
        screen_name = screen_class.__name__
        bindings = screen_class.BINDINGS
        binding_keys = [b.key for b in bindings]
        
        assert 'escape' in binding_keys, f"Escape binding missing in {screen_name}"
        assert hasattr(screen_class, 'action_cancel'), f"action_cancel missing in {screen_name}"
        print(f"   ✓ {screen_name}: Escape key and action_cancel defined")
    
    # Test 4: Check input submission handlers
    print("\n4. Checking input submission handlers...")
    
    assert hasattr(LoadIdentityScreen, 'on_input_submitted'), \
        "on_input_submitted missing in LoadIdentityScreen"
    print("   ✓ LoadIdentityScreen.on_input_submitted defined")
    
    assert hasattr(AddContactScreen, 'on_input_submitted'), \
        "on_input_submitted missing in AddContactScreen"
    print("   ✓ AddContactScreen.on_input_submitted defined")
    
    assert hasattr(JarvisApp, 'on_input_submitted'), \
        "on_input_submitted missing in JarvisApp"
    print("   ✓ JarvisApp.on_input_submitted defined")
    
    # Test 5: Check button handlers
    print("\n5. Checking button press handlers...")
    
    assert hasattr(JarvisApp, 'on_button_pressed'), \
        "on_button_pressed missing in JarvisApp"
    print("   ✓ JarvisApp.on_button_pressed defined")
    
    assert hasattr(LoadIdentityScreen, 'on_button_pressed'), \
        "on_button_pressed missing in LoadIdentityScreen"
    print("   ✓ LoadIdentityScreen.on_button_pressed defined")
    
    assert hasattr(AddContactScreen, 'on_button_pressed'), \
        "on_button_pressed missing in AddContactScreen"
    print("   ✓ AddContactScreen.on_button_pressed defined")
    
    print("\n" + "=" * 60)
    print("✓ UI Bindings and Actions: ALL TESTS PASSED")
    print("=" * 60)


def main():
    """Run all verification tests."""
    print_banner("Jarvis UI Interaction Verification")
    
    try:
        test_link_code_generator()
        test_contact_linking()
        test_manual_contact_entry()
        test_ui_bindings()
        
        print_banner("✓ ALL VERIFICATION TESTS PASSED!")
        
        print("\nSummary of Verified Features:")
        print("  ✓ LinkCodeGenerator creates jarvis:// format links")
        print("  ✓ Contact linking via link code works")
        print("  ✓ Manual contact entry works")
        print("  ✓ Keyboard shortcuts defined (Ctrl+C, Ctrl+G, Ctrl+S, Ctrl+Q)")
        print("  ✓ Escape key handlers in all modal screens")
        print("  ✓ Enter key handlers for forms")
        print("  ✓ Send button handler defined")
        print("  ✓ All action methods exist")
        print()
        
        return 0
        
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}\n")
        return 1
    except Exception as e:
        print(f"\n✗ UNEXPECTED ERROR: {e}\n")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
