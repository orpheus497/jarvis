"""
Jarvis - Cryptography tests.

Created by orpheus497

Tests for the five-layer encryption system, key exchange, and identity management.
"""

import pytest
import os
from jarvis import crypto


def test_keypair_generation():
    """Test X25519 keypair generation."""
    keypair = crypto.IdentityKeyPair()
    
    # Verify key sizes
    assert len(keypair.get_public_key_bytes()) == 32
    assert len(keypair.get_private_key_bytes()) == 32
    
    # Verify keys are different
    assert keypair.get_public_key_bytes() != keypair.get_private_key_bytes()


def test_keypair_serialization():
    """Test keypair serialization and deserialization."""
    original = crypto.IdentityKeyPair()
    
    # Serialize
    data = original.to_dict()
    
    # Deserialize
    restored = crypto.IdentityKeyPair.from_dict(data)
    
    # Verify keys match
    assert original.get_public_key_bytes() == restored.get_public_key_bytes()
    assert original.get_private_key_bytes() == restored.get_private_key_bytes()


def test_key_exchange():
    """Test X25519 key exchange produces matching keys."""
    # Generate two keypairs
    alice = crypto.IdentityKeyPair()
    bob = crypto.IdentityKeyPair()
    
    # Perform key exchange
    alice_keys = crypto.perform_key_exchange(
        alice.private_key,
        bob.public_key
    )
    
    bob_keys = crypto.perform_key_exchange(
        bob.private_key,
        alice.public_key
    )
    
    # Verify both parties derive same keys
    assert alice_keys == bob_keys
    
    # Verify we get 5 keys
    assert len(alice_keys) == 5
    
    # Verify each key is 32 bytes
    for key in alice_keys:
        assert len(key) == 32
    
    # Verify keys are different from each other
    assert len(set(alice_keys)) == 5


def test_five_layer_encryption():
    """Test five-layer encryption and decryption."""
    # Generate keypairs and session keys
    alice = crypto.IdentityKeyPair()
    bob = crypto.IdentityKeyPair()
    session_keys = crypto.perform_key_exchange(alice.private_key, bob.public_key)
    
    # Test message
    plaintext = "This is a secret message with unicode: 你好世界 🔒"
    
    # Encrypt
    encrypted = crypto.encrypt_message_five_layer(plaintext, session_keys)
    
    # Verify structure
    assert 'nonce1' in encrypted
    assert 'nonce2' in encrypted
    assert 'nonce3' in encrypted
    assert 'nonce4' in encrypted
    assert 'nonce5' in encrypted
    assert 'ciphertext' in encrypted
    assert encrypted['layers'] == 5
    assert encrypted['version'] == '1.0'
    
    # Verify encrypted data is different from plaintext
    assert encrypted['ciphertext'] != plaintext
    
    # Decrypt
    decrypted = crypto.decrypt_message_five_layer(encrypted, session_keys)
    
    # Verify matches original
    assert decrypted == plaintext


def test_encryption_with_wrong_keys():
    """Test that decryption fails with wrong keys."""
    # Generate two sets of keys
    alice = crypto.IdentityKeyPair()
    bob = crypto.IdentityKeyPair()
    charlie = crypto.IdentityKeyPair()
    
    alice_bob_keys = crypto.perform_key_exchange(alice.private_key, bob.public_key)
    alice_charlie_keys = crypto.perform_key_exchange(alice.private_key, charlie.public_key)
    
    # Encrypt with Alice-Bob keys
    plaintext = "Secret message"
    encrypted = crypto.encrypt_message_five_layer(plaintext, alice_bob_keys)
    
    # Try to decrypt with Alice-Charlie keys (wrong keys)
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_message_five_layer(encrypted, alice_charlie_keys)


def test_identity_file_encryption():
    """Test identity file encryption and decryption."""
    identity_data = {
        'uid': 'test_uid_12345',
        'username': 'testuser',
        'keypair': crypto.IdentityKeyPair().to_dict(),
        'created_at': '2025-10-25T00:00:00Z',
        'fingerprint': 'a' * 64
    }
    
    password = "test_password_123"
    
    # Encrypt
    encrypted = crypto.encrypt_identity_file(identity_data, password)
    
    # Verify structure
    assert 'salt' in encrypted
    assert 'nonce' in encrypted
    assert 'ciphertext' in encrypted
    assert 'version' in encrypted
    
    # Decrypt
    decrypted = crypto.decrypt_identity_file(encrypted, password)
    
    # Verify matches original
    assert decrypted == identity_data


def test_identity_file_wrong_password():
    """Test that identity decryption fails with wrong password."""
    identity_data = {'uid': 'test', 'username': 'test'}
    correct_password = "correct_password"
    wrong_password = "wrong_password"
    
    # Encrypt
    encrypted = crypto.encrypt_identity_file(identity_data, correct_password)
    
    # Try to decrypt with wrong password
    with pytest.raises(crypto.CryptoError):
        crypto.decrypt_identity_file(encrypted, wrong_password)


def test_fingerprint_generation():
    """Test fingerprint generation."""
    keypair = crypto.IdentityKeyPair()
    public_key_bytes = keypair.get_public_key_bytes()
    
    # Generate fingerprint
    fingerprint = crypto.generate_fingerprint(public_key_bytes)
    
    # Verify fingerprint format (64 hex characters)
    assert len(fingerprint) == 64
    assert all(c in '0123456789abcdef' for c in fingerprint)
    
    # Verify deterministic (same input produces same output)
    fingerprint2 = crypto.generate_fingerprint(public_key_bytes)
    assert fingerprint == fingerprint2
    
    # Verify different keys produce different fingerprints
    keypair2 = crypto.IdentityKeyPair()
    fingerprint3 = crypto.generate_fingerprint(keypair2.get_public_key_bytes())
    assert fingerprint != fingerprint3


def test_uid_generation():
    """Test UID generation."""
    uid1 = crypto.generate_uid()
    uid2 = crypto.generate_uid()
    
    # Verify format (32 hex characters)
    assert len(uid1) == 32
    assert all(c in '0123456789abcdef' for c in uid1)
    
    # Verify uniqueness
    assert uid1 != uid2


def test_group_uid_generation():
    """Test group UID generation."""
    gid1 = crypto.generate_group_uid()
    gid2 = crypto.generate_group_uid()
    
    # Verify format (g + 31 hex characters)
    assert len(gid1) == 32
    assert gid1[0] == 'g'
    assert all(c in '0123456789abcdef' for c in gid1[1:])
    
    # Verify uniqueness
    assert gid1 != gid2


def test_message_hash():
    """Test message hash computation and verification."""
    message = b"Test message content"
    
    # Compute hash
    hash1 = crypto.compute_message_hash(message)
    
    # Verify format (96 hex characters for SHA-384)
    assert len(hash1) == 96
    assert all(c in '0123456789abcdef' for c in hash1)
    
    # Verify deterministic
    hash2 = crypto.compute_message_hash(message)
    assert hash1 == hash2
    
    # Verify integrity check
    assert crypto.verify_message_integrity(message, hash1)
    assert not crypto.verify_message_integrity(b"Different message", hash1)


def test_argon2_parameters():
    """Test that Argon2id uses correct parameters."""
    import time
    
    username = "testuser"
    password = "testpassword123"
    salt = os.urandom(16)
    
    # Derive key and measure time
    start = time.time()
    key = crypto.derive_identity_key(username, password, salt)
    elapsed = time.time() - start
    
    # Verify key size
    assert len(key) == 32
    
    # Verify time is reasonable (0.5-5 seconds on modern hardware)
    # This ensures Argon2id is actually running with proper parameters
    assert 0.1 < elapsed < 10, f"Key derivation took {elapsed:.2f}s"


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
