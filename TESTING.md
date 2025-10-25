# Testing Guide for Jarvis

This document describes how to test the Jarvis peer-to-peer encrypted messenger application.

Created by **orpheus497**

---

## Prerequisites

Make sure you have set up the development environment:

```bash
./build.sh
# Or manually:
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install pytest pytest-asyncio pytest-cov
```

---

## Running Tests

### Unit Tests

The unit tests cover core functionality including encryption, key exchange, and data structures:

```bash
source venv/bin/activate  # Windows: venv\Scripts\activate
pytest tests/ -v
```

Expected output:
```
test_crypto.py::test_keypair_generation ... ok
test_crypto.py::test_key_exchange ... ok
test_crypto.py::test_five_layer_encryption ... ok
test_crypto.py::test_identity_file_encryption ... ok
test_crypto.py::test_fingerprint_generation ... ok
test_crypto.py::test_uid_generation ... ok
test_network.py::test_protocol_packing ... ok
test_network.py::test_protocol_unpacking ... ok
test_network.py::test_connection_establishment ... ok

----------------------------------------------------------------------
Ran 9 tests in X.XXXs

OK
```

### Integration Tests

The integration test runs through complete workflows:

```bash
source venv/bin/activate
python tests/test_integration.py
```

This test:
1. Creates two identities
2. Establishes P2P connection
3. Exchanges encrypted messages
4. Creates a group chat
5. Sends group messages
6. Verifies encryption/decryption

### Manual Testing

To manually test the application:

1. Start the application:
   ```bash
   source venv/bin/activate
   python -m jarvis
   ```

2. Test the following workflows:

#### First-Time Setup
- Select "Create Identity"
- Enter username and password
- Confirm password matches
- Set listen port
- Verify UID is generated
- Verify fingerprint is displayed

#### Add Contact
- Press Ctrl+C or click "Add Contact"
- Enter all contact information
- Verify fingerprint is displayed
- Confirm contact appears in list

#### Send Message
- Select a contact from list
- Type a message
- Press Enter or click Send
- Verify message appears in chat

#### Group Chat
- Press Ctrl+G or click "New Group"
- Enter group name
- Create group
- Verify group appears in list
- Send group message
- Verify message reaches all members

#### Settings
- Press Ctrl+S or click Settings
- View identity information
- Verify UID and fingerprint displayed
- Test password change

---

## Testing Security Features

### Encryption Verification

1. Create two instances of Jarvis on same machine (different ports)
2. Add each as contacts
3. Send a message
4. Use Wireshark to capture traffic on loopback interface
5. Verify no plaintext message content visible
6. Verify encrypted data appears as random bytes

### Key Exchange

Test that key exchange completes successfully:

```python
from jarvis.crypto import IdentityKeyPair, perform_key_exchange

# Generate two keypairs
alice_keypair = IdentityKeyPair()
bob_keypair = IdentityKeyPair()

# Perform key exchange
alice_keys = perform_key_exchange(
    alice_keypair.private_key,
    bob_keypair.public_key
)

bob_keys = perform_key_exchange(
    bob_keypair.private_key,
    alice_keypair.public_key
)

# Verify keys match
assert alice_keys == bob_keys
print("✓ Key exchange successful")
```

### Five-Layer Encryption

Test encryption/decryption cycle:

```python
from jarvis.crypto import perform_key_exchange, encrypt_message_five_layer, decrypt_message_five_layer

plaintext = "This is a secret message"

# Encrypt
encrypted = encrypt_message_five_layer(plaintext, session_keys)

# Verify encrypted data looks random
assert 'ciphertext' in encrypted
assert encrypted['ciphertext'] != plaintext
assert encrypted['layers'] == 5

# Decrypt
decrypted = decrypt_message_five_layer(encrypted, session_keys)

# Verify matches original
assert decrypted == plaintext
print("✓ Five-layer encryption working")
```

### Password Security

Test Argon2id parameter compliance:

```python
from jarvis.crypto import derive_identity_key
import time

salt = os.urandom(16)
password = "test_password_123"

# Measure time (should be 1-2 seconds)
start = time.time()
key = derive_identity_key("testuser", password, salt)
elapsed = time.time() - start

assert len(key) == 32  # 256 bits
assert 0.5 < elapsed < 5  # Reasonable time
print(f"✓ Key derivation took {elapsed:.2f} seconds")
```

---

## Platform-Specific Testing

### Linux

```bash
# Test on Ubuntu/Debian/Fedora
./install.sh
./run_jarvis.sh

# Test notifications
# Send yourself a message from another instance
# Verify notification appears

# Test file permissions
ls -la ~/.jarvis/
# Should show 600 (rw-------) for identity.enc
```

### Windows

```cmd
# Test on Windows 10/11
install.bat
run_jarvis.bat

# Test notifications
# Send yourself a message
# Verify Windows notification appears

# Test firewall
# Verify Windows Firewall allows the port
netsh advfirewall firewall show rule name=all | findstr Jarvis
```

### macOS

```bash
# Test on macOS 10.14+
./install.sh
./run_jarvis.sh

# Test notifications
# Send yourself a message
# Verify macOS notification appears

# Test with Apple Silicon (M1/M2)
# Verify all dependencies work with ARM architecture
```

### Termux (Android)

```bash
# Install on Termux
pkg install python git termux-api
git clone https://github.com/orpheus497/jarvis.git
cd jarvis
./install.sh

# Test notifications
# Verify termux-notification works
termux-notification --title "Test" --content "Test message"

# Test background operation
# Run Jarvis, minimize terminal
# Verify notifications still work
```

---

## Performance Testing

Test with various scales:

### Small Scale (2-5 contacts)
- Message send latency
- Connection establishment time
- Memory usage
- CPU usage

### Medium Scale (10-20 contacts)
- Multiple simultaneous connections
- Group chat with 10 members
- Message throughput

### Large Scale (50+ contacts)
- Many contacts in list
- Multiple group chats
- Message history performance

### Stress Testing

```python
# Send 1000 messages rapidly
for i in range(1000):
    send_message(f"Test message {i}")
    
# Verify:
# - No memory leaks
# - No connection drops
# - All messages delivered
# - UI remains responsive
```

---

## Network Testing

### Local Network

Test on same LAN:
1. Two devices on same network
2. Use local IP addresses (192.168.x.x)
3. No port forwarding needed
4. Test connection establishment
5. Test message delivery

### Internet (Port Forwarding)

Test across Internet:
1. Configure port forwarding on router
2. Use public IP address
3. Test connection from external network
4. Verify encryption over Internet

### Firewall Testing

Test with various firewall configurations:
- UFW (Linux)
- Windows Firewall
- macOS Firewall
- Router firewall

Verify:
- Incoming connections allowed on listen port
- Outgoing connections work
- Blocked ports properly rejected

### NAT Traversal

Test behavior behind NAT:
- Both peers behind NAT (requires port forwarding)
- One peer behind NAT (should work)
- No NAT (direct Internet connection, should work)

---

## Security Testing

### Vulnerability Testing

**Input Validation:**
- Test with invalid UIDs
- Test with malformed IP addresses
- Test with out-of-range ports
- Test with extremely long inputs
- Test with special characters

**Protocol Fuzzing:**
- Send malformed packets
- Send oversized payloads
- Send invalid message types
- Verify proper error handling

**Cryptographic Testing:**
- Attempt replay attacks
- Attempt MITM with wrong fingerprint
- Attempt to decrypt without proper keys
- Verify nonce uniqueness

### Penetration Testing

**Network Attacks:**
- Port scanning
- Service enumeration
- Connection flooding
- Packet injection

**Application Attacks:**
- SQL injection (N/A - no database)
- XSS (N/A - terminal UI)
- Buffer overflow attempts
- Directory traversal (file paths)

---

## Troubleshooting Tests

### Connection Issues

**Test Scenarios:**
- Contact offline
- Wrong IP address
- Wrong port
- Firewall blocking
- Router not forwarding
- Wrong fingerprint

**Expected Behavior:**
- Clear error messages
- Graceful failure
- Automatic retry
- Status indicators update

### Data Issues

**Test Scenarios:**
- Corrupted identity file
- Missing data files
- Incorrect file permissions
- Disk full
- Invalid JSON format

**Expected Behavior:**
- Error messages displayed
- Data recovery where possible
- No crashes or data loss

---

## Continuous Testing

For development, set up automatic testing:

```bash
# Install pytest-watch
pip install pytest-watch

# Run tests automatically on file changes
ptw tests/ -- -v
```

---

## Code Coverage

Measure test coverage:

```bash
pip install pytest-cov
pytest tests/ --cov=jarvis --cov-report=html
```

View coverage report:
```bash
# Linux/macOS
open htmlcov/index.html

# Windows
start htmlcov/index.html
```

Expected coverage:
- crypto.py: >95%
- network.py: >85%
- protocol.py: >90%
- contact.py: >90%
- message.py: >90%
- identity.py: >90%
- group.py: >90%
- utils.py: >95%
- ui.py: >50% (UI testing is limited in automated tests)

---

## Test Checklist

Before release, verify:

- [ ] All unit tests pass
- [ ] All integration tests pass
- [ ] Manual testing completed on all platforms
- [ ] Security tests pass
- [ ] Performance tests within acceptable ranges
- [ ] No memory leaks
- [ ] No resource exhaustion
- [ ] Error handling works correctly
- [ ] Documentation is accurate
- [ ] Installation scripts work
- [ ] Uninstallation scripts work
- [ ] Notifications work on all platforms
- [ ] Encryption verified with traffic capture
- [ ] Key exchange works correctly
- [ ] Fingerprint verification works
- [ ] Group chats work
- [ ] Background operation works
- [ ] Settings can be changed
- [ ] Password change works
- [ ] Data persistence works
- [ ] File permissions correct

---

## Reporting Issues

When reporting test failures:

1. **System Information:**
   - OS and version
   - Python version
   - Jarvis version
   - Hardware specs

2. **Steps to Reproduce:**
   - Exact commands run
   - Configuration used
   - Input data

3. **Expected vs Actual:**
   - What should happen
   - What actually happened
   - Error messages

4. **Logs:**
   - Terminal output
   - Error traces
   - Debug information

5. **Environment:**
   - Virtual environment active?
   - Dependencies installed?
   - Network configuration

---

## Automated Testing

### GitHub Actions (CI/CD)

Example workflow for automated testing:

```yaml
name: Test Jarvis

on: [push, pull_request]

jobs:
  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, windows-latest, macos-latest]
        python-version: [3.8, 3.9, 3.10, 3.11]
    
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: ${{ matrix.python-version }}
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install pytest pytest-cov
    - name: Run tests
      run: pytest tests/ -v --cov=jarvis
```

---

Created by **orpheus497**

For more information, see:
- [README.md](README.md) - General documentation
- [SECURITY.md](SECURITY.md) - Security details
- [QUICKREF.md](QUICKREF.md) - Quick reference guide
