# Jarvis 🛡️

**Version 1.0.0** - _A terminal-based peer-to-peer end-to-end encrypted messenger._

Created by **orpheus497**.

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS%20%7C%20Termux-lightgrey)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)

Jarvis is a cross-platform terminal-based messenger that provides complete privacy through peer-to-peer direct connections. Your messages never pass through any server, are never stored in the cloud, and are protected by five layers of military-grade encryption.

```
░        ░░░      ░░░       ░░░  ░░░░  ░░        ░░░      ░░
▒▒▒▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒▒▒▒
▓▓▓▓▓▓▓  ▓▓  ▓▓▓▓  ▓▓       ▓▓▓▓  ▓▓  ▓▓▓▓▓▓  ▓▓▓▓▓▓      ▓▓
█  ████  ██        ██  ███  █████    ███████  ███████████  █
██      ███  ████  ██  ████  █████  █████        ███      ██
```

---

## Philosophy

Your conversations remain completely under your control.

*   **No Cloud:** Messages are transmitted directly between peers, never stored on servers.
*   **No Tracking:** No analytics, no tracking pixels, no telemetry of any kind.
*   **Total Privacy:** Only you and your contacts can read your messages.
*   **No Servers:** Direct peer-to-peer connections using TCP sockets.
*   **Supreme Encryption:** Five-layer encryption alternating AES-256-GCM and ChaCha20-Poly1305.

---

## Features

### Security

*   **Five-Layer Encryption:** Messages are encrypted through five independent layers
    *   Layer 1: AES-256-GCM (first encryption)
    *   Layer 2: ChaCha20-Poly1305 (second encryption)
    *   Layer 3: AES-256-GCM (third encryption)
    *   Layer 4: ChaCha20-Poly1305 (fourth encryption)
    *   Layer 5: AES-256-GCM (fifth encryption)
*   **Key Exchange:** X25519 Elliptic Curve Diffie-Hellman for session key establishment
*   **Key Derivation:** Argon2id with 3 iterations, 64 MB memory, 1 thread
*   **Identity Protection:** Master password never stored on disk, exists only in memory
*   **Fingerprint Verification:** SHA-256 fingerprints for contact authentication
*   **Unique UIDs:** 128-bit cryptographically secure unique identifiers

### Communication

*   **Direct P2P Connections:** No intermediary servers, messages go directly peer-to-peer
*   **Group Chats:** Create encrypted group conversations with multiple participants
*   **Cross-Platform:** Works on Linux, Windows, macOS, and Termux (Android)
*   **Background Operation:** Runs in background with system notifications
*   **Automatic Reconnection:** Handles network interruptions gracefully
*   **Message History:** Encrypted local storage of conversation history

### Interface

*   **Terminal UI:** Beautiful terminal interface using Textual framework
*   **Colorful Display:** Rich colors and formatting for easy reading
*   **Animated ASCII Banner:** An animated ASCII art banner that cycles through a gradient of colors.
*   **Contact Management:** Add, verify, and manage contacts
*   **Status Indicators:** Real-time online/offline status
*   **Unread Badges:** Visual indicators for unread messages
*   **Keyboard Shortcuts:** Efficient keyboard-driven interface

---

## Screenshots

*Coming soon - terminal screenshots*

---

## Installation

### Quick Install

**Linux/macOS:**
```bash
chmod +x install.sh
./install.sh
```

**Windows:**
```cmd
install.bat
```

**Termux (Android):**
```bash
pkg install python git
git clone https://github.com/orpheus497/jarvis.git
cd jarvis
chmod +x install.sh
./install.sh
pkg install termux-api  # For notifications
```

These scripts set up a local Python virtual environment and install all necessary dependencies. After installation, run Jarvis using the generated launcher script:

**Linux/macOS:**
```bash
./run_jarvis.sh
```

**Windows:**
```cmd
run_jarvis.bat
```

### Build From Source

```bash
# Clone repository
git clone https://github.com/orpheus497/jarvis.git
cd jarvis

# Automated build (sets up local venv and installs dependencies)
chmod +x build.sh
./build.sh

# Manual build (if you prefer to manage the venv yourself)
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt
pip install .

# Run
python -m jarvis
```

**Requirements:** 
- Python 3.8 or higher
- textual (MIT License)
- cryptography (Apache 2.0/BSD License)
- argon2-cffi (MIT License)
- rich (MIT License)

All dependencies are installed automatically by the setup scripts.

---

## Uninstallation

To remove the local Jarvis environment (virtual environment and launcher scripts):

**Linux/macOS:** ./uninstall.sh  
**Windows:** uninstall.bat  

*Note: Your identity and message data are NOT deleted for safety. They remain in your data directory.*

**Data Locations:**
- **Linux/macOS:** `~/.jarvis/`
- **Windows:** `%APPDATA%\Jarvis\`
- **Termux:** `~/.jarvis/`

To completely remove all data:
```bash
# Linux/macOS/Termux
rm -rf ~/.jarvis

# Windows
rmdir /s /q "%APPDATA%\Jarvis"
```

---

## Usage

### First-Time Setup

1.  Launch Jarvis using the launcher script or `jarvis` command.
2.  Choose "Create Identity".
3.  Enter your username and master password.
4.  Set your listen port (default: 5000).
5.  **Save your UID** - you'll share this with contacts.

**⚠️ IMPORTANT:** Your master password cannot be recovered. If you forget it, your identity is permanently inaccessible.

### Adding Contacts

1.  Press `Ctrl+C` or click "Add Contact".
2.  Enter contact information:
    *   **UID:** Contact's unique identifier (32 hex characters)
    *   **Username:** Display name
    *   **Public Key:** Contact's public key (base64)
    *   **Host:** IP address or hostname
    *   **Port:** Listen port (default: 5000)
3.  **Verify fingerprint** with contact through a trusted channel (phone call, in person, etc.)
4.  Mark contact as verified after fingerprint confirmation.

### Sharing Your Identity

Share this information with contacts who want to add you:

*   **UID:** Your unique identifier (shown in settings)
*   **Public Key:** Your public key (shown in settings)
*   **Host:** Your IP address or hostname
*   **Port:** Your listen port

### Daily Use

*   **Send Message:** Select contact, type message, press Enter or click Send
*   **Group Chat:** Press `Ctrl+G` to create a group, invite contacts
*   **Status Indicators:** Green dot = online, Red dot = offline
*   **Unread Messages:** Yellow badge shows unread count
*   **Settings:** Press `Ctrl+S` to access settings
*   **Quit:** Press `Ctrl+Q` or `Escape` to exit

### Keyboard Shortcuts

*   `Ctrl+C` - Add Contact
*   `Ctrl+G` - New Group
*   `Ctrl+S` - Settings
*   `Ctrl+Q` - Quit
*   `Enter` - Send Message
*   `Escape` - Cancel/Close

---

## How It Works

### Network Architecture

Jarvis uses direct peer-to-peer TCP connections. When you add a contact, you provide their IP address and port. Jarvis then:

1.  Establishes a TCP connection to the contact's IP:port
2.  Exchanges X25519 public keys
3.  Verifies the contact's fingerprint
4.  Derives five independent session keys using HKDF
5.  Begins encrypted communication

**No servers. No cloud. No third parties.**

### Encryption Process

Each message goes through five layers of encryption:

```
Plaintext
   ↓ AES-256-GCM (Key 1)
Ciphertext 1
   ↓ ChaCha20-Poly1305 (Key 2)
Ciphertext 2
   ↓ AES-256-GCM (Key 3)
Ciphertext 3
   ↓ ChaCha20-Poly1305 (Key 4)
Ciphertext 4
   ↓ AES-256-GCM (Key 5)
Final Ciphertext → Transmitted
```

Decryption reverses this process layer by layer. Each layer uses:
- Independent encryption key (256 bits)
- Unique random nonce (96 bits)
- Authenticated encryption (prevents tampering)

### Group Chats

Group messages are encrypted individually for each member and transmitted peer-to-peer:

1.  Creator establishes a group with a unique group ID
2.  Members are added with their UIDs
3.  When sending a group message, Jarvis:
    *   Encrypts the message with each member's session keys
    *   Transmits directly to each online member
    *   Stores locally for offline members to receive later

---

## Security

### Encryption

*   **Five-Layer Encryption:** Alternating AES-256-GCM and ChaCha20-Poly1305
*   **Key Exchange:** X25519 ECDH (128-bit security level)
*   **Key Derivation:** Argon2id (3 iterations, 64 MB memory)
*   **Session Keys:** Unique per connection, derived via HKDF
*   **Nonces:** 96-bit random nonces, never reused

### Identity Storage

*   **Master Password:** Never stored on disk
*   **Private Keys:** Encrypted with AES-256-GCM using Argon2id-derived key
*   **Local Only:** Identity file never leaves your computer

### Network Security

*   **Fingerprint Verification:** SHA-256 fingerprints for MITM protection
*   **No Telemetry:** Zero network connections except direct P2P
*   **No Tracking:** No analytics, cookies, or tracking of any kind

### Threat Model

**Protected Against:**
- ✓ Brute-force password attacks (Argon2id)
- ✓ Data tampering (authenticated encryption)
- ✓ Man-in-the-middle attacks (fingerprint verification)
- ✓ Network eavesdropping (five-layer encryption)
- ✓ Server compromise (no servers)
- ✓ Data breaches (no cloud storage)

**NOT Protected Against:**
- ✗ Weak master passwords (user responsibility)
- ✗ Keyloggers on compromised systems
- ✗ Physical access to unlocked computer
- ✗ Coercion or legal compulsion

### Best Practices

1.  **Strong Password:** Use a long, unique master password
2.  **Verify Fingerprints:** Always verify contact fingerprints out-of-band
3.  **Secure Systems:** Only use Jarvis on trusted, secure computers
4.  **Network Security:** Use behind a firewall, consider VPN
5.  **Physical Security:** Lock your computer when away
6.  **Regular Backups:** Export your identity file periodically

---

## Networking

### Port Forwarding

For contacts to reach you from the Internet, you may need to configure port forwarding on your router:

1.  Choose a port (default: 5000)
2.  Configure your router to forward that port to your computer's local IP
3.  Share your **public IP address** and port with contacts

**Finding Your Public IP:**
```bash
curl ifconfig.me
```

### Firewall

Ensure your firewall allows incoming connections on your listen port:

**Linux (ufw):**
```bash
sudo ufw allow 5000/tcp
```

**Windows:**
```powershell
netsh advfirewall firewall add rule name="Jarvis" dir=in action=allow protocol=TCP localport=5000
```

### Local Network

For testing or local network use, you can use local IP addresses (192.168.x.x or 10.x.x.x) without port forwarding.

---

## Platform-Specific Notes

### Linux

- Works on all major distributions (Ubuntu, Fedora, Debian, Arch, etc.)
- Notifications via `libnotify` (notify-send)
- Desktop integration via `.desktop` file

### Windows

- Windows 10 and 11 supported
- Native Windows notifications
- PowerShell notification sounds

### macOS

- macOS 10.14+ supported
- Notifications via AppleScript
- Native system sounds

### Termux (Android)

- Install `termux-api` for notifications: `pkg install termux-api`
- Can run in background with notifications
- Lower power usage than GUI apps
- Access via terminal on Android

---

## Troubleshooting

### Cannot Connect to Contact

1.  Verify contact's IP address and port
2.  Check if port forwarding is configured
3.  Verify firewall allows the port
4.  Confirm contact is online and Jarvis is running
5.  Check fingerprint matches

### Notifications Not Working

**Linux:** Install libnotify: `sudo apt install libnotify-bin`  
**Termux:** Install termux-api: `pkg install termux-api`  
**Windows/macOS:** Notifications should work by default

### High CPU Usage

- This is normal during initial connection (key exchange and encryption)
- Argon2id intentionally uses CPU to prevent brute-force attacks
- CPU usage drops to near-zero during normal operation

### Port Already in Use

- Change your listen port in settings
- Or stop the process using the port:
  ```bash
  # Linux/macOS
  lsof -ti:5000 | xargs kill
  
  # Windows
  netstat -ano | findstr :5000
taskkill /PID <PID> /F
  ```

---

## Development

### Setting Up Development Environment

```bash
git clone https://github.com/orpheus497/jarvis.git
cd jarvis
./build.sh  # Sets up dev environment
source venv/bin/activate
```

### Running Tests

```bash
pytest tests/
```

### Code Structure

```
jarvis/
├── src/jarvis/
│   ├── __init__.py       # Package metadata
│   ├── __main__.py       # Entry point
│   ├── crypto.py         # Five-layer encryption
│   ├── network.py        # P2P networking
│   ├── protocol.py       # Wire protocol
│   ├── contact.py        # Contact management
│   ├── message.py        # Message storage
│   ├── identity.py       # Identity management
│   ├── group.py          # Group chat
│   ├── notification.py   # Cross-platform notifications
│   ├── ui.py             # Textual UI
│   └── utils.py          # Utility functions
└── tests/                # Test suite
```

---

## Acknowledgements

This project was designed and originated by **orpheus497**.

### Dependencies

*   **Textual** - Terminal UI framework (MIT License)  
    Created by Will McGugan and Textualize.io team
    
*   **cryptography** - Cryptographic primitives (Apache 2.0/BSD License)  
    Created by the Python Cryptographic Authority
    
*   **argon2-cffi** - Argon2 password hashing (MIT License)  
    Created by Hynek Schlawack
    
*   **Rich** - Terminal formatting (MIT License)  
    Created by Will McGugan

*   **pyperclip** - Cross-platform clipboard support (MIT License)  
    Created by Al Sweigart

### Standards

*   **Keep a Changelog** - For standardized changelog format
*   **Semantic Versioning** - For version numbering
*   **X25519** - Elliptic curve Diffie-Hellman (RFC 7748)
*   **AES-GCM** - Authenticated encryption (NIST SP 800-38D)
*   **ChaCha20-Poly1305** - Authenticated encryption (RFC 8439)
*   **Argon2** - Password hashing (RFC 9106)

### Inspiration

This project is inspired by the philosophy of [pwick](https://github.com/orpheus497/pwick) - complete local control, no external dependencies, and supreme security.

---

## Contributing

Contributions are welcome! Please:

1.  Fork the repository
2.  Create a feature branch
3.  Make your changes
4.  Add tests
5.  Submit a pull request

**Guidelines:**
- Follow existing code style
- Add docstrings to all functions
- Update CHANGELOG.md
- Ensure all tests pass
- No external API dependencies

---

## License

MIT License - see `LICENSE` file for details.

Copyright (c) 2025 orpheus497

---

## Roadmap

Future considerations (not promises):

- [ ] Voice calling (encrypted audio streams)
- [ ] File transfers (encrypted P2P file sharing)
- [ ] Mobile apps (native Android/iOS)
- [ ] Tor integration (anonymous connections)
- [ ] Multi-device sync (encrypted)
- [ ] Contact discovery (via fingerprint)

---

## Contact

Created by **orpheus497**

For bugs and feature requests, please use GitHub Issues.

---

## Disclaimer

Jarvis is provided as-is for lawful purposes only. Users are responsible for:
- Complying with local laws and regulations
- Securing their master passwords
- Verifying contact fingerprints
- Maintaining physical security of devices
- Understanding the threat model and limitations

The author is not responsible for any misuse, data loss, or security breaches.

---

**Remember:** Your security is in your hands. Verify fingerprints. Use strong passwords. Trust no one by default.

**Stay secure. Stay private. Stay free.**