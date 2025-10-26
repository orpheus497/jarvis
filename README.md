# Jarvis 🛡️

**Version 1.2.0** - _A terminal-based peer-to-peer end-to-end encrypted messenger._

Created by **orpheus497**.

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Version](https://img.shields.io/badge/version-1.2.0-blue)
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
*   **Automatic Connection:** Connects to all contacts, groups, and sessions automatically on login
*   **Connection Status Indicators:** Four-level status system for real-time visibility
    *   **Green:** All connections active (all peers online and connected)
    *   **Amber:** Partial connections (some peers online, messages can be sent/received)
    *   **Red:** No active connections (server running but no peers connected)
    *   **Grey:** Server offline (cannot send or receive messages)
*   **Message History:** Encrypted local storage of conversation history

### Interface

*   **Terminal UI:** Beautiful terminal interface using Textual framework
*   **Colorful Display:** Rich colors and formatting for easy reading
*   **Animated ASCII Banner:** An animated ASCII art banner that cycles through a gradient of colors.
*   **Contact Management:** Add, verify, and manage contacts
*   **Status Indicators:** Real-time online/offline status
*   **Unread Badges:** Visual indicators for unread messages
*   **Keyboard Shortcuts:** Efficient keyboard-driven interface
*   **Lock Feature:** Secure your app with Ctrl+L (keeps connections active)

### Privacy & Data Control

*   **Account Deletion:** Complete account and data deletion with password confirmation
*   **Account Export:** Export complete account including identity, contacts, messages, and groups
*   **Data Management:** Delete individual contacts, messages, or groups
*   **Secure Wipe:** All cryptographic keys and sensitive data removed on deletion
*   **User Control:** Full control over your data at all times

---

## Screenshots

The application features a terminal-based UI with real-time connection status, message history, and contact management.

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
- textual >= 0.47.0 (MIT License)
- cryptography >= 42.0.4 (Apache 2.0/BSD License) - with security fixes
- argon2-cffi >= 23.1.0 (MIT License)
- rich >= 13.7.0 (MIT License)

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
2.  Read the welcome screen carefully - it contains important information.
3.  Choose "Create Identity".
4.  Enter your username (visible to contacts) and a strong master password.
5.  Set your listen port (default: 5000).
6.  **Save your UID** - you'll share this with contacts to allow them to add you.

**⚠️ CRITICAL:** Your master password cannot be recovered. If you forget it, your identity is permanently inaccessible. Write it down in a secure location.

**🔑 Understanding Your Listen Port:**
- This port is used for incoming P2P connections from contacts
- Must be open in your firewall
- May require port forwarding on your router for Internet connections
- Each instance of Jarvis must use a different port on the same machine

### Connecting to Contacts

**How Jarvis Establishes Connections:**

Jarvis automatically connects to all your contacts when you log in. For connections to work:

1. **Both devices must be running Jarvis** and logged in
2. **Network connectivity** must exist between devices:
   - Same device (localhost): Both instances can connect via 127.0.0.1
   - Same LAN: Use local IP addresses (192.168.x.x or 10.x.x.x)
   - Over Internet: Both need public IPs or port forwarding configured
3. **Firewalls must allow** the listen port (default: 5000)
4. **Each contact must have** the other's correct host information

**Connection Status Indicators:**
- **Green dot (●)**: Contact is online and connected - messages will deliver instantly
- **Red dot (●)**: Contact is offline or not reachable - messages will queue
- **Status display**: Shows "X/Y online" where X is connected and Y is total contacts

**Troubleshooting Connection Issues:**

If contacts don't connect:
1. Verify both devices are running Jarvis and logged in
2. Check the host field contains the correct IP address or hostname
3. Verify the port number matches the contact's listen port
4. Test network connectivity with `ping` or `telnet` to the host:port
5. Ensure firewalls allow incoming connections on the listen port
6. For Internet connections, verify port forwarding is configured
7. Check the connection status display for real-time connection information

### Adding Contacts

**Method 1: Link Code (fastest and recommended)**
1.  Press `Ctrl+C` or click "Add Contact".
2.  Ask your contact to go to Settings and copy their link code.
3.  Paste the link code (jarvis://...) and press "Add Contact".
4.  Jarvis will automatically attempt to connect to the contact.

**Method 2: Contact Card File**
1.  Press `Ctrl+C` or click "Add Contact".
2.  Click "Import Contact Card" to import a .jcard file.
3.  Contact card files are stored in the contact_cards directory.

**Method 3: Manual Entry**
1.  Press `Ctrl+C` or click "Add Contact".
2.  Enter contact information manually:
    *   **UID:** Contact's unique identifier (32 hex characters)
    *   **Username:** Display name
    *   **Public Key:** Contact's public key (base64)
    *   **Host:** IP address or hostname of contact's device
    *   **Port:** Contact's listen port (default: 5000)
3.  **Verify fingerprint** with contact through a trusted channel (phone call, in person, etc.)
4.  Mark contact as verified after fingerprint confirmation.

**⚠️ Important:** Always verify the fingerprint with your contact through a separate trusted channel to prevent man-in-the-middle attacks.

### Sharing Your Identity

**Method 1: Link Code (easiest)**
*   Go to Settings (`Ctrl+S`) and click "Copy Link Code"
*   Share via any messaging app or email
*   Contact can paste this code directly in Jarvis

**Method 2: Contact Card File**
*   Go to Settings (`Ctrl+S`) and click "Export Contact Card"
*   Contact card is saved to contact_cards directory
*   Share the .jcard file with contacts (via email, USB drive, etc.)

**Method 3: Manual Information**
Share this information with contacts who want to add you:
*   **UID:** Your unique identifier (shown in settings)
*   **Public Key:** Your public key (shown in settings)
*   **Host:** Your IP address or hostname
*   **Port:** Your listen port

### Exporting Your Account

You can export your complete account data (identity, contacts, messages, and groups) for backup purposes:

1.  Go to Settings (`Ctrl+S`)
2.  Click "Export Account"
3.  Account file (.jexport) is saved to account_exports directory
4.  Transfer file securely for backup
5.  Keep the file encrypted and secure

**Benefits:**
*   Complete backup of your account
*   Transfer to a different device
*   Disaster recovery

### Daily Use

*   **Send Message:** Select contact, type message, press Enter or click Send
*   **Group Chat:** Press `Ctrl+G` to create a group, invite contacts
*   **Status Indicators:** Green dot = online, Red dot = offline
*   **Unread Messages:** Yellow badge shows unread count
*   **Settings:** Press `Ctrl+S` to access settings
*   **Contact Info:** Press `Ctrl+I` to view contact or group details
*   **Delete Contact/Group:** Press `Ctrl+D` or use `Ctrl+I` then click Delete button
*   **Copy Data:** All UIDs, fingerprints, and link codes have copy buttons
*   **Export Contact Card:** From Settings screen (only your own card)
*   **Export Account:** From Settings - backup complete account data
*   **Lock App:** Press `Ctrl+L` to lock the application (keeps connections active)
*   **Delete Account:** Access via Settings menu - removes all data permanently
*   **Quit:** Press `Ctrl+Q` or `Escape` to exit

### Keyboard Shortcuts

*   `Ctrl+C` - Add Contact
*   `Ctrl+G` - New Group
*   `Ctrl+S` - Settings
*   `Ctrl+I` - Contact/Group Info
*   `Ctrl+D` - Delete Current Contact/Group
*   `Ctrl+L` - Lock Application
*   `Ctrl+Q` - Quit
*   `Enter` - Send Message
*   `Escape` - Cancel/Close

---

## How It Works

### Architecture

Jarvis uses a **client-server architecture** to ensure persistent connections:

**Background Server Process:**
- Runs continuously in the background (even when UI is closed)
- Maintains all P2P connections with contacts
- Handles message encryption, decryption, and routing
- Manages identity, contacts, groups, and message storage
- Provides IPC interface for client UI processes

**Foreground Client UI:**
- Lightweight user interface process
- Connects to background server via IPC (Inter-Process Communication)
- Displays messages and connection status in real-time
- Can be closed and reopened without disconnecting from contacts
- Multiple UI instances can connect to the same server

**Benefits:**
- **Persistent Connections:** Your connections stay active even when UI is closed
- **Reliable Messaging:** Messages are delivered automatically when contacts come online
- **Multiple Clients:** Run multiple UI windows connecting to the same server
- **Resource Efficient:** Server process uses minimal resources when idle
- **Background Operation:** Continue receiving messages with UI closed

When you start Jarvis:
1. The system checks if a server is already running
2. If not, it automatically starts a background server process
3. The UI connects to the server via local IPC (port 5999)
4. Server authenticates you and maintains P2P connections
5. You can close the UI, and connections remain active in the background

### Network Architecture

Jarvis uses direct peer-to-peer TCP connections. When you add a contact, you provide their IP address and port. The background server then performs the following steps:

1.  Establishes a TCP connection to the contact's IP:port
2.  Exchanges X25519 public keys
3.  Verifies the contact's fingerprint
4.  Derives five independent session keys using HKDF
5.  Begins encrypted communication

**No cloud servers. No intermediaries. No third parties.**

The background server maintains these P2P connections continuously, ensuring your contacts can reach you at any time without requiring the UI to be open.

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

## Server Management

### Background Server

Jarvis runs a background server process that maintains P2P connections. The server:

- Starts automatically when you launch the UI
- Runs independently in the background
- Persists when UI is closed
- Manages all network connections
- Handles message encryption and routing
- Uses minimal resources when idle

### Server Commands

**Check Server Status:**
```bash
# Check if server is running
pgrep -f jarvis-server  # Linux/macOS
tasklist /FI "IMAGENAME eq python*" | findstr jarvis  # Windows
```

**Start Server Manually (Advanced):**
```bash
jarvis-server --data-dir ~/.jarvis --ipc-port 5999
```

**Stop Server:**
The server stops automatically when:
- You quit Jarvis UI and no other clients are connected
- System shuts down
- Manual termination: `kill <pid>` (Linux/macOS) or `taskkill /PID <pid>` (Windows)

### Multiple UI Windows

You can run multiple UI windows connected to the same server:

```bash
# Terminal 1
jarvis

# Terminal 2
jarvis
```

Both windows will share the same identity, contacts, and messages. They'll both receive real-time updates when messages arrive.

### Server Data

Server data is stored in:
- **Linux/macOS:** `~/.jarvis/`
- **Windows:** `%APPDATA%\Jarvis\`
- **Termux:** `~/.jarvis/`

Files:
- `server.pid` - Server process ID (deleted when server stops)
- `identity.enc` - Encrypted identity file
- `contacts.json` - Contact list
- `messages.json` - Message history
- `groups.json` - Group information

---

## Troubleshooting

### Server Issues

**Server Won't Start:**
1. Check if another instance is running: `pgrep -f jarvis-server`
2. Remove stale PID file: `rm ~/.jarvis/server.pid`
3. Check port availability: `lsof -i:5999` (Linux/macOS)
4. Try starting server manually with debug: `jarvis-server --data-dir ~/.jarvis`

**UI Can't Connect to Server:**
1. Verify server is running
2. Check firewall allows local connections on port 5999
3. Try restarting the server
4. Check data directory permissions

**Messages Not Being Delivered:**
1. Verify server is connected to contacts (check connection status)
2. Ensure contacts' servers are also running
3. Check network connectivity between devices
4. Verify firewall allows P2P port (default: 5000)

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
│   ├── main.py           # Application launcher
│   ├── server.py         # Background server daemon
│   ├── client.py         # Client API for IPC
│   ├── client_adapter.py # Adapter for UI compatibility
│   ├── crypto.py         # Five-layer encryption
│   ├── network.py        # P2P networking
│   ├── protocol.py       # Wire protocol
│   ├── contact.py        # Contact management
│   ├── message.py        # Message storage
│   ├── identity.py       # Identity management
│   ├── group.py          # Group chat
│   ├── session.py        # Session management
│   ├── notification.py   # Cross-platform notifications
│   ├── ui.py             # Textual UI (client)
│   └── utils.py          # Utility functions
└── tests/                # Test suite
```

---

## Acknowledgements

This project was designed and originated by **orpheus497**.

### Dependencies

Jarvis relies on the following open-source projects, and we are grateful to their creators and maintainers:

*   **Textual** (MIT License)  
    Terminal UI framework  
    Created by Will McGugan and the Textualize.io team  
    https://github.com/Textualize/textual
    
*   **cryptography** (Apache 2.0/BSD License)  
    Cryptographic primitives and protocols  
    Created by the Python Cryptographic Authority  
    https://github.com/pyca/cryptography
    
*   **argon2-cffi** (MIT License)  
    Argon2 password hashing implementation  
    Created by Hynek Schlawack  
    https://github.com/hynek/argon2-cffi
    
*   **Rich** (MIT License)  
    Terminal formatting and rendering library  
    Created by Will McGugan  
    https://github.com/Textualize/rich

*   **pyperclip** (BSD 3-Clause License)  
    Cross-platform clipboard support  
    Created by Al Sweigart  
    https://github.com/asweigart/pyperclip

All dependencies are free, open-source, and royalty-free. No external APIs or closed-source software is required.

### Standards and Protocols

This project implements industry-standard cryptographic protocols and best practices:

*   **Keep a Changelog** - For standardized changelog format  
    https://keepachangelog.com/
    
*   **Semantic Versioning** - For version numbering  
    https://semver.org/
    
*   **X25519** - Elliptic curve Diffie-Hellman key exchange (RFC 7748)  
    IETF standard for secure key agreement
    
*   **AES-GCM** - Authenticated encryption with associated data (NIST SP 800-38D)  
    NIST-approved authenticated encryption mode
    
*   **ChaCha20-Poly1305** - Authenticated encryption (RFC 8439)  
    IETF standard for authenticated encryption
    
*   **Argon2** - Memory-hard password hashing (RFC 9106)  
    IETF standard for password-based key derivation

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