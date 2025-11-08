# Jarvis 🛡️

**Version 2.3.0** - _Terminal-based peer-to-peer end-to-end encrypted messenger with internet connectivity_

Created by **orpheus497**.

![Version](https://img.shields.io/badge/version-2.3.0-blue)
![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20macOS-lightgrey)

Jarvis is a cross-platform terminal-based messenger that provides complete privacy through peer-to-peer direct connections with automatic NAT traversal for internet messaging. Your messages never pass through any server, are never stored in the cloud, and are protected by five layers of military-grade encryption.

```
░        ░░░      ░░░       ░░░  ░░░░  ░░        ░░░      ░░
▒▒▒▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒  ▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒▒  ▒▒▒▒▒▒▒
▓▓▓▓▓▓▓  ▓▓  ▓▓▓▓  ▓▓       ▓▓▓▓  ▓▓  ▓▓▓▓▓▓  ▓▓▓▓▓▓      ▓▓
█  ████  ██        ██  ███  █████    ███████  ███████████  █
██      ███  ████  ██  ████  █████  █████        ███      ██
```

Jarvis provides complete privacy through end-to-end encryption with forward secrecy, direct peer-to-peer connections with automatic NAT traversal, offline message queuing, peer discovery, and rich communication features including file transfer, voice messages, and group chat.

---

## Philosophy

Your conversations remain completely under your control.

*   **No Cloud:** Messages are transmitted directly between peers, never stored on servers.
*   **No Tracking:** No analytics, no tracking pixels, no telemetry of any kind.
*   **Total Privacy:** Only you and your contacts can read your messages.
*   **No Servers Required:** Direct peer-to-peer connections using TCP sockets.
*   **Internet Ready:** Automatic NAT traversal with UPnP/STUN for connections over the internet.
*   **Supreme Encryption:** Five-layer encryption alternating AES-256-GCM and ChaCha20-Poly1305.

---

## Features

### 🌐 Internet Connectivity

*   **Automatic NAT Traversal:** Connect over the internet without manual port forwarding
    *   UPnP IGD automatic port mapping
    *   STUN protocol for public IP discovery  
    *   NAT type detection (7 types supported)
    *   Connection strategy selection based on network topology
*   **Peer Discovery:** Find contacts automatically on local networks
    *   mDNS/DNS-SD service broadcasting
    *   Real-time peer detection
    *   Automatic address updates
*   **Message Queue:** Reliable offline message delivery
    *   Messages queued when recipients offline
    *   Exponential backoff retry logic
    *   7-day message retention
    *   Delivery receipt tracking
*   **Connection Reliability:** Robust connection management
    *   Formal finite state machine
    *   Automatic reconnection handling
    *   Connection health monitoring
*   **Security Hardening:** Protection for internet exposure
    *   IP whitelisting/blacklisting
    *   Connection limits per IP
    *   Rate limiting

### 🔐 Security

*   **Five-Layer Encryption:** Messages are encrypted through five independent layers
    *   Layer 1: AES-256-GCM (first encryption)
    *   Layer 2: ChaCha20-Poly1305 (second encryption)
    *   Layer 3: AES-256-GCM (third encryption)
    *   Layer 4: ChaCha20-Poly1305 (fourth encryption)
    *   Layer 5: AES-256-GCM (fifth encryption)
*   **Forward Secrecy:** Double Ratchet algorithm for automatic key rotation
    *   Signal Protocol-style implementation
    *   Per-message key rotation
    *   Past messages cannot be decrypted if keys compromised
    *   Protection against retroactive surveillance
*   **Key Exchange:** X25519 Elliptic Curve Diffie-Hellman for session key establishment
*   **Key Derivation:** Argon2id with 3 iterations, 64 MB memory, 1 thread
*   **Identity Protection:** Master password never stored on disk, exists only in memory
*   **Fingerprint Verification:** SHA-256 fingerprints for contact authentication
*   **Unique UIDs:** 128-bit cryptographically secure unique identifiers
*   **Rate Limiting:** Token bucket algorithm prevents abuse and DoS attacks
*   **Message Size Limits:** Configurable limits prevent memory exhaustion

### Communication

*   **Direct P2P Connections:** No intermediary servers, messages go directly peer-to-peer
*   **Encrypted File Transfer:** Send files up to 100MB with automatic chunking
    *   1MB chunks with individual encryption
    *   Progress tracking and resume capability
    *   SHA-256 integrity verification
    *   Automatic retry on failure
*   **Voice Messages:** Record and send encrypted audio messages (optional feature)
*   **Group Chats:** Create encrypted group conversations with multiple participants
*   **Message Reactions:** React to messages with emojis in real-time
*   **Rich Text:** Markdown formatting support (bold, italic, code blocks)
*   **Typing Indicators:** Real-time typing status for active conversations
*   **Cross-Platform:** Works on Linux, Windows, and macOS
*   **Background Operation:** Runs in background with system notifications
*   **Automatic Reconnection:** Handles network interruptions gracefully
*   **Automatic Connection:** Connects to all contacts, groups, and sessions automatically on login
*   **Connection Status Indicators:** Four-level status system for real-time visibility
    *   **Green:** All connections active (all peers online and connected)
    *   **Amber:** Partial connections (some peers online, messages can be sent/received)
    *   **Red:** No active connections (server running but no peers connected)
    *   **Grey:** Server offline (cannot send or receive messages)
*   **Message History:** Encrypted local storage with full-text search (SQLite + FTS5)

### Interface

*   **Terminal UI:** Beautiful terminal interface using Textual framework
*   **Colorful Display:** Rich colors and formatting for easy reading
    *   **Color Palette:** Red, white, black, grey, purple, cyan, amber
    *   Status indicator colors: green (all connected), amber (partial), red (none), grey (offline)
    *   Banner colors: white, red, bright white, dark red, purple, grey with cyan accents
    *   Informational elements and links highlighted in cyan
    *   See [docs/COLORS.md](docs/COLORS.md) for complete color usage documentation
*   **Animated ASCII Banner:** An animated ASCII art banner that cycles through a gradient of colors
*   **Full-Text Search:** Instant search across all messages with filtering (Ctrl+F)
*   **Statistics Dashboard:** View message counts, transfer stats, and activity (Ctrl+T)
*   **File Transfer Progress:** Real-time progress bars and transfer statistics
*   **Connection Quality:** Visual indicators for latency and throughput
*   **Contact Management:** Add, verify, and manage contacts
*   **QR Code Sharing:** Generate QR codes for easy contact exchange
*   **Status Indicators:** Real-time online/offline status
*   **Unread Badges:** Visual indicators for unread messages
*   **Keyboard Shortcuts:** Efficient keyboard-driven interface
*   **Lock Feature:** Secure your app with Ctrl+L (keeps connections active)

### Privacy & Data Control

*   **Configuration System:** TOML-based configuration with environment variable overrides
*   **Automatic Backups:** Scheduled encrypted backups with rotation policy
*   **Backup Restore:** One-command restoration from encrypted backups
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

**Requirements:** Python 3.8 or higher

```bash
# Install from source
git clone https://github.com/orpheus497/jarvisapp.git
cd jarvisapp
pip install .

# Run
jarvis
```

All dependencies are installed automatically.

**Data Storage:**
- **Linux/macOS:** `~/.jarvis/`
- **Windows:** `%APPDATA%\Jarvis\`

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

### Automatic NAT Traversal

Jarvis includes built-in NAT traversal capabilities that handle internet connectivity automatically:

*   **UPnP IGD**: Automatic port mapping on compatible routers
*   **STUN Protocol**: Public IP address discovery without external web services
*   **NAT Type Detection**: Identifies your network topology (7 types supported)
*   **Connection Strategy**: Selects optimal connection method based on your network

These features work automatically when you start Jarvis - no manual configuration required for most networks.

### Port Forwarding

For networks without UPnP support, you may need to configure port forwarding on your router:

1.  Choose a port (default: 5000)
2.  Configure your router to forward that port to your computer's local IP
3.  Share your public IP address and port with contacts

**Finding Your Public IP:**

Use the built-in STUN discovery (automatic when Jarvis starts), or check locally:

**Linux/macOS:**
```bash
# View network interfaces and addresses
ip addr show    # Linux
ifconfig        # macOS
```

**Windows:**
```powershell
# View network interfaces and addresses
ipconfig
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
Notifications should work by default on all platforms

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

## Configuration

Create a `config.toml` file in your data directory (`~/.jarvis/` or `%APPDATA%\Jarvis\`) to customize settings. Environment variables (prefixed with `JARVIS_`) can override configuration values.

---

## Acknowledgements

This project was designed and originated by **orpheus497**.

### Dependencies

Jarvis relies on the following open-source projects, and we are grateful to their creators and maintainers.

For a complete list of all dependencies, their licenses, and upstream links, see [docs/DEPENDENCIES.md](docs/DEPENDENCIES.md).

All dependencies are included and installed automatically:

**Core Libraries:**
*   **textual** - Terminal UI framework (MIT)
*   **cryptography** - Cryptographic primitives (Apache-2.0 / BSD-3-Clause)
*   **argon2-cffi** - Password hashing (MIT)
*   **rich** - Terminal formatting (MIT)
*   **pyperclip** - Clipboard support (BSD-3-Clause)
*   **tomli** - TOML parser for Python <3.11 (MIT)
*   **zstandard** - Compression (BSD-3-Clause)
*   **liboqs-python** - Post-quantum cryptography (MIT)
*   **qrcode** & **pillow** - QR code generation (BSD-3-Clause, HPND/PIL)
*   **sounddevice** & **soundfile** - Voice messages (MIT, BSD-3-Clause)

**Internet Connectivity:**
*   **miniupnpc** - UPnP IGD port mapping (BSD-3-Clause)
*   **pystun3** - STUN protocol client (MIT)
*   **zeroconf** - mDNS/DNS-SD peer discovery (LGPL-2.1)
*   **validators** - Input validation (MIT)
*   **aiofiles** - Async file I/O (Apache-2.0)

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

*   **Double Ratchet Algorithm** - Forward secrecy protocol  
    Signal Protocol specification for end-to-end encryption  
    https://signal.org/docs/specifications/doubleratchet/

*   **SQLite FTS5** - Full-text search engine  
    High-performance full-text search implementation  
    https://www.sqlite.org/fts5.html

*   **UPnP IGD** - Internet Gateway Device Protocol  
    Automatic port mapping for NAT traversal  
    https://openconnectivity.org/developer/specifications/upnp-resources/upnp/

*   **STUN** - Session Traversal Utilities for NAT (RFC 5389)  
    IETF standard for NAT traversal and public address discovery  
    https://tools.ietf.org/html/rfc5389

*   **mDNS/DNS-SD** - Multicast DNS Service Discovery (RFC 6762/6763)  
    IETF standard for zero-configuration networking  
    https://tools.ietf.org/html/rfc6762

### Inspiration

This project is inspired by the philosophy of [pwick](https://github.com/orpheus497/pwick) - complete local control, no external dependencies, and supreme security.

---

## Contributing

Contributions welcome! Fork the repository, make your changes, and submit a pull request.

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