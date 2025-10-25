# Jarvis Quick Reference Guide

Quick reference for keyboard shortcuts, commands, and common operations.

Created by **orpheus497**

---

## Keyboard Shortcuts

### Global

| Shortcut | Action |
|----------|--------|
| `Ctrl+Q` | Quit Jarvis |
| `Ctrl+C` | Add Contact |
| `Ctrl+G` | New Group |
| `Ctrl+S` | Settings |
| `Escape` | Cancel / Close Modal |

### Chat

| Shortcut | Action |
|----------|--------|
| `Enter` | Send Message |
| `Tab` | Navigate UI Elements |
| `Shift+Tab` | Navigate Backwards |

---

## Command Line Options

```bash
# Start with default settings
jarvis

# Use custom data directory
jarvis --data-dir ~/my-jarvis-data

# Use custom port
jarvis --port 6000

# Enable debug mode
jarvis --debug

# Show version
jarvis --version

# Show help
jarvis --help
```

---

## First-Time Setup

1. **Create Identity**
   - Enter username
   - Create strong password
   - Set listen port (default: 5000)
   - Save your UID

2. **Share Your Identity**
   - UID: Your unique identifier
   - Public Key: From settings
   - Host: Your IP address
   - Port: Your listen port

3. **Add First Contact**
   - Get contact's UID, public key, host, port
   - Press Ctrl+C or click "Add Contact"
   - Enter information
   - Verify fingerprint out-of-band
   - Mark as verified after confirmation

---

## Common Operations

### Adding a Contact

1. Press `Ctrl+C` or click "Add Contact"
2. Enter:
   - **UID:** 32-character hex string
   - **Username:** Display name
   - **Public Key:** Base64-encoded public key
   - **Host:** IP address or hostname
   - **Port:** Listen port (usually 5000)
3. Click "Add"
4. **Important:** Verify fingerprint with contact
5. Mark as verified after confirmation

### Verifying Fingerprints

1. Open settings (`Ctrl+S`)
2. View your fingerprint
3. Contact does the same
4. Compare fingerprints via phone call or in person
5. Mark each other as verified

### Sending Messages

1. Select contact from list
2. Type message in input field
3. Press `Enter` or click "Send"
4. Green dot = online, red dot = offline

### Creating Groups

1. Press `Ctrl+G` or click "New Group"
2. Enter group name
3. Optionally add description
4. Click "Create"
5. Add members through contact list

### Group Messaging

1. Select group from groups tab
2. Type message
3. Press `Enter` or click "Send"
4. Message sent to all online members

---

## File Locations

### Linux/macOS
```
~/.jarvis/
├── identity.enc      # Encrypted identity
├── contacts.json     # Contact list
├── messages.json     # Message history
└── groups.json       # Group information
```

### Windows
```
%APPDATA%\Jarvis\
├── identity.enc
├── contacts.json
├── messages.json
└── groups.json
```

### Termux
```
~/.jarvis/
├── identity.enc
├── contacts.json
├── messages.json
└── groups.json
```

---

## Port Forwarding

### Finding Your Local IP

**Linux/macOS:**
```bash
ip addr show  # or ifconfig
hostname -I
```

**Windows:**
```cmd
ipconfig
```

**Termux:**
```bash
ip addr show
```

### Finding Your Public IP

```bash
curl ifconfig.me
```

Or visit: https://whatismyip.com

### Configuring Router

1. Access router admin panel (usually 192.168.1.1 or 192.168.0.1)
2. Find "Port Forwarding" or "NAT" section
3. Add rule:
   - **External Port:** Your chosen port (e.g., 5000)
   - **Internal IP:** Your local IP (e.g., 192.168.1.100)
   - **Internal Port:** Same as external
   - **Protocol:** TCP
4. Save and apply changes

---

## Firewall Configuration

### Linux (UFW)

```bash
# Allow Jarvis port
sudo ufw allow 5000/tcp

# Check status
sudo ufw status
```

### Linux (firewalld)

```bash
# Allow Jarvis port
sudo firewall-cmd --permanent --add-port=5000/tcp
sudo firewall-cmd --reload

# Check status
sudo firewall-cmd --list-ports
```

### Windows

```powershell
# Add firewall rule
netsh advfirewall firewall add rule name="Jarvis" dir=in action=allow protocol=TCP localport=5000

# Check rules
netsh advfirewall firewall show rule name=all
```

### macOS

```bash
# Add firewall rule (requires admin)
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /path/to/python
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp /path/to/python
```

---

## Troubleshooting

### Cannot Connect

**Check:**
- Contact is online and running Jarvis
- IP address is correct
- Port is correct
- Firewall allows the port
- Port forwarding configured (if needed)
- Fingerprint matches

**Test:**
```bash
# Test if port is open
telnet <host> <port>

# Or use netcat
nc -zv <host> <port>
```

### Notifications Not Working

**Linux:**
```bash
# Install libnotify
sudo apt install libnotify-bin  # Debian/Ubuntu
sudo dnf install libnotify       # Fedora
```

**Termux:**
```bash
# Install termux-api
pkg install termux-api
```

**Test:**
```bash
# Linux
notify-send "Test" "Test message"

# Termux
termux-notification --title "Test" --content "Test message"
```

### High Memory Usage

- Normal during encryption (Argon2id uses 64 MB)
- Memory usage should drop after operation
- Close unused conversations
- Restart Jarvis if memory doesn't free

### Port Already in Use

**Find process using port:**
```bash
# Linux/macOS
lsof -ti:5000

# Windows
netstat -ano | findstr :5000
```

**Kill process:**
```bash
# Linux/macOS
kill -9 $(lsof -ti:5000)

# Windows
taskkill /PID <PID> /F
```

**Or change port:**
- Use different port in Jarvis settings
- Update contacts with new port

---

## Security Best Practices

### Master Password

✓ **DO:**
- Use 12+ characters
- Mix uppercase, lowercase, numbers, symbols
- Use a passphrase for memorability
- Write it down in a secure location
- Create a physical backup

✗ **DON'T:**
- Use dictionary words
- Reuse passwords from other services
- Share via email or messaging
- Store in text files
- Use short or simple passwords

### Fingerprint Verification

✓ **DO:**
- Verify through trusted out-of-band channel
- Phone call or in person
- Compare full fingerprint
- Both parties verify each other
- Mark as verified only after confirmation

✗ **DON'T:**
- Trust fingerprints sent over same channel
- Skip verification for "trusted" contacts
- Verify electronically only
- Assume fingerprint is correct

### System Security

✓ **DO:**
- Keep OS updated
- Use full-disk encryption
- Enable firewall
- Lock computer when away
- Use trusted networks only

✗ **DON'T:**
- Use on compromised systems
- Leave computer unlocked
- Use on public computers
- Trust untrusted networks
- Disable security features

---

## Quick Tips

### Performance

- Close unused conversations to free memory
- Limit message history loaded (default: 50 messages)
- Disconnect from offline contacts
- Restart Jarvis daily for best performance

### Privacy

- Use VPN to hide your IP address
- Use Tor for anonymous connections (advanced)
- Regularly delete old messages
- Don't screenshot sensitive conversations
- Clear terminal scrollback regularly

### Usability

- Use keyboard shortcuts for efficiency
- Organize contacts with clear names
- Use groups for team communications
- Verify contacts before sensitive conversations
- Back up your identity file regularly

---

## Status Indicators

| Indicator | Meaning |
|-----------|---------|
| 🟢 Green dot | Contact is online |
| 🔴 Red dot | Contact is offline |
| ✅ Green check | Contact verified |
| ⚠️ Yellow badge | Unread messages |
| 🔒 Lock icon | Encrypted connection |

---

## Encryption Layers

Every message passes through five layers:

1. **AES-256-GCM** (Layer 1)
2. **ChaCha20-Poly1305** (Layer 2)
3. **AES-256-GCM** (Layer 3)
4. **ChaCha20-Poly1305** (Layer 4)
5. **AES-256-GCM** (Layer 5)

Each layer uses:
- Independent 256-bit key
- Unique 96-bit nonce
- 128-bit authentication tag

---

## Support

### Documentation

- **README.md** - Full documentation
- **SECURITY.md** - Security details
- **TESTING.md** - Testing guide
- **CHANGELOG.md** - Version history

### Getting Help

1. Check documentation
2. Search GitHub issues
3. Create GitHub issue
4. Include:
   - OS and version
   - Python version
   - Error messages
   - Steps to reproduce

---

## Version Information

**Current Version:** 1.0.0  
**Release Date:** 2025-10-25  
**Created by:** orpheus497  
**License:** MIT  

---

**Remember:** Verify fingerprints. Use strong passwords. Trust no one by default.

**Stay secure. Stay private. Stay free.**
