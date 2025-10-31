# Installation Guide - Jarvis v2.1.0

## Requirements

- Python 3.8 or higher
- pip (Python package installer)
- Internet connection for initial installation

## System Dependencies

For full functionality, install these system packages:

### Linux (Debian/Ubuntu)
```bash
sudo apt-get update
sudo apt-get install python3-dev libffi-dev portaudio19-dev miniupnpc avahi-daemon
```

### Linux (Fedora/RHEL)
```bash
sudo dnf install python3-devel libffi-devel portaudio-devel miniupnpc avahi
```

### macOS
```bash
brew install portaudio miniupnpc
```

### Windows
- Install Visual C++ Build Tools from Microsoft
- Avahi/mDNS (Bonjour) is included with iTunes or install Bonjour Print Services

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/orpheus497/jarvis.git
cd jarvis

# Install the package
pip install .
```

### For Development

```bash
# Install in editable mode with all dependencies
pip install -e .
```

### Using pip (once published)

```bash
pip install jarvis-messenger
```

## Running Jarvis

After installation, run:

```bash
jarvis
```

### First Time Setup

On first run, Jarvis will:
1. Create identity and ask for username
2. Generate encryption keys
3. Set master password
4. Start the P2P server
5. Attempt NAT traversal for internet connectivity

## Network Configuration

### Firewall Configuration

Allow incoming TCP connections on your chosen port (default: 5555):

**Linux (ufw):**
```bash
sudo ufw allow 5555/tcp
```

**Linux (firewalld):**
```bash
sudo firewall-cmd --permanent --add-port=5555/tcp
sudo firewall-cmd --reload
```

**Windows:**
```
Windows Defender Firewall → Advanced Settings → Inbound Rules → New Rule
Protocol: TCP, Port: 5555
```

### Router Configuration

Jarvis automatically attempts UPnP port forwarding. If UPnP is disabled on your router:

1. Enable UPnP in router settings (recommended), OR
2. Manually forward port 5555 TCP to your computer's IP
3. If neither works, Jarvis will use STUN for NAT detection (LAN-only mode)

## Data Directory

Jarvis stores all data locally:

- **Linux/macOS:** `~/.jarvis/`
- **Windows:** `%APPDATA%\Jarvis\`

### Data Structure
```
~/.jarvis/
├── identity.enc          # Your encrypted identity
├── contacts.db           # Contact list
├── messages.db           # Message history
├── groups.db             # Group chat data
├── config.toml           # Configuration file
├── message_queue.db      # Offline message queue
├── server.pid            # Server process ID
└── backups/              # Encrypted backups
```

## Uninstallation

```bash
# Remove the package
pip uninstall jarvis-messenger

# Optionally remove data (WARNING: This deletes all your messages and identity!)
# Linux/macOS
rm -rf ~/.jarvis

# Windows
rmdir /s /q "%APPDATA%\Jarvis"
```

## Troubleshooting

### Permission Errors
```bash
# Install for current user only
pip install --user .
```

### Port Already in Use
```bash
# Start Jarvis on different port
jarvis --port 5556
```

### UPnP Not Working
- Check if UPnP is enabled in router settings
- Try manual port forwarding
- Use local network only mode (works on LAN)

### mDNS/Discovery Not Working
**Linux:** Ensure avahi-daemon is running:
```bash
sudo systemctl status avahi-daemon
sudo systemctl start avahi-daemon
```

**macOS:** Built-in (Bonjour) should work automatically

**Windows:** Install Bonjour Print Services

### Audio Issues (Voice Messages)
**Linux:**
```bash
sudo apt-get install python3-pyaudio portaudio19-dev
```

**macOS:**
```bash
brew install portaudio
pip install --upgrade pyaudio
```

### Dependency Conflicts
```bash
# Create a virtual environment
python3 -m venv jarvis-env
source jarvis-env/bin/activate  # Linux/macOS
# or
jarvis-env\Scripts\activate  # Windows

# Install in isolated environment
pip install .
```

## Verification

After installation, verify everything works:

```bash
# Check version
jarvis --version

# Run in verbose mode to see logs
jarvis --verbose

# Test NAT traversal
# Look for "UPnP port mapping successful" or "STUN discovery successful" in logs
```

## Updating

To update to the latest version:

```bash
cd jarvis
git pull
pip install --upgrade .
```

Your data directory and identity are preserved during updates.

## Platform-Specific Notes

### Linux
- Works best on systemd-based distributions
- Wayland users: clipboard functionality may require wl-clipboard

### macOS
- Apple Silicon (M1/M2): All dependencies support ARM64
- Requires macOS 10.15 (Catalina) or later

### Windows
- Windows 10/11 supported
- Windows Defender may prompt for network access (allow it)
- UPnP works on most home routers

## Getting Help

- GitHub Issues: https://github.com/orpheus497/jarvis/issues
- Check logs in `~/.jarvis/jarvis.log`
- Run with `--verbose` flag for detailed diagnostics
