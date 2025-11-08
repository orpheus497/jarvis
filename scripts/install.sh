#!/bin/bash
# Jarvis P2P Encrypted Messenger - Installation Script
# Created by orpheus497
#
# This script automates the installation of Jarvis including:
# - Dependency checking
# - Virtual environment setup
# - Package installation
# - Optional systemd service setup

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
PYTHON_MIN_VERSION="3.8"
INSTALL_DIR="${INSTALL_DIR:-/opt/jarvis}"
DATA_DIR="${DATA_DIR:-$HOME/.jarvis}"
VENV_DIR="$INSTALL_DIR/venv"

# Functions
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_python() {
    print_info "Checking Python version..."
    if ! command -v python3 &> /dev/null; then
        print_error "Python 3 is not installed"
        exit 1
    fi

    PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
    if ! python3 -c "import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)"; then
        print_error "Python $PYTHON_VERSION found, but >= $PYTHON_MIN_VERSION required"
        exit 1
    fi

    print_info "Python $PYTHON_VERSION detected ✓"
}

check_dependencies() {
    print_info "Checking system dependencies..."

    # Check for pip
    if ! python3 -m pip --version &> /dev/null; then
        print_error "pip is not installed"
        exit 1
    fi

    # Check for venv module
    if ! python3 -c "import venv" 2>/dev/null; then
        print_error "python3-venv is not installed"
        print_info "Install with: sudo apt install python3-venv (Debian/Ubuntu)"
        exit 1
    fi

    print_info "System dependencies satisfied ✓"
}

create_directories() {
    print_info "Creating directories..."

    if [ ! -w "$(dirname "$INSTALL_DIR")" ]; then
        print_error "No write permission to $(dirname "$INSTALL_DIR")"
        print_info "Try running with sudo or change INSTALL_DIR"
        exit 1
    fi

    mkdir -p "$INSTALL_DIR"
    mkdir -p "$DATA_DIR"

    print_info "Directories created ✓"
}

setup_virtualenv() {
    print_info "Setting up virtual environment..."

    python3 -m venv "$VENV_DIR"
    source "$VENV_DIR/bin/activate"

    # Upgrade pip
    pip install --upgrade pip > /dev/null

    print_info "Virtual environment created ✓"
}

install_jarvis() {
    print_info "Installing Jarvis..."

    # Copy source files
    cp -r src "$INSTALL_DIR/"
    cp pyproject.toml README.md LICENSE.txt CHANGELOG.md "$INSTALL_DIR/"

    # Install in virtual environment
    cd "$INSTALL_DIR"
    source "$VENV_DIR/bin/activate"
    pip install -e . > /dev/null

    print_info "Jarvis installed ✓"
}

create_config() {
    print_info "Creating default configuration..."

    if [ ! -f "$DATA_DIR/config.toml" ]; then
        cat > "$DATA_DIR/config.toml" << 'EOF'
# Jarvis Configuration File
# See docs/CONFIGURATION.md for all options

[network]
server_port = 5000
ipc_port = 5999
connection_timeout = 30

[dht]
enabled = true
port = 6881
# Configure bootstrap nodes for DHT
# bootstrap_nodes = [["192.168.1.100", 6881]]

[logging]
level = "INFO"
# file = "jarvis.log"

[backup]
enabled = true
interval = 86400  # 24 hours
retention_days = 30
max_count = 10
EOF
        print_info "Config template created at $DATA_DIR/config.toml"
    else
        print_warn "Config already exists at $DATA_DIR/config.toml (not overwriting)"
    fi
}

setup_systemd() {
    if [ "$EUID" -ne 0 ]; then
        print_warn "Systemd service requires root privileges"
        print_info "To install service later, run with sudo"
        return
    fi

    print_info "Installing systemd service..."

    # Create jarvis user if doesn't exist
    if ! id -u jarvis &>/dev/null; then
        useradd -r -s /bin/false -d "$DATA_DIR" jarvis
        print_info "Created jarvis user"
    fi

    # Set ownership
    chown -R jarvis:jarvis "$DATA_DIR"

    # Install service file
    cp deployment/systemd/jarvis-server.service /etc/systemd/system/
    systemctl daemon-reload

    print_info "Systemd service installed ✓"
    print_info "Enable with: sudo systemctl enable jarvis-server"
    print_info "Start with: sudo systemctl start jarvis-server"
}

create_launcher() {
    print_info "Creating launcher script..."

    cat > "$INSTALL_DIR/jarvis-launcher.sh" << EOF
#!/bin/bash
# Jarvis Launcher
source "$VENV_DIR/bin/activate"
export JARVIS_DATA_DIR="$DATA_DIR"
exec python -m jarvis "\$@"
EOF

    chmod +x "$INSTALL_DIR/jarvis-launcher.sh"

    # Create symlink in /usr/local/bin if we have permission
    if [ -w /usr/local/bin ]; then
        ln -sf "$INSTALL_DIR/jarvis-launcher.sh" /usr/local/bin/jarvis
        print_info "Launcher installed to /usr/local/bin/jarvis ✓"
    else
        print_warn "Cannot create symlink in /usr/local/bin (no permission)"
        print_info "Add to your PATH: export PATH=\"$INSTALL_DIR:\$PATH\""
    fi
}

print_summary() {
    echo ""
    echo "======================================"
    echo "  Jarvis Installation Complete! 🛡️"
    echo "======================================"
    echo ""
    echo "Installation directory: $INSTALL_DIR"
    echo "Data directory: $DATA_DIR"
    echo "Config file: $DATA_DIR/config.toml"
    echo ""
    echo "To start Jarvis:"
    if command -v jarvis &> /dev/null; then
        echo "  $ jarvis"
    else
        echo "  $ $INSTALL_DIR/jarvis-launcher.sh"
    fi
    echo ""
    echo "For systemd service (requires sudo):"
    echo "  $ sudo systemctl enable jarvis-server"
    echo "  $ sudo systemctl start jarvis-server"
    echo ""
    echo "Documentation:"
    echo "  README: $INSTALL_DIR/README.md"
    echo "  Docs: https://github.com/orpheus497/jarvisapp"
    echo ""
}

# Main installation flow
main() {
    echo "======================================"
    echo "  Jarvis Installation Script"
    echo "======================================"
    echo ""

    check_python
    check_dependencies
    create_directories
    setup_virtualenv
    install_jarvis
    create_config
    create_launcher

    # Ask about systemd service
    if [ "$EUID" -eq 0 ]; then
        read -p "Install systemd service? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            setup_systemd
        fi
    fi

    print_summary
}

# Run main installation
main "$@"
