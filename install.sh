#!/bin/bash
# Installation script for Jarvis on Linux/macOS
# This script sets up a local environment for Jarvis
# 
# Created by orpheus497

set -e

echo "======================================"
echo "  Jarvis v1.2.0 Local Setup Script"
echo "======================================"
echo ""
echo "Peer-to-Peer Encrypted Messenger"
echo "Created by orpheus497"
echo ""

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not found."
    echo "Please install Python 3.8 or higher."
    exit 1
fi

PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "Found Python $PYTHON_VERSION"

# Check if pip is available
if ! python3 -m pip --version &> /dev/null; then
    echo "Error: pip is required but not found."
    echo "Please install pip for Python 3."
    exit 1
fi

# Create virtual environment
VENV_DIR="venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating Python virtual environment in './$VENV_DIR'..."
    python3 -m venv "$VENV_DIR"
else
    echo "Virtual environment already exists."
fi

# Activate and install dependencies
echo "Installing dependencies..."
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install -r requirements.txt
pip install .
deactivate

# Create launcher script
LAUNCHER_SCRIPT="run_jarvis.sh"
echo "Creating launcher script './$LAUNCHER_SCRIPT'..."
cat > "$LAUNCHER_SCRIPT" << 'EOL'
#!/bin/bash
# Launcher for Jarvis
# Activates the virtual environment and runs the application

# Get the directory where the script is located
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Activate virtual environment and run Jarvis
source "$DIR/venv/bin/activate"
python -m jarvis "$@"
deactivate
EOL

chmod +x "$LAUNCHER_SCRIPT"

# Create desktop entry for Linux
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    DESKTOP_FILE="$HOME/.local/share/applications/jarvis.desktop"
    mkdir -p "$HOME/.local/share/applications"
    
    echo "Creating desktop entry..."
    cat > "$DESKTOP_FILE" << EOL
[Desktop Entry]
Version=1.0
Type=Application
Name=Jarvis
Comment=Peer-to-Peer Encrypted Messenger
Exec=$(pwd)/run_jarvis.sh
Icon=utilities-terminal
Terminal=true
Categories=Network;InstantMessaging;
Keywords=chat;messenger;encrypted;p2p;
EOL
    
    echo "Desktop entry created at: $DESKTOP_FILE"
fi

echo ""
echo "✓ Setup complete!"
echo ""
echo "To run Jarvis, execute:"
echo "  ./$LAUNCHER_SCRIPT"
echo ""
echo "Or simply:"
echo "  jarvis"
echo ""
echo "To remove the local environment, run:"
echo "  ./uninstall.sh"
echo ""
echo "For Termux users:"
echo "  Install termux-api package for notifications:"
echo "  pkg install termux-api"
echo ""
