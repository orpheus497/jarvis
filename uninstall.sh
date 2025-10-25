#!/bin/bash
# Uninstallation script for Jarvis on Linux/macOS
# Removes the virtual environment and launcher scripts
# 
# Created by orpheus497

echo "======================================"
echo "  Jarvis Uninstall Script"
echo "======================================"
echo ""

read -p "Remove Jarvis environment? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Uninstall cancelled."
    exit 0
fi

# Remove virtual environment
if [ -d "venv" ]; then
    echo "Removing virtual environment..."
    rm -rf venv
fi

# Remove launcher script
if [ -f "run_jarvis.sh" ]; then
    echo "Removing launcher script..."
    rm -f run_jarvis.sh
fi

# Remove desktop entry
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    DESKTOP_FILE="$HOME/.local/share/applications/jarvis.desktop"
    if [ -f "$DESKTOP_FILE" ]; then
        echo "Removing desktop entry..."
        rm -f "$DESKTOP_FILE"
    fi
fi

echo ""
echo "✓ Uninstall complete!"
echo ""
echo "Note: Your data files have been preserved:"
echo "  - Identity: ~/.jarvis/identity.enc"
echo "  - Contacts: ~/.jarvis/contacts.json"
echo "  - Messages: ~/.jarvis/messages.json"
echo "  - Groups: ~/.jarvis/groups.json"
echo ""
echo "To completely remove all data, delete the data directory:"
echo "  rm -rf ~/.jarvis"
echo ""
