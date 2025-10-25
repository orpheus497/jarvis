#!/bin/bash
# Build script for Jarvis development
# Sets up development environment with all tools
# 
# Created by orpheus497

set -e

echo "======================================"
echo "  Jarvis Development Build Script"
echo "======================================"
echo ""

# Check for Python 3
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is required but not found."
    exit 1
fi

echo "Setting up development environment..."

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
pip install --editable .

# Install development dependencies
pip install pytest pytest-asyncio pytest-cov black flake8 mypy

echo ""
echo "✓ Development environment ready!"
echo ""
echo "To activate the environment:"
echo "  source venv/bin/activate"
echo ""
echo "To run tests:"
echo "  pytest tests/"
echo ""
echo "To run Jarvis:"
echo "  python -m jarvis"
echo ""
