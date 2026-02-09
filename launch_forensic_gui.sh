#!/bin/bash

# Forensic GUI Analyzer - Launcher Script
# Checks dependencies and launches the application

set -e

echo "=========================================="
echo "  Forensic Disk Analyzer - Launcher"
echo "=========================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check Python
echo -n "Checking Python... "
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    echo -e "${GREEN}✓${NC} Python $PYTHON_VERSION"
else
    echo -e "${RED}✗${NC} Python 3 not found"
    exit 1
fi

# Check Tkinter
echo -n "Checking Tkinter... "
if python3 -c "import tkinter" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} Tkinter available"
else
    echo -e "${RED}✗${NC} Tkinter not found"
    echo ""
    echo "Install Tkinter:"
    echo "  Ubuntu/Debian: sudo apt-get install python3-tk"
    echo "  macOS: brew install python-tk"
    exit 1
fi

# Check E01 support (optional)
echo -n "Checking E01 support... "
if python3 -c "import pyewf" 2>/dev/null; then
    echo -e "${GREEN}✓${NC} pyewf available"
    E01_SUPPORT=true
elif python3 -c "import pytsk3" 2>/dev/null; then
    echo -e "${YELLOW}⚠${NC} pytsk3 available (limited E01 support)"
    E01_SUPPORT=partial
else
    echo -e "${YELLOW}⚠${NC} No E01 support"
    echo "  Install: pip install pytsk3"
    E01_SUPPORT=false
fi

echo ""
echo "=========================================="
echo "  Launching Application"
echo "=========================================="
echo ""

# Check for root if analyzing devices
if [ "$1" == "--device" ] || [ "$1" == "-d" ]; then
    if [ "$EUID" -ne 0 ]; then
        echo -e "${YELLOW}Warning:${NC} Device analysis requires root privileges"
        echo "Relaunch with: sudo $0 $@"
        echo ""
        read -p "Continue anyway? [y/N] " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
fi

# Launch
python3 forensic_gui_analyzer.py "$@"
