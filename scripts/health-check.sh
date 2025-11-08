#!/bin/bash
# Jarvis Health Check Script
# Created by orpheus497
#
# Checks the status of Jarvis server daemon
# Exit codes:
#   0 - Healthy
#   1 - Unhealthy (server not running)
#   2 - Degraded (server running but IPC not responsive)

set -e

# Configuration
DATA_DIR="${JARVIS_DATA_DIR:-$HOME/.jarvis}"
PID_FILE="$DATA_DIR/server.pid"
IPC_PORT="${JARVIS_IPC_PORT:-5999}"
TIMEOUT=5

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Check if server process is running
check_process() {
    if [ ! -f "$PID_FILE" ]; then
        return 1
    fi

    PID=$(cat "$PID_FILE" 2>/dev/null)
    if [ -z "$PID" ]; then
        return 1
    fi

    if ! kill -0 "$PID" 2>/dev/null; then
        # Process not running, remove stale PID file
        rm -f "$PID_FILE"
        return 1
    fi

    return 0
}

# Check if IPC port is accessible
check_ipc() {
    # Try to connect to IPC port
    if command -v nc &> /dev/null; then
        if timeout "$TIMEOUT" nc -z localhost "$IPC_PORT" 2>/dev/null; then
            return 0
        fi
    elif command -v python3 &> /dev/null; then
        # Fallback to Python socket check
        python3 << EOF
import socket
import sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout($TIMEOUT)
    s.connect(('localhost', $IPC_PORT))
    s.close()
    sys.exit(0)
except:
    sys.exit(1)
EOF
        return $?
    fi

    return 1
}

# Main health check
main() {
    local exit_code=0

    echo "Jarvis Health Check"
    echo "==================="
    echo ""

    # Check process
    if check_process; then
        echo -e "${GREEN}✓${NC} Server process running (PID: $(cat "$PID_FILE"))"
    else
        echo -e "${RED}✗${NC} Server process not running"
        exit_code=1
    fi

    # Check IPC if process is running
    if [ $exit_code -eq 0 ]; then
        if check_ipc; then
            echo -e "${GREEN}✓${NC} IPC port $IPC_PORT responsive"
        else
            echo -e "${YELLOW}⚠${NC} IPC port $IPC_PORT not responsive"
            exit_code=2
        fi
    fi

    echo ""
    case $exit_code in
        0)
            echo -e "${GREEN}Status: HEALTHY${NC}"
            ;;
        1)
            echo -e "${RED}Status: DOWN${NC}"
            ;;
        2)
            echo -e "${YELLOW}Status: DEGRADED${NC}"
            ;;
    esac

    return $exit_code
}

# Run health check
main "$@"
exit $?
