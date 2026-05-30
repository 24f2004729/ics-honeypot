#!/usr/bin/env bash
# =============================================================================
#  run_honeypot.sh
#  ---------------------------------------------------------------------------
#  One-command launcher for the ICS Honeypot.
#  Must be run from the ics_honeypot/ project root directory.
#
#  Usage:
#      sudo bash run_honeypot.sh          # full mode (all ports)
#      bash run_honeypot.sh --no-sudo     # dev mode (changes port 502 → 5020)
# =============================================================================

set -e   # exit immediately on any error

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "  ┌─────────────────────────────────────────────────┐"
echo "  │        ICS Honeypot — Startup Script            │"
echo "  └─────────────────────────────────────────────────┘"
echo ""

# ---------------------------------------------------------------------------
# Check Python version (3.8+ required)
# ---------------------------------------------------------------------------
PYTHON=$(command -v python3 || command -v python)
if [ -z "$PYTHON" ]; then
    echo "  [ERROR] Python 3 not found. Install with: sudo apt install python3"
    exit 1
fi

PY_VERSION=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$($PYTHON -c "import sys; print(sys.version_info.major)")
PY_MINOR=$($PYTHON -c "import sys; print(sys.version_info.minor)")

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 8 ]; }; then
    echo "  [ERROR] Python 3.8+ required. Found: $PY_VERSION"
    exit 1
fi
echo "  [+] Python $PY_VERSION detected"

# ---------------------------------------------------------------------------
# Dev mode: patch config to use non-privileged port for Modbus
# ---------------------------------------------------------------------------
if [ "$1" == "--no-sudo" ]; then
    echo "  [*] Dev mode: patching Modbus port 502 → 5020 (no sudo needed)"
    sed -i 's/^MODBUS_PORT  = 502/MODBUS_PORT  = 5020/' honeypot/shared/config.py
    echo "  [*] Point your Modbus scanner to port 5020 instead of 502"
fi

# ---------------------------------------------------------------------------
# Ensure logs directory exists
# ---------------------------------------------------------------------------
mkdir -p logs
echo "  [+] Logs directory: $SCRIPT_DIR/logs/"

# ---------------------------------------------------------------------------
# Launch
# ---------------------------------------------------------------------------
echo "  [+] Starting honeypot…"
echo ""
$PYTHON main.py
