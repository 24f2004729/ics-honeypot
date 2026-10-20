#!/usr/bin/env bash
# =============================================================================
#  run_honeypot.sh
#  ---------------------------------------------------------------------------
#  Production Launcher for ICS Honeypot
#
#  Usage:
#      sudo bash run_honeypot.sh          # Full mode (Port 502, 20000, 1883)
#      bash run_honeypot.sh --dev         # Dev mode (Modbus Port 5020, unprivileged)
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "  ┌────────────────────────────────────────────────────────┐"
echo "  │        ICS Honeypot — Enterprise SCADA Decoy           │"
echo "  └────────────────────────────────────────────────────────┘"
echo ""

PYTHON=$(command -v python3 || command -v python)
if [ -z "$PYTHON" ]; then
    echo "  [ERROR] Python 3 not found. Install with: sudo apt install python3"
    exit 1
fi

PY_MAJOR=$($PYTHON -c "import sys; print(sys.version_info.major)")
PY_MINOR=$($PYTHON -c "import sys; print(sys.version_info.minor)")

if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 8 ]; }; then
    echo "  [ERROR] Python 3.8+ required. Found: $PY_MAJOR.$PY_MINOR"
    exit 1
fi
echo "  [+] Python $PY_MAJOR.$PY_MINOR detected"

mkdir -p logs

if [ "$1" == "--no-sudo" ] || [ "$1" == "--dev" ]; then
    echo "  [*] Dev mode: binding Modbus to unprivileged port 5020"
    $PYTHON main.py --dev
else
    echo "  [+] Running in full standard mode (ports 502, 20000, 1883)"
    $PYTHON main.py "$@"
fi
