# =============================================================================
#  ics_honeypot / main.py
#  ---------------------------------------------------------------------------
#  ICS Honeypot — Main Entry Point
#  ---------------------------------------------------------------------------
#  Starts all three protocol listeners (Modbus, DNP3, MQTT) as daemon threads,
#  then blocks in the main thread waiting for a keyboard interrupt (Ctrl+C).
#
#  On Ctrl+C:
#    1. All listeners are gracefully stopped
#    2. An HTML threat intelligence report is generated from events.jsonl
#    3. The report path is printed
#
#  Run from the project root:
#      sudo python3 -m main           (sudo needed for port 502)
#  Or:
#      sudo python3 main.py
#
#  To skip port 502 (no sudo needed), change MODBUS_PORT in config.py to 5020.
# =============================================================================

import sys
import time
import signal
import threading

from honeypot.modbus.listener  import ModbusListener
from honeypot.dnp3.listener    import DNP3Listener
from honeypot.mqtt.listener    import MQTTListener
from honeypot.reporter.report  import generate_report
from honeypot.shared.config    import MODBUS_PORT, DNP3_PORT, MQTT_PORT

# ANSI colours for startup banner
CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ---------------------------------------------------------------------------
# Startup banner
# ---------------------------------------------------------------------------

BANNER = f"""
{CYAN}{BOLD}
  ██╗ ██████╗███████╗    ██╗  ██╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗ ████████╗
  ██║██╔════╝██╔════╝    ██║  ██║██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔══██╗██╔═══██╗╚══██╔══╝
  ██║██║     ███████╗    ███████║██║   ██║██╔██╗ ██║█████╗   ╚████╔╝ ██████╔╝██║   ██║   ██║
  ██║██║     ╚════██║    ██╔══██║██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝  ██╔═══╝ ██║   ██║   ██║
  ██║╚██████╗███████║    ██║  ██║╚██████╔╝██║ ╚████║███████╗   ██║   ██║     ╚██████╔╝   ██║
  ╚═╝ ╚═════╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝    ╚═╝
{RESET}
  {YELLOW}Multi-Protocol ICS Honeypot  |  Modbus TCP · DNP3 · MQTT{RESET}
  {YELLOW}Built for ICS/OT Security Research{RESET}
"""


def print_startup_info():
    """Print the banner and port information."""
    print(BANNER)
    print(f"  {GREEN}[+]{RESET} Modbus TCP listener  →  port {BOLD}{MODBUS_PORT}{RESET}  (requires sudo / cap_net_bind_service)")
    print(f"  {GREEN}[+]{RESET} DNP3 listener         →  port {BOLD}{DNP3_PORT}{RESET}")
    print(f"  {GREEN}[+]{RESET} MQTT listener         →  port {BOLD}{MQTT_PORT}{RESET}")
    print()
    print(f"  {YELLOW}[*]{RESET} Logs  → logs/honeypot.log")
    print(f"  {YELLOW}[*]{RESET} Events→ logs/events.jsonl")
    print(f"  {YELLOW}[*]{RESET} Press {BOLD}Ctrl+C{RESET} to stop and generate HTML report")
    print()
    print("  " + "─" * 72)
    print()


# ---------------------------------------------------------------------------
# Listener management
# ---------------------------------------------------------------------------

def start_all_listeners() -> list:
    """
    Instantiate and start all three protocol honeypot listeners.
    Returns the list of listener objects so they can be stopped later.
    """
    listeners = [
        ModbusListener(),
        DNP3Listener(),
        MQTTListener(),
    ]
    for listener in listeners:
        try:
            listener.start()
        except PermissionError as exc:
            print(f"\n  {RED}[!] Permission denied starting {listener.__class__.__name__}: {exc}{RESET}")
            print(f"  {YELLOW}[*] Try running with sudo, or change port in config.py{RESET}\n")
            sys.exit(1)
        except OSError as exc:
            print(f"\n  {RED}[!] Could not bind port for {listener.__class__.__name__}: {exc}{RESET}")
            print(f"  {YELLOW}[*] Is another process using this port? Run: sudo lsof -i :<port>{RESET}\n")
            sys.exit(1)

    return listeners


def stop_all_listeners(listeners: list):
    """Signal all listeners to stop accepting new connections."""
    for listener in listeners:
        listener.stop()


# ---------------------------------------------------------------------------
# Signal handler (Ctrl+C)
# ---------------------------------------------------------------------------

_shutdown_event = threading.Event()


def _signal_handler(signum, frame):
    """Handle SIGINT (Ctrl+C) gracefully."""
    print(f"\n\n  {YELLOW}[*] Shutdown signal received — stopping listeners…{RESET}")
    _shutdown_event.set()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    print_startup_info()

    # Register signal handler for clean Ctrl+C shutdown
    signal.signal(signal.SIGINT,  _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    listeners = start_all_listeners()

    print(f"  {GREEN}[+] All listeners running.  Waiting for connections…{RESET}\n")

    # Block until Ctrl+C or SIGTERM
    try:
        while not _shutdown_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass   # caught by signal handler, _shutdown_event already set

    # Graceful shutdown
    stop_all_listeners(listeners)
    time.sleep(0.5)   # give threads a moment to close open sockets

    # Generate the HTML threat intelligence report
    print(f"\n  {CYAN}[*] Generating threat intelligence report…{RESET}")
    report_path = generate_report()
    print(f"  {GREEN}[+] Report saved: {BOLD}{report_path}{RESET}")
    print(f"\n  {YELLOW}Open the report in any browser to view attack analysis.{RESET}\n")


if __name__ == "__main__":
    main()
