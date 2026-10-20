# =============================================================================
#  ics_honeypot / main.py
#  ---------------------------------------------------------------------------
#  ICS Honeypot — Main Application Entry Point
#  ---------------------------------------------------------------------------
#  Runs multi-protocol listeners concurrently (Modbus TCP, DNP3, MQTT)
#  coupled with a real-time thermodynamic/electrical process simulator.
#
#  Usage:
#      python3 main.py                      # Standard privileged ports (502, 20000, 1883)
#      python3 main.py --dev                # Dev mode (Modbus runs on 5020, no sudo needed)
#      python3 main.py --profile schneider  # Set device profile (moxa, schneider, siemens)
#      python3 main.py --report-only        # Generate HTML report from existing logs
# =============================================================================

import sys
import time
import signal
import threading
import argparse

import honeypot.shared.config as cfg
from honeypot.modbus.listener  import ModbusListener
from honeypot.dnp3.listener    import DNP3Listener
from honeypot.mqtt.listener    import MQTTListener
from honeypot.reporter.report  import generate_report
from honeypot.simulation.process import simulator

CYAN   = "\033[96m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

BANNER = f"""
{CYAN}{BOLD}
  ██╗ ██████╗███████╗    ██╗  ██╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗██████╗  ██████╗ ████████╗
  ██║██╔════╝██╔════╝    ██║  ██║██╔═══██╗████╗  ██║██╔════╝╚██╗ ██╔╝██╔══██╗██╔═══██╗╚══██╔══╝
  ██║██║     ███████╗    ███████║██║   ██║██╔██╗ ██║█████╗   ╚████╔╝ ██████╔╝██║   ██║   ██║
  ██║██║     ╚════██║    ██╔══██║██║   ██║██║╚██╗██║██╔══╝    ╚██╔╝  ██╔═══╝ ██║   ██║   ██║
  ██║╚██████╗███████║    ██║  ██║╚██████╔╝██║ ╚████║███████╗   ██║   ██║     ╚██████╔╝   ██║
  ╚═╝ ╚═════╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝      ╚═════╝    ╚═╝
{RESET}
  {YELLOW}Enterprise ICS/SCADA Honeypot  |  Modbus TCP · DNP3 · MQTT{RESET}
  {YELLOW}MITRE ATT&CK® for ICS Aligned  |  Dynamic Process Simulation Engine{RESET}
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="Enterprise Multi-Protocol ICS Honeypot & Threat Intelligence System"
    )
    parser.add_argument("--dev", action="store_true", help="Run in dev mode (Modbus port 5020, unprivileged)")
    parser.add_argument("--modbus-port", type=int, default=None, help="Override Modbus TCP port")
    parser.add_argument("--dnp3-port", type=int, default=None, help="Override DNP3 port")
    parser.add_argument("--mqtt-port", type=int, default=None, help="Override MQTT port")
    parser.add_argument("--profile", type=str, choices=["moxa", "schneider", "siemens"], default=None,
                        help="Device emulation profile")
    parser.add_argument("--report-only", action="store_true", help="Generate HTML report and exit")
    return parser.parse_args()


def apply_overrides(args):
    if args.dev:
        cfg.MODBUS_PORT = 5020
    if args.modbus-port if hasattr(args, 'modbus-port') else False:
        pass
    if args.modbus_port is not None:
        cfg.MODBUS_PORT = args.modbus_port
    if args.dnp3_port is not None:
        cfg.DNP3_PORT = args.dnp3_port
    if args.mqtt_port is not None:
        cfg.MQTT_PORT = args.mqtt_port
    if args.profile:
        cfg.ACTIVE_PROFILE_NAME = args.profile
        profile = cfg.PROFILES[args.profile]
        cfg.MODBUS_VENDOR = profile["vendor"]
        cfg.MODBUS_PRODUCT = profile["product"]
        cfg.MODBUS_VERSION = profile["version"]


def print_startup_info():
    print(BANNER)
    print(f"  {GREEN}[+]{RESET} Device Profile       →  {BOLD}{cfg.MODBUS_VENDOR} ({cfg.MODBUS_PRODUCT}){RESET}")
    print(f"  {GREEN}[+]{RESET} Modbus TCP Listener  →  port {BOLD}{cfg.MODBUS_PORT}{RESET}")
    print(f"  {GREEN}[+]{RESET} DNP3 Listener         →  port {BOLD}{cfg.DNP3_PORT}{RESET}")
    print(f"  {GREEN}[+]{RESET} MQTT Broker Listener  →  port {BOLD}{cfg.MQTT_PORT}{RESET}")
    print(f"  {GREEN}[+]{RESET} Process Simulator    →  Substation Transformer Model {BOLD}[ACTIVE]{RESET}")
    print()
    print(f"  {YELLOW}[*]{RESET} Logs   → {cfg.LOG_FILE}")
    print(f"  {YELLOW}[*]{RESET} Events → {cfg.EVENT_FILE} (JSONL + MITRE ATT&CK for ICS)")
    print(f"  {YELLOW}[*]{RESET} Press {BOLD}Ctrl+C{RESET} to stop and generate threat report")
    print("  " + "─" * 72)
    print()


def start_all_listeners() -> list:
    listeners = [
        ModbusListener(port=cfg.MODBUS_PORT),
        DNP3Listener(port=cfg.DNP3_PORT),
        MQTTListener(port=cfg.MQTT_PORT),
    ]
    for listener in listeners:
        try:
            listener.start()
        except PermissionError as exc:
            print(f"\n  {RED}[!] Permission denied binding {listener.__class__.__name__}: {exc}{RESET}")
            print(f"  {YELLOW}[*] Run with sudo or use --dev to run on unprivileged port 5020{RESET}\n")
            sys.exit(1)
        except OSError as exc:
            print(f"\n  {RED}[!] Could not bind port for {listener.__class__.__name__}: {exc}{RESET}")
            sys.exit(1)
    return listeners


_shutdown_event = threading.Event()


def _signal_handler(signum, frame):
    print(f"\n\n  {YELLOW}[*] Shutdown signal received — stopping listeners…{RESET}")
    _shutdown_event.set()


def main():
    args = parse_args()
    apply_overrides(args)

    if args.report_only:
        print(f"\n  {CYAN}[*] Generating threat intelligence report from existing logs…{RESET}")
        report_path = generate_report()
        print(f"  {GREEN}[+] Report saved: {BOLD}{report_path}{RESET}\n")
        return

    print_startup_info()

    signal.signal(signal.SIGINT,  _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)

    listeners = start_all_listeners()
    print(f"  {GREEN}[+] All listeners running. Waiting for connections…{RESET}\n")

    try:
        while not _shutdown_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass

    for listener in listeners:
        listener.stop()
    simulator.stop()
    time.sleep(0.5)

    print(f"\n  {CYAN}[*] Generating threat intelligence report…{RESET}")
    report_path = generate_report()
    print(f"  {GREEN}[+] Threat Report: {BOLD}{report_path}{RESET}")
    print(f"\n  {YELLOW}Open the report in any browser to review attack metrics.{RESET}\n")


if __name__ == "__main__":
    main()
