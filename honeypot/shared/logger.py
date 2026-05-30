# =============================================================================
#  ics_honeypot / shared / logger.py
#  ---------------------------------------------------------------------------
#  Dual-output logging system for the ICS Honeypot.
#
#  Every attacker interaction is written to TWO destinations simultaneously:
#    1. honeypot.log  — human-readable, coloured console + rotating file
#    2. events.jsonl  — machine-parseable JSON Lines (one JSON object per line)
#
#  The JSON Lines format is intentional: it can be ingested directly into
#  Splunk, ELK, or any SIEM without any parsing pipeline changes.
#
#  Usage (from any listener module):
#      from honeypot.shared.logger import HoneypotLogger
#      log = HoneypotLogger("Modbus")
#      log.connection("192.168.1.50", 45231)
#      log.attack("192.168.1.50", 45231, "read_registers", raw_bytes, details)
# =============================================================================

import os
import json
import logging
import logging.handlers
import datetime
import threading

from honeypot.shared.config import (
    LOG_DIR, LOG_FILE, EVENT_FILE,
    LOG_MAX_BYTES, LOG_BACKUP_COUNT,
    KNOWN_SCANNERS
)

# ---------------------------------------------------------------------------
# ANSI colour codes — makes console output scannable at a glance
# ---------------------------------------------------------------------------
RESET   = "\033[0m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
BOLD    = "\033[1m"

# ---------------------------------------------------------------------------
# Module-level setup — runs once when the module is first imported
# ---------------------------------------------------------------------------

# Ensure the logs/ directory exists before any handler tries to open files
os.makedirs(LOG_DIR, exist_ok=True)

# Shared lock so concurrent listener threads don't interleave JSON writes
_json_lock = threading.Lock()


def _build_file_handler() -> logging.handlers.RotatingFileHandler:
    """
    Create a rotating file handler for honeypot.log.
    Rotates at LOG_MAX_BYTES, keeping LOG_BACKUP_COUNT backups.
    """
    handler = logging.handlers.RotatingFileHandler(
        LOG_FILE,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s  [%(levelname)-8s]  %(name)-10s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))
    return handler


def _build_console_handler() -> logging.StreamHandler:
    """
    Create a console handler that writes to stdout.
    No colour codes are added here; colouring is done in HoneypotLogger
    before the message reaches this handler.
    """
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s  %(message)s",
        datefmt="%H:%M:%S"
    ))
    return handler


# Root logger shared across all honeypot modules
_root = logging.getLogger("honeypot")
_root.setLevel(logging.DEBUG)
_root.addHandler(_build_file_handler())
_root.addHandler(_build_console_handler())


# =============================================================================
#  HoneypotLogger — per-protocol wrapper around the standard logger
# =============================================================================

class HoneypotLogger:
    """
    Structured logger for one ICS protocol listener (Modbus, DNP3, or MQTT).

    Each public method both:
      • emits a human-readable line via the standard logging framework, and
      • appends a JSON event to events.jsonl for SIEM ingestion.
    """

    def __init__(self, protocol: str):
        """
        Parameters
        ----------
        protocol : str
            Short protocol label used as a prefix in every log line.
            Recommended values: "Modbus", "DNP3", "MQTT".
        """
        self.protocol = protocol.upper()
        self._logger  = logging.getLogger(f"honeypot.{protocol.lower()}")

    # ------------------------------------------------------------------
    # Public logging methods
    # ------------------------------------------------------------------

    def connection(self, ip: str, port: int):
        """Log a new TCP connection from an attacker."""
        scanner = self._identify_scanner(None)   # no bytes yet at connect time
        msg = (
            f"{CYAN}{BOLD}[{self.protocol}]{RESET} "
            f"{GREEN}NEW CONNECTION{RESET}  "
            f"{ip}:{port}"
        )
        self._logger.info(msg)
        self._write_event("connection", ip, port, {
            "scanner_hint": scanner
        })

    def disconnection(self, ip: str, port: int):
        """Log a client disconnecting (graceful or reset)."""
        msg = (
            f"{CYAN}[{self.protocol}]{RESET} "
            f"DISCONNECT  {ip}:{port}"
        )
        self._logger.info(msg)
        self._write_event("disconnection", ip, port, {})

    def attack(
        self,
        ip:        str,
        port:      int,
        action:    str,
        raw_bytes: bytes,
        details:   dict
    ):
        """
        Log a decoded attacker request — the most important event type.

        Parameters
        ----------
        ip        : attacker IP address
        port      : attacker source port
        action    : human-readable description of what was attempted
                    e.g. "read_holding_registers", "write_coil", "dnp3_read_class0"
        raw_bytes : the exact bytes received (stored hex-encoded in JSON)
        details   : protocol-specific decoded fields as a dict
        """
        scanner = self._identify_scanner(raw_bytes)
        hex_str = raw_bytes.hex(" ").upper() if raw_bytes else ""

        # Colour-code by action severity
        colour = RED if "write" in action.lower() else YELLOW

        msg = (
            f"{CYAN}{BOLD}[{self.protocol}]{RESET} "
            f"{colour}PROBE{RESET}  "
            f"{ip}:{port}  "
            f"action={action}  "
            f"bytes=[{hex_str[:60]}{'…' if len(hex_str) > 60 else ''}]"
        )
        if scanner:
            msg += f"  {MAGENTA}scanner={scanner}{RESET}"

        self._logger.warning(msg)
        self._write_event("attack", ip, port, {
            "action":      action,
            "raw_hex":     raw_bytes.hex() if raw_bytes else "",
            "byte_length": len(raw_bytes) if raw_bytes else 0,
            "scanner":     scanner,
            **details
        })

    def response(self, ip: str, port: int, action: str, fake_data: dict):
        """Log the fake response we sent back to keep the attacker engaged."""
        msg = (
            f"{CYAN}[{self.protocol}]{RESET} "
            f"{GREEN}RESPONDED{RESET}  "
            f"{ip}:{port}  action={action}  data={fake_data}"
        )
        self._logger.info(msg)
        self._write_event("response", ip, port, {
            "action":    action,
            "fake_data": fake_data
        })

    def error(self, ip: str, port: int, message: str):
        """Log a parsing error or unexpected frame — useful for detecting fuzzing."""
        msg = (
            f"{CYAN}[{self.protocol}]{RESET} "
            f"{RED}ERROR{RESET}  "
            f"{ip}:{port}  {message}"
        )
        self._logger.error(msg)
        self._write_event("error", ip, port, {"message": message})

    def info(self, message: str):
        """Generic informational message (startup, shutdown, etc.)."""
        self._logger.info(f"{CYAN}[{self.protocol}]{RESET}  {message}")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _write_event(self, event_type: str, ip: str, port: int, extra: dict):
        """
        Append a single JSON object to events.jsonl.
        Thread-safe via module-level lock.
        """
        event = {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "protocol":  self.protocol,
            "event":     event_type,
            "src_ip":    ip,
            "src_port":  port,
            **extra
        }
        with _json_lock:
            with open(EVENT_FILE, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(event) + "\n")

    @staticmethod
    def _identify_scanner(raw_bytes: bytes | None) -> str:
        """
        Compare the first packet against known scanner fingerprints.
        Returns a descriptive string if matched, empty string otherwise.
        """
        if not raw_bytes:
            return ""
        for signature, name in KNOWN_SCANNERS.items():
            if raw_bytes.startswith(signature):
                return name
        return ""
