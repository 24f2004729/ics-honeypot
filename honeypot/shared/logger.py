# =============================================================================
#  ics_honeypot / shared / logger.py
#  ---------------------------------------------------------------------------
#  Dual-Output Structured Logging & SIEM Ingestion Engine
#  ---------------------------------------------------------------------------
#  Every attacker interaction is written to TWO destinations simultaneously:
#    1. honeypot.log  — human-readable, ANSI-coloured console + rotating file
#    2. events.jsonl  — machine-parseable JSON Lines with MITRE ATT&CK ICS tags
#
#  Also supports asynchronous Webhook notifications (Slack/Discord/SIEM)
#  for CRITICAL and HIGH severity events using pure Python stdlib.
# =============================================================================

import os
import json
import logging
import logging.handlers
import datetime
import threading
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

from honeypot.shared.config import (
    LOG_DIR, LOG_FILE, EVENT_FILE,
    LOG_MAX_BYTES, LOG_BACKUP_COUNT,
    KNOWN_SCANNERS, ALERT_WEBHOOK_URL
)
from honeypot.shared.mitre import classify_mitre_attack

# ANSI color codes
RESET   = "\033[0m"
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
MAGENTA = "\033[95m"
BOLD    = "\033[1m"

os.makedirs(LOG_DIR, exist_ok=True)
_json_lock = threading.Lock()


def _build_file_handler() -> logging.handlers.RotatingFileHandler:
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
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(
        fmt="%(asctime)s  %(message)s",
        datefmt="%H:%M:%S"
    ))
    return handler


_root = logging.getLogger("honeypot")
_root.setLevel(logging.DEBUG)
_root.addHandler(_build_file_handler())
_root.addHandler(_build_console_handler())


def _dispatch_webhook_async(event: Dict[str, Any]):
    """Send webhook alert asynchronously in a background thread without blocking."""
    if not ALERT_WEBHOOK_URL:
        return

    def _worker():
        try:
            payload = json.dumps({
                "content": (
                    f"🚨 **ICS Honeypot Alert** [{event.get('severity', 'ALERT')}]\n"
                    f"- **Protocol:** {event.get('protocol')}\n"
                    f"- **Attacker:** `{event.get('src_ip')}:{event.get('src_port')}`\n"
                    f"- **Action:** `{event.get('action')}`\n"
                    f"- **MITRE:** {event.get('mitre_id')} ({event.get('mitre_name')})\n"
                    f"- **Tactic:** {event.get('mitre_tactic')}"
                )
            }).encode("utf-8")
            req = urllib.request.Request(
                ALERT_WEBHOOK_URL,
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "ICSHoneypot/2.0"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                pass
        except Exception:
            pass

    threading.Thread(target=_worker, daemon=True).start()


class HoneypotLogger:
    """
    Structured logger for ICS protocol listeners with MITRE ATT&CK integration.
    """

    def __init__(self, protocol: str):
        self.protocol = protocol.upper()
        self._logger  = logging.getLogger(f"honeypot.{protocol.lower()}")

    def connection(self, ip: str, port: int):
        """Log a new TCP connection from an attacker."""
        msg = f"{CYAN}{BOLD}[{self.protocol}]{RESET} {GREEN}NEW CONNECTION{RESET}  {ip}:{port}"
        self._logger.info(msg)
        self._write_event("connection", ip, port, {})

    def disconnection(self, ip: str, port: int):
        """Log client disconnect."""
        msg = f"{CYAN}[{self.protocol}]{RESET} DISCONNECT  {ip}:{port}"
        self._logger.info(msg)
        self._write_event("disconnection", ip, port, {})

    def attack(
        self,
        ip: str,
        port: int,
        action: str,
        raw_bytes: bytes,
        details: Optional[Dict[str, Any]] = None
    ):
        """
        Log a decoded attack request with MITRE ATT&CK taxonomy classification.
        """
        details = details or {}
        scanner = self._identify_scanner(raw_bytes)
        hex_str = raw_bytes.hex(" ").upper() if raw_bytes else ""

        # Map to MITRE ATT&CK for ICS
        mitre_info = classify_mitre_attack(action, details)

        severity = details.get("severity")
        if not severity:
            action_up = action.upper()
            if "CRITICAL" in action_up or "OPERATE" in action_up or "WRITE_MULTIPLE" in action_up:
                severity = "CRITICAL"
            elif "WRITE" in action_up or details.get("password"):
                severity = "HIGH"
            else:
                severity = "MEDIUM"

        colour = RED if severity in ("CRITICAL", "HIGH") else YELLOW

        msg = (
            f"{CYAN}{BOLD}[{self.protocol}]{RESET} "
            f"{colour}PROBE [{severity}]{RESET}  "
            f"{ip}:{port}  "
            f"action={action}  "
            f"MITRE={mitre_info['mitre_id']} ({mitre_info['mitre_name']})  "
            f"bytes=[{hex_str[:50]}{'…' if len(hex_str) > 50 else ''}]"
        )
        if scanner:
            msg += f"  {MAGENTA}scanner={scanner}{RESET}"

        self._logger.warning(msg)

        event_data = {
            "action": action,
            "raw_hex": raw_bytes.hex() if raw_bytes else "",
            "byte_length": len(raw_bytes) if raw_bytes else 0,
            "scanner": scanner,
            "severity": severity,
            **mitre_info,
            **details
        }
        self._write_event("attack", ip, port, event_data)

        if severity in ("CRITICAL", "HIGH"):
            _dispatch_webhook_async({
                "protocol": self.protocol,
                "src_ip": ip,
                "src_port": port,
                "severity": severity,
                "action": action,
                **mitre_info
            })

    def response(self, ip: str, port: int, action: str, fake_data: Dict[str, Any]):
        """Log honeypot decoy response."""
        msg = f"{CYAN}[{self.protocol}]{RESET} {GREEN}RESPONDED{RESET}  {ip}:{port}  action={action}  data={fake_data}"
        self._logger.info(msg)
        self._write_event("response", ip, port, {
            "action": action,
            "fake_data": fake_data
        })

    def error(self, ip: str, port: int, message: str):
        """Log parsing error or malformed frame."""
        msg = f"{CYAN}[{self.protocol}]{RESET} {RED}ERROR{RESET}  {ip}:{port}  {message}"
        self._logger.error(msg)
        self._write_event("error", ip, port, {"message": message})

    def info(self, message: str):
        """Informational message."""
        self._logger.info(f"{CYAN}[{self.protocol}]{RESET}  {message}")

    def _write_event(self, event_type: str, ip: str, port: int, extra: Dict[str, Any]):
        event = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
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
    def _identify_scanner(raw_bytes: Optional[bytes]) -> str:
        if not raw_bytes:
            return ""
        for signature, name in KNOWN_SCANNERS.items():
            if raw_bytes.startswith(signature):
                return name
        return ""
