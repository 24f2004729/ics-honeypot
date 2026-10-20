# =============================================================================
#  ics_honeypot / shared / config.py
#  ---------------------------------------------------------------------------
#  Central configuration for the ICS Honeypot.
#  All network settings, device profiles, rate limits, and thresholds live here.
#  Supports environment variable overrides for containerized & CI workflows.
# =============================================================================

import os
from typing import Dict, Any

# ---------------------------------------------------------------------------
# Network & Listener Ports (Configurable via Environment Variables)
# ---------------------------------------------------------------------------
MODBUS_PORT = int(os.getenv("MODBUS_PORT", "502"))        # Modbus TCP (IEC 61158)
DNP3_PORT   = int(os.getenv("DNP3_PORT", "20000"))        # DNP3 over TCP (IEEE 1815)
MQTT_PORT   = int(os.getenv("MQTT_PORT", "1883"))         # MQTT broker (ISO/IEC 20922)

# ---------------------------------------------------------------------------
# Socket & Connection Safeguards (Anti-DoS / Resource Management)
# ---------------------------------------------------------------------------
SOCKET_BACKLOG         = int(os.getenv("SOCKET_BACKLOG", "20"))
SOCKET_TIMEOUT         = int(os.getenv("SOCKET_TIMEOUT", "30"))
RECV_BUFFER            = 4096
MAX_BUFFER_SIZE        = 65536    # 64 KB limit per connection to avoid memory exhaustion
MAX_ACTIVE_CONNECTIONS = int(os.getenv("MAX_ACTIVE_CONNECTIONS", "100"))
MAX_CONNS_PER_IP       = int(os.getenv("MAX_CONNS_PER_IP", "10"))

# ---------------------------------------------------------------------------
# Device Profiles (Realistic ICS Device Identities)
# ---------------------------------------------------------------------------
PROFILES = {
    "moxa": {
        "vendor": "Moxa Inc.",
        "product": "NPort 5150A Serial Device Server",
        "version": "FW:V1.5 Build 19041617"
    },
    "schneider": {
        "vendor": "Schneider Electric",
        "product": "Modicon M340 PLC BMXP342020",
        "version": "V03.20"
    },
    "siemens": {
        "vendor": "Siemens AG",
        "product": "SIMATIC S7-1200 CPU 1214C",
        "version": "FW:V4.5"
    }
}

ACTIVE_PROFILE_NAME = os.getenv("DEVICE_PROFILE", "moxa").lower()
CURRENT_PROFILE = PROFILES.get(ACTIVE_PROFILE_NAME, PROFILES["moxa"])

MODBUS_VENDOR  = CURRENT_PROFILE["vendor"]
MODBUS_PRODUCT = CURRENT_PROFILE["product"]
MODBUS_VERSION = CURRENT_PROFILE["version"]

# DNP3 Device Identity
DNP3_OUTSTATION_ADDR = int(os.getenv("DNP3_OUTSTATION_ADDR", "2"))   # Address we pretend to be
DNP3_MASTER_ADDR     = int(os.getenv("DNP3_MASTER_ADDR", "1"))       # Expected master address

# ---------------------------------------------------------------------------
# Static Baseline Sensor Fallbacks (Used if dynamic simulator is bypassed)
# ---------------------------------------------------------------------------
FAKE_VOLTAGE  = 2305   # 230.5 V
FAKE_TEMP     = 352    # 35.2 °C
FAKE_HUMIDITY = 653    # 65.3 %
FAKE_PRESSURE = 10132  # 1013.2 hPa

# ---------------------------------------------------------------------------
# Logging & Threat Intelligence
# ---------------------------------------------------------------------------
LOG_DIR     = os.getenv("LOG_DIR", os.path.join(os.path.dirname(__file__), "..", "..", "logs"))
LOG_FILE    = os.path.join(LOG_DIR, "honeypot.log")
EVENT_FILE  = os.path.join(LOG_DIR, "events.jsonl")
REPORT_FILE = os.path.join(LOG_DIR, "report.html")

LOG_MAX_BYTES    = 10 * 1024 * 1024  # 10 MB
LOG_BACKUP_COUNT = 5

# Optional SIEM / Alerting Webhook (Discord, Slack, or generic HTTP POST)
ALERT_WEBHOOK_URL = os.getenv("ALERT_WEBHOOK_URL", "")

# ---------------------------------------------------------------------------
# Threat Intelligence — Known Scanner Fingerprints
# ---------------------------------------------------------------------------
KNOWN_SCANNERS: Dict[bytes, str] = {
    bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A]):
        "Shodan / Censys default probe",
    bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0xFF, 0x03, 0x00, 0x00, 0x00, 0x7D]):
        "PLCScan default probe",
    bytes([0x47, 0x45, 0x54, 0x20, 0x2F]):
        "HTTP scanner on wrong port",
    bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x2B, 0x0E, 0x01, 0x00]):
        "Nmap modbus-discover.nse MEI probe",
}
