# =============================================================================
#  ics_honeypot / shared / config.py
#  ---------------------------------------------------------------------------
#  Central configuration for the ICS Honeypot.
#  All ports, timeouts, file paths, and fake sensor value ranges live here
#  so that nothing is hardcoded scattered across the codebase.
#
#  To customise the honeypot (e.g. run on non-privileged ports during dev),
#  change the values in this single file — nothing else needs to be touched.
# =============================================================================

import os

# ---------------------------------------------------------------------------
# Network — Listener Ports
# ---------------------------------------------------------------------------
# Standard ICS protocol ports.  Ports < 1024 require root on Linux.
# During development you can substitute 5020 / 20001 / 1885 if running
# without sudo, and point your scanner at those ports instead.

MODBUS_PORT  = 502       # Modbus TCP  (IEC 61158)
DNP3_PORT    = 20000     # DNP3 over TCP  (IEEE 1815)
MQTT_PORT    = 1883      # MQTT broker  (ISO/IEC 20922)

# Maximum simultaneous clients per listener before new connections are queued
SOCKET_BACKLOG = 10

# How long (seconds) a client socket can be idle before we close it
SOCKET_TIMEOUT = 30

# How many bytes we read in one recv() call — large enough for any ICS frame
RECV_BUFFER = 4096

# ---------------------------------------------------------------------------
# Fake Sensor Readings — what the honeypot "reports" to scanners
# ---------------------------------------------------------------------------
# These values deliberately look like a real substation / industrial site.
# Realistic values increase the time an attacker spends probing, giving us
# more log data to analyse.

FAKE_VOLTAGE    = 2305   # 230.5 V  (stored as integer × 10, Modbus style)
FAKE_TEMP       = 352    # 35.2 °C
FAKE_HUMIDITY   = 653    # 65.3 %
FAKE_PRESSURE   = 10132  # 1013.2 hPa

# Modbus holding register map exposed to attackers
# register index → (description, fake value)
MODBUS_REGISTER_MAP = {
    0: ("voltage_high",   (FAKE_VOLTAGE  >> 8) & 0xFF),
    1: ("voltage_low",     FAKE_VOLTAGE        & 0xFF),
    2: ("temp_high",      (FAKE_TEMP     >> 8) & 0xFF),
    3: ("temp_low",        FAKE_TEMP           & 0xFF),
    4: ("humidity_high",  (FAKE_HUMIDITY >> 8) & 0xFF),
    5: ("humidity_low",    FAKE_HUMIDITY       & 0xFF),
    6: ("pressure_high",  (FAKE_PRESSURE >> 8) & 0xFF),
    7: ("pressure_low",    FAKE_PRESSURE       & 0xFF),
}

# Modbus device identity strings — returned if attacker sends a MEI request
MODBUS_VENDOR      = "Siemens AG"
MODBUS_PRODUCT     = "SIMATIC S7-1200"
MODBUS_VERSION     = "FW:V4.5"

# DNP3 device identity
DNP3_OUTSTATION_ADDR = 2     # address we pretend to be
DNP3_MASTER_ADDR     = 1     # address we expect the attacker to use

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

LOG_DIR      = os.path.join(os.path.dirname(__file__), "..", "..", "logs")
LOG_FILE     = os.path.join(LOG_DIR, "honeypot.log")       # human-readable
EVENT_FILE   = os.path.join(LOG_DIR, "events.jsonl")       # JSON lines — one event per line
REPORT_FILE  = os.path.join(LOG_DIR, "report.html")        # generated HTML report

# Rotate logs when they exceed this size (bytes).  10 MB default.
LOG_MAX_BYTES    = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 5

# ---------------------------------------------------------------------------
# Threat Intelligence — Known Scanner Fingerprints
# ---------------------------------------------------------------------------
# If an attacker's first Modbus request matches one of these byte patterns,
# we tag the session with the known tool name in the log.

KNOWN_SCANNERS = {
    bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A]):
        "Shodan / Censys default probe",
    bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0xFF, 0x03, 0x00, 0x00, 0x00, 0x7D]):
        "PLCScan",
    bytes([0x47, 0x45, 0x54, 0x20, 0x2F]):   # "GET /"
        "HTTP scanner on wrong port",
}
